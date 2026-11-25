//! The weekly digest: one Teams card per route with everything that did not
//! deserve an immediate alert.
//!
//! Sections: medium/low/unknown vulnerabilities opened since the last digest
//! (with their fix, when one existed from the start),
//! minor/patch releases by release-notes class, active oaths (flagging those
//! carried to a new version), and declared components with their age.
//!
//! kv keys: `digest_last` (local date of the last digest) and
//! `digest_release_id` (highest release id covered).

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveTime, TimeZone, Utc, Weekday};
use chrono_tz::Tz;
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgPool};

use super::alert::{self, clip, package_name, severity_name, Alert, Line, Link};
use super::store::Channels;
use super::{channels, outbox, warn_once, FIX_ALERTS_AT_ONCE};
use crate::config::{ChannelConfig, HeimdallConfig};
use crate::model::Severity;
use crate::version::is_prerelease;

/// Fix lines quoted per bug-fix release.
const FIX_LINES: usize = 3;

/// One line of a digest section, with the realm it belongs to (None: every
/// realm, such as a release or an all-realms oath).
struct Row {
    realm: Option<String>,
    line: Line,
}

struct Section {
    title: &'static str,
    rows: Vec<Row>,
}

/// The most recent digest slot at or before `now`: its local date and its
/// instant. A local time that does not exist (DST spring-forward gap) moves to
/// the next valid local time; an ambiguous one (fall-back) takes the first.
fn latest_slot(
    now: DateTime<Utc>,
    weekday: Weekday,
    hour: u32,
    tz: Tz,
) -> Option<(NaiveDate, DateTime<Utc>)> {
    let local_date = now.with_timezone(&tz).date_naive();
    let back =
        (7 + local_date.weekday().num_days_from_monday() - weekday.num_days_from_monday()) % 7;
    let mut date = local_date - Duration::days(i64::from(back));
    for _ in 0..2 {
        let mut t = date.and_time(NaiveTime::from_hms_opt(hour, 0, 0)?);
        // Walk out of a gap (at most a few hours wide).
        for _ in 0..(6 * 60) {
            if let Some(at) = tz.from_local_datetime(&t).earliest() {
                let at = at.with_timezone(&Utc);
                if at <= now {
                    return Some((date, at));
                }
                break;
            }
            t += Duration::minutes(1);
        }
        date -= Duration::days(7);
    }
    None
}

/// Queue the digest when `now` is past the latest weekly slot (configured
/// weekday and hour in the digest timezone) and no digest went out for that
/// slot, so a pod that was down during the slot catches up. Returns whether
/// it queued. Vulnerabilities it lists are marked notified in the same
/// transaction.
pub async fn maybe_send(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    chans: &Channels,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    let d = &cfg.digest;
    // Paging channels (PagerDuty, Alertmanager) skip the digest by default.
    let chans: Vec<ChannelConfig> = chans
        .list
        .iter()
        .filter(|c| c.wants_digest())
        .cloned()
        .collect();
    if chans.is_empty() {
        return Ok(false);
    }
    let Some((slot_date, _)) = latest_slot(now, d.weekday, d.hour, d.timezone) else {
        return Ok(false);
    };
    let today = slot_date.to_string();

    let mut tx = pool.begin().await?;
    // Two schedulers in the same hour: the second waits and sees digest_last.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('digest'))")
        .execute(&mut *tx)
        .await?;
    // ISO dates compare as strings; a stored date at or after the slot's
    // means this slot (or a later one) was already sent.
    if kv_get(&mut tx, "digest_last")
        .await?
        .is_some_and(|last| last >= today)
    {
        return Ok(false);
    }
    let last_release: Option<i64> = kv_get(&mut tx, "digest_release_id")
        .await?
        .and_then(|s| s.parse().ok());

    let (mut listed, vulns) = vulnerabilities(&mut tx).await?;
    listed.extend(quiet_fixes(&mut tx).await?);
    // A vuln of a realm no digest channel covers stays pending for a later
    // digest.
    let vuln_ids: Vec<i64> = listed
        .into_iter()
        .filter(|(_, realm)| digest_covers(&chans, realm))
        .map(|(id, _)| id)
        .collect();
    let mut sections = vec![vulns];
    sections.extend(releases(&mut tx, last_release, now - Duration::days(7)).await?);
    sections.push(oaths(&mut tx, d.timezone).await?);
    sections.push(declared(&mut tx, d.timezone).await?);

    for ch in &chans {
        let payload = channels::render(ch, &alert_for(ch, &today, &sections));
        outbox::push(&mut tx, &format!("digest|{today}"), &payload, ch).await?;
    }
    sqlx::query("UPDATE findings SET notified_at = now() WHERE id = ANY($1)")
        .bind(&vuln_ids)
        .execute(&mut *tx)
        .await?;
    let max_release: Option<i64> = sqlx::query_scalar("SELECT max(id) FROM releases")
        .fetch_one(&mut *tx)
        .await?;
    kv_set(&mut tx, "digest_last", &today).await?;
    // No release stored yet: leave the watermark unset, or the next digest
    // would take every release ever stored as new.
    if let Some(max) = max_release {
        let covered = max.max(last_release.unwrap_or(0));
        kv_set(&mut tx, "digest_release_id", &covered.to_string()).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Does a digest channel cover this realm? Warns once per realm when none does.
fn digest_covers(chans: &[ChannelConfig], realm: &str) -> bool {
    let covered = chans.iter().any(|c| c.covers(realm));
    if !covered {
        warn_once(
            &format!("digest-realm|{realm}"),
            &format!("no digest channel covers realm {realm}; its digest findings stay pending"),
        );
    }
    covered
}

/// The channel's digest: only rows of the realms it covers (rows of no
/// realm go to every channel). Each formatter caps the sections.
fn alert_for(ch: &ChannelConfig, today: &str, sections: &[Section]) -> Alert {
    let sections = sections
        .iter()
        .map(|s| alert::Section {
            title: s.title.to_string(),
            lines: s
                .rows
                .iter()
                .filter(|r| r.realm.as_deref().is_none_or(|realm| ch.covers(realm)))
                .map(|r| r.line.clone())
                .collect(),
        })
        .collect();
    Alert::digest(today, sections)
}

#[derive(FromRow)]
struct VulnRow {
    id: i64,
    realm: String,
    service: Option<String>,
    ref_id: Option<String>,
    severity: Severity,
    purl: Option<String>,
    /// The suggested fixed version, if any.
    fix: Option<String>,
}

/// Open medium/low/unknown Vuln findings no digest has listed yet, and their
/// (id, realm) (to mark notified).
async fn vulnerabilities(tx: &mut PgConnection) -> anyhow::Result<(Vec<(i64, String)>, Section)> {
    let rows: Vec<VulnRow> = sqlx::query_as(
        "SELECT f.id, f.realm, s.name AS service, f.ref_id, f.severity, \
                f.details->>'purl' AS purl, f.details->'advice'->>'suggest' AS fix \
         FROM findings f LEFT JOIN services s ON s.id = f.service_id \
         WHERE f.kind = 'vuln' AND f.status = 'open' AND f.notified_at IS NULL \
           AND f.severity IN ('medium', 'low', 'unknown') \
         ORDER BY f.ref_id, f.realm, s.name \
         FOR UPDATE OF f",
    )
    .fetch_all(&mut *tx)
    .await?;
    let ids = rows.iter().map(|r| (r.id, r.realm.clone())).collect();
    let rows = rows
        .into_iter()
        .map(|r| {
            let fix = r.fix.map(|f| format!(" (fix: {f})")).unwrap_or_default();
            Row {
                line: Line::plain(format!(
                    "{} ({}): {}/{} {}{fix}",
                    r.ref_id.unwrap_or_default(),
                    severity_name(r.severity),
                    r.realm,
                    r.service.unwrap_or_default(),
                    r.purl.unwrap_or_default()
                )),
                realm: Some(r.realm),
            }
        })
        .collect();
    Ok((
        ids,
        Section {
            title: "Medium and low vulnerabilities",
            rows,
        },
    ))
}

/// Pending FixAvailable findings that did not deserve an immediate alert
/// (see `FIX_ALERTS_AT_ONCE`), as (id, realm), to mark notified with the
/// digest. Their Vuln's row already shows the fix.
async fn quiet_fixes(tx: &mut PgConnection) -> anyhow::Result<Vec<(i64, String)>> {
    let sql = format!(
        "SELECT f.id, f.realm FROM findings f \
         WHERE f.kind = 'fixavailable' AND f.status = 'open' AND f.notified_at IS NULL \
           AND NOT {FIX_ALERTS_AT_ONCE} \
         ORDER BY f.id \
         FOR UPDATE OF f"
    );
    Ok(sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *tx)
        .await?)
}

#[derive(FromRow)]
struct ReleaseRow {
    target: String,
    version: String,
    notes_url: Option<String>,
    notes_class: Option<String>,
    excerpt: Option<Value>,
}

/// Minor/patch releases stored since the last digest (id above the
/// watermark, however old their publish date), in four sections by notes
/// class. Releases whose notes mention a CVE affecting us already alerted and
/// are left out. The first digest has no watermark: it takes releases
/// published since `first_since` (or undated), so a first sight's history
/// does not flood it.
async fn releases(
    tx: &mut PgConnection,
    after_id: Option<i64>,
    first_since: DateTime<Utc>,
) -> anyhow::Result<Vec<Section>> {
    let rows: Vec<ReleaseRow> = sqlx::query_as(
        "SELECT target, version, notes_url, notes_class, excerpt FROM releases \
         WHERE NOT is_major AND notes_class IS DISTINCT FROM 'cve_affecting' \
           AND CASE WHEN $1::bigint IS NULL \
                    THEN published_at IS NULL OR published_at >= $2 \
                    ELSE id > $1 END \
         ORDER BY target, id",
    )
    .bind(after_id)
    .bind(first_since)
    .fetch_all(&mut *tx)
    .await?;
    let mut security = Vec::new();
    let mut bugfix = Vec::new();
    let mut other = Vec::new();
    let mut no_notes = Vec::new();
    for r in rows.into_iter().filter(|r| !is_prerelease(&r.version)) {
        // The release name links to its notes (a link Heimdall makes); the
        // rest of the row is upstream text, rendered plain.
        let name = format!("{} {}", r.target, r.version);
        let (link, name) = match &r.notes_url {
            Some(url) => (
                Some(Link {
                    title: name,
                    url: url.clone(),
                }),
                String::new(),
            ),
            None => (None, name),
        };
        let row = |text: String| Row {
            realm: None,
            line: Line {
                link: link.clone(),
                text,
            },
        };
        match r.notes_class.as_deref() {
            Some("security") => security.push(row(name)),
            Some("bugfix") => {
                let fixes: Vec<String> = r
                    .excerpt
                    .as_ref()
                    .and_then(|e| e["fix"].as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .take(FIX_LINES)
                            .map(clip)
                            .collect()
                    })
                    .unwrap_or_default();
                if fixes.is_empty() {
                    bugfix.push(row(name));
                } else {
                    bugfix.push(row(format!("{name}: {}", fixes.join("; "))));
                }
            }
            Some("plain") => other.push(row(name)),
            Some("gave_up") => no_notes.push(row(format!("{name} (notes could not be fetched)"))),
            Some(_) => no_notes.push(row(name)),
            // Not looked at yet (the notes run comes later): say so.
            None => no_notes.push(row(format!("{name} (not checked yet)"))),
        }
    }
    Ok(vec![
        Section {
            title: "Security releases",
            rows: security,
        },
        Section {
            title: "Bug fixes",
            rows: bugfix,
        },
        Section {
            title: "Other releases",
            rows: other,
        },
        Section {
            title: "No release notes found",
            rows: no_notes,
        },
    ])
}

#[derive(FromRow)]
struct OathRow {
    advisory_id: String,
    name_key: String,
    service_name: String,
    realm: Option<String>,
    kind: String,
    reason: String,
    version_at_creation: String,
    expires_at: Option<DateTime<Utc>>,
    review_at: Option<DateTime<Utc>>,
}

/// Active oaths with their expiry or review date, flagging the ones carried
/// to a version other than the one they were sworn on.
async fn oaths(tx: &mut PgConnection, tz: Tz) -> anyhow::Result<Section> {
    let list: Vec<OathRow> = sqlx::query_as(
        "SELECT advisory_id, name_key, service_name, realm, kind, reason, version_at_creation, \
                expires_at, review_at \
         FROM oaths WHERE status = 'active' ORDER BY advisory_id, service_name, id",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut rows = Vec::new();
    for o in list {
        let when = match (o.expires_at, o.review_at) {
            (Some(t), _) => format!("expires {}", t.with_timezone(&tz).date_naive()),
            (None, Some(t)) => format!("review {}", t.with_timezone(&tz).date_naive()),
            (None, None) => "no date".to_string(),
        };
        let mut text = format!(
            "{} on {} ({}), {}: {} {when}, \"{}\"",
            o.advisory_id,
            o.service_name,
            o.realm.as_deref().unwrap_or("all realms"),
            package_name(&o.name_key),
            o.kind,
            clip(&o.reason)
        );
        let versions = current_versions(tx, &o).await?;
        let sworn = o.version_at_creation.trim_start_matches('v');
        if let Some(v) = versions.iter().find(|v| v.trim_start_matches('v') != sworn) {
            text.push_str(&format!(" · carried to new version {v}"));
        }
        rows.push(Row {
            realm: o.realm,
            line: Line::plain(text),
        });
    }
    Ok(Section {
        title: "Active oaths",
        rows,
    })
}

/// Versions of the oath's component its service runs now (directly or in an
/// image), in the oath's realm or any realm for an all-realms oath.
async fn current_versions(tx: &mut PgConnection, o: &OathRow) -> anyhow::Result<Vec<String>> {
    let versions = sqlx::query_scalar(
        "SELECT c.version FROM services s \
         JOIN service_components sc ON sc.service_id = s.id \
         JOIN components c ON c.id = sc.component_id \
         WHERE s.name = $1 AND ($2::text IS NULL OR s.realm = $2) AND c.name_key = $3 \
           AND sc.source IN ('git', 'cluster', 'declared') \
         UNION \
         SELECT c.version FROM services s \
         JOIN service_components sc ON sc.service_id = s.id \
         JOIN image_components ic ON ic.digest = sc.via_image_digest \
         JOIN components c ON c.id = ic.component_id \
         WHERE s.name = $1 AND ($2::text IS NULL OR s.realm = $2) AND c.name_key = $3 \
           AND sc.source IN ('git', 'cluster', 'declared') \
         ORDER BY 1",
    )
    .bind(&o.service_name)
    .bind(&o.realm)
    .bind(&o.name_key)
    .fetch_all(&mut *tx)
    .await?;
    Ok(versions)
}

/// Declared components, "declared since {date}", so stale versions show.
async fn declared(tx: &mut PgConnection, tz: Tz) -> anyhow::Result<Section> {
    let list: Vec<(String, String, String, String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT s.realm, s.name, c.purl, c.version, sc.declared_since \
         FROM service_components sc \
         JOIN services s ON s.id = sc.service_id \
         JOIN components c ON c.id = sc.component_id \
         WHERE sc.source = 'declared' \
         ORDER BY s.realm, s.name, c.purl",
    )
    .fetch_all(&mut *tx)
    .await?;
    let rows = list
        .into_iter()
        .map(|(realm, service, purl, version, since)| Row {
            line: Line::plain(format!(
                "{service}: {} {version}, declared since {} ({realm})",
                package_name(&purl),
                since.with_timezone(&tz).date_naive()
            )),
            realm: Some(realm),
        })
        .collect();
    Ok(Section {
        title: "Declared components",
        rows,
    })
}

async fn kv_get(tx: &mut PgConnection, key: &str) -> anyhow::Result<Option<String>> {
    let v = sqlx::query_scalar("SELECT value FROM kv WHERE key = $1")
        .bind(key)
        .fetch_optional(&mut *tx)
        .await?;
    Ok(v)
}

async fn kv_set(tx: &mut PgConnection, key: &str, value: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO kv (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(key)
    .bind(value)
    .execute(&mut *tx)
    .await?;
    Ok(())
}
