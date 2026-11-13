//! The weekly digest: one Teams card per route with everything that did not
//! deserve an immediate alert.
//!
//! Sections: medium/low/unknown vulnerabilities opened since the last digest,
//! minor/patch releases by release-notes class, active oaths (flagging those
//! carried to a new version), and declared components with their age.
//!
//! kv keys: `digest_last` (local date of the last digest) and
//! `digest_release_id` (highest release id covered).

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use chrono_tz::Tz;
use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgPool};

use super::teams::{
    clip, message, package_name, severity_name, text_block, title_block, MAX_CARD_BYTES, MAX_ROWS,
};
use super::{covers, outbox, realm_has_route};
use crate::config::{HeimdallConfig, TeamsRoute};
use crate::model::Severity;
use crate::version::is_prerelease;

/// Fix lines quoted per bug-fix release.
const FIX_LINES: usize = 3;

/// One line of a digest section, with the realm it belongs to (None: every
/// realm, such as a release or an all-realms oath).
struct Row {
    realm: Option<String>,
    text: String,
}

struct Section {
    title: &'static str,
    rows: Vec<Row>,
}

/// Queue the digest when `now`, in the digest timezone, is in the configured
/// weekday and hour and no digest went out that local day. Returns whether
/// it queued. Vulnerabilities it lists are marked notified in the same
/// transaction.
pub async fn maybe_send(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    now: DateTime<Utc>,
) -> anyhow::Result<bool> {
    let d = &cfg.digest;
    let local = now.with_timezone(&d.timezone);
    if local.weekday() != d.weekday || local.hour() != d.hour || cfg.teams.is_empty() {
        return Ok(false);
    }
    let today = local.date_naive().to_string();

    let mut tx = pool.begin().await?;
    // Two schedulers in the same hour: the second waits and sees digest_last.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('digest'))")
        .execute(&mut *tx)
        .await?;
    if kv_get(&mut tx, "digest_last").await?.as_deref() == Some(today.as_str()) {
        return Ok(false);
    }
    let last_release: Option<i64> = kv_get(&mut tx, "digest_release_id")
        .await?
        .and_then(|s| s.parse().ok());

    let (listed, vulns) = vulnerabilities(&mut tx).await?;
    // A vuln of a realm no route covers stays pending for a later digest.
    let vuln_ids: Vec<i64> = listed
        .into_iter()
        .filter(|(_, realm)| realm_has_route(cfg, realm))
        .map(|(id, _)| id)
        .collect();
    let mut sections = vec![vulns];
    sections.extend(releases(&mut tx, last_release, now - Duration::days(7)).await?);
    sections.push(oaths(&mut tx, d.timezone).await?);
    sections.push(declared(&mut tx, d.timezone).await?);

    for route in &cfg.teams {
        let card = card_for(route, &today, &sections);
        outbox::push(&mut tx, &format!("digest|{today}"), &card, &route.name).await?;
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

/// The route's card: rows of the realms it covers, each section capped.
/// Rows are cut further if the card is still too big for Teams.
fn card_for(route: &TeamsRoute, today: &str, sections: &[Section]) -> Value {
    let mut card = Value::Null;
    for cap in [MAX_ROWS, 10, 5] {
        let mut body = vec![title_block(
            &format!("Heimdall weekly digest {today}"),
            Severity::Unknown,
        )];
        for s in sections {
            let rows: Vec<&str> = s
                .rows
                .iter()
                .filter(|r| r.realm.as_deref().is_none_or(|realm| covers(route, realm)))
                .map(|r| r.text.as_str())
                .collect();
            if rows.is_empty() {
                continue;
            }
            body.push(serde_json::json!({"type": "TextBlock", "text": s.title,
                                          "weight": "Bolder", "wrap": true, "spacing": "Medium"}));
            let mut lines: Vec<String> = rows.iter().take(cap).map(|r| format!("- {r}")).collect();
            if rows.len() > cap {
                lines.push(format!("- and {} more", rows.len() - cap));
            }
            body.push(text_block(&lines.join("\n"), false));
        }
        if body.len() == 1 {
            body.push(text_block("Nothing to report this week.", true));
        }
        card = message(body, Vec::new());
        if card.to_string().len() <= MAX_CARD_BYTES {
            break;
        }
    }
    card
}

#[derive(FromRow)]
struct VulnRow {
    id: i64,
    realm: String,
    service: Option<String>,
    ref_id: Option<String>,
    severity: Severity,
    purl: Option<String>,
}

/// Open medium/low/unknown Vuln findings no digest has listed yet, and their
/// (id, realm) (to mark notified).
async fn vulnerabilities(tx: &mut PgConnection) -> anyhow::Result<(Vec<(i64, String)>, Section)> {
    let rows: Vec<VulnRow> = sqlx::query_as(
        "SELECT f.id, f.realm, s.name AS service, f.ref_id, f.severity, f.details->>'purl' AS purl \
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
        .map(|r| Row {
            text: format!(
                "{} ({}): {}/{} {}",
                r.ref_id.unwrap_or_default(),
                severity_name(r.severity),
                r.realm,
                r.service.unwrap_or_default(),
                r.purl.unwrap_or_default()
            ),
            realm: Some(r.realm),
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
        let name = match &r.notes_url {
            Some(url) => format!("[{} {}]({url})", r.target, r.version),
            None => format!("{} {}", r.target, r.version),
        };
        let row = |text: String| Row { realm: None, text };
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
            text,
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
            text: format!(
                "{service}: {} {version}, declared since {} ({realm})",
                package_name(&purl),
                since.with_timezone(&tz).date_naive()
            ),
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
