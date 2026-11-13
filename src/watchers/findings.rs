//! MajorRelease and Eol findings: opening, re-opening and resolving them.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Duration, Utc};
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};

use super::endoflife::Cycle;
use super::plan::purl_version;
use super::{Planned, Running, WatchKind};
use crate::config::HeimdallConfig;
use crate::matcher::key;
use crate::model::{FindingKind, Severity};
use crate::version::{compare, is_major, is_prerelease, major_line, parse_tag};

/// End of support this close (or already past) opens an Eol finding.
const EOL_WINDOW_DAYS: i64 = 60;

/// Open and resolve MajorRelease and Eol findings in one transaction, holding
/// every realm's matcher lock so no matcher run interleaves.
pub(super) async fn update_findings(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    planned: &[Planned],
    running: &[Running],
    cycles: &HashMap<String, Vec<Cycle>>,
    now: DateTime<Utc>,
) -> anyhow::Result<(Vec<i64>, usize)> {
    let mut tx = pool.begin().await?;
    // Sorted, so two watcher runs take the locks in the same order.
    let mut realms: Vec<&String> = cfg.realms.iter().collect();
    realms.sort();
    realms.dedup();
    for realm in realms {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('matcher:' || $1))")
            .bind(realm)
            .execute(&mut *tx)
            .await?;
    }

    let mut opened = Vec::new();
    for p in planned.iter().filter(|p| p.track_releases) {
        opened.extend(open_majors(&mut tx, p, now).await?);
    }
    let mut resolved = resolve_majors(&mut tx, planned, now).await?;
    let (eol_opened, eol_resolved) =
        eol_findings(&mut tx, cfg, planned, running, cycles, now).await?;
    opened.extend(eol_opened);
    resolved += eol_resolved;
    tx.commit().await?;
    Ok((opened, resolved))
}

/// A MajorRelease finding for each major line, newer than what we run, that
/// has no finding yet. The finding names the line's lowest stored release.
async fn open_majors(
    tx: &mut PgConnection,
    p: &Planned,
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<i64>> {
    let t = &p.target;
    let (Some(current), Some(realm)) = (&t.current, &p.realm) else {
        return Ok(Vec::new());
    };
    let versions: Vec<String> =
        sqlx::query_scalar("SELECT version FROM releases WHERE target = $1")
            .bind(&t.name)
            .fetch_all(&mut *tx)
            .await?;
    // Lines already alerted (a finding of any status) or passed over.
    let mut done: HashSet<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT details->>'line' FROM findings WHERE kind = 'majorrelease' AND details->>'target' = $1",
    )
    .bind(&t.name)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .flatten()
    .collect();
    let done_key = format!("majorlines_done|{}", t.name);
    let passed_over: Option<String> = sqlx::query_scalar("SELECT value FROM kv WHERE key = $1")
        .bind(&done_key)
        .fetch_optional(&mut *tx)
        .await?;
    if let Some(json) = passed_over {
        done.extend(serde_json::from_str::<Vec<String>>(&json).unwrap_or_default());
    }
    let current_suffix = parse_tag(current).map(|c| c.suffix);

    // line -> lowest version in it
    let mut lines: BTreeMap<String, String> = BTreeMap::new();
    for v in versions {
        let comparable = if t.kind == WatchKind::Oci {
            parse_tag(&v).map(|tag| tag.suffix) == current_suffix
        } else {
            !is_prerelease(&v)
        };
        if !comparable || !is_major(current, &v, t.major_component) {
            continue;
        }
        let line = major_line(&v, t.major_component);
        if done.contains(&line) {
            continue;
        }
        match lines.get(&line) {
            Some(lowest) if compare(t.kind.ecosystem(), &v, lowest) != Some(Ordering::Less) => {}
            _ => {
                lines.insert(line, v);
            }
        }
    }

    // Only the highest new line alerts (first sight of 16 -> 17, 18 says
    // "18 is out", once); the lower ones are marked done so they never do.
    let mut highest: Option<(String, String)> = None;
    for (line, version) in &lines {
        let higher = highest.as_ref().is_none_or(|(_, h)| {
            compare(t.kind.ecosystem(), version, h) == Some(Ordering::Greater)
        });
        if higher {
            highest = Some((line.clone(), version.clone()));
        }
    }
    if !lines.is_empty() {
        done.extend(lines.keys().cloned());
        let mut all: Vec<&String> = done.iter().collect();
        all.sort();
        sqlx::query(
            "INSERT INTO kv (key, value) VALUES ($1, $2) \
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&done_key)
        .bind(serde_json::to_string(&all)?)
        .execute(&mut *tx)
        .await?;
    }

    let mut opened = Vec::new();
    if let Some((line, version)) = highest {
        let details = json!({
            "target": t.name,
            "watcher": t.kind.label(),
            "version": version,
            "line": line,
            "current": current,
            "name_key": t.name_key,
            "repo": t.repo,
        });
        let k = key(FindingKind::MajorRelease, &[&t.name, &version]);
        opened.extend(
            open_finding(
                tx,
                &k,
                FindingKind::MajorRelease,
                realm,
                &version,
                Severity::High,
                &details,
                now,
            )
            .await?,
        );
    }
    Ok(opened)
}

/// Resolve open MajorRelease findings whose target we no longer run, or now
/// run at (or past) the finding's major.
async fn resolve_majors(
    tx: &mut PgConnection,
    planned: &[Planned],
    now: DateTime<Utc>,
) -> anyhow::Result<usize> {
    let open: Vec<(i64, Value)> = sqlx::query_as(
        "SELECT id, details FROM findings WHERE kind = 'majorrelease' AND status = 'open'",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut resolved = 0;
    for (id, d) in open {
        let (target, version) = (
            d["target"].as_str().unwrap_or(""),
            d["version"].as_str().unwrap_or(""),
        );
        let still_ahead = planned.iter().any(|p| {
            p.track_releases
                && p.target.name == target
                && p.target
                    .current
                    .as_deref()
                    .is_some_and(|cur| is_major(cur, version, p.target.major_component))
        });
        if !still_ahead {
            resolved += resolve(tx, id, now).await?;
        }
    }
    Ok(resolved)
}

/// Eol findings per realm for every running cycle whose end of support is
/// within the window, and resolution of those whose cycle the realm no
/// longer runs. A target whose fetch failed keeps its findings as they are.
async fn eol_findings(
    tx: &mut PgConnection,
    cfg: &HeimdallConfig,
    planned: &[Planned],
    running: &[Running],
    cycles: &HashMap<String, Vec<Cycle>>,
    now: DateTime<Utc>,
) -> anyhow::Result<(Vec<i64>, usize)> {
    let cutoff = (now + Duration::days(EOL_WINDOW_DAYS)).date_naive();
    let mut opened = Vec::new();
    // Keys of every cycle some realm runs, inside the window or not.
    let mut running_keys: HashSet<String> = HashSet::new();
    let eol_targets: Vec<&Planned> = planned
        .iter()
        .filter(|p| p.target.kind == WatchKind::Endoflife)
        .collect();
    for p in &eol_targets {
        let (Some(target_cycles), Some(name_key)) =
            (cycles.get(&p.target.name), &p.target.name_key)
        else {
            continue;
        };
        for (realm, c) in running.iter().filter(|(_, c)| &c.name_key == name_key) {
            let Some(version) = purl_version(&c.purl) else {
                continue;
            };
            let Some(cycle) = running_cycle(target_cycles, &version) else {
                continue;
            };
            let k = key(FindingKind::Eol, &[realm, &p.target.name, &cycle.cycle]);
            running_keys.insert(k.clone());
            let Some(eol) = cycle.eol.filter(|d| *d <= cutoff) else {
                continue;
            };
            let details = json!({
                "target": p.target.name,
                "cycle": cycle.cycle,
                "eol": eol,
                "version": version,
                "latest": cycle.latest,
            });
            opened.extend(
                open_finding(
                    tx,
                    &k,
                    FindingKind::Eol,
                    realm,
                    &cycle.cycle,
                    Severity::High,
                    &details,
                    now,
                )
                .await?,
            );
        }
    }

    let open: Vec<(i64, String, Option<String>)> = sqlx::query_as(
        "SELECT id, key, details->>'target' FROM findings WHERE kind = 'eol' AND status = 'open'",
    )
    .fetch_all(&mut *tx)
    .await?;
    let mut resolved = 0;
    for (id, k, target) in open {
        let target = target.unwrap_or_default();
        let configured = cfg
            .watchers
            .endoflife
            .iter()
            .any(|e| e.inventory_name == target);
        let checked = cycles.contains_key(&target);
        if !configured || (checked && !running_keys.contains(&k)) {
            resolved += resolve(tx, id, now).await?;
        }
    }
    Ok((opened, resolved))
}

/// The cycle `version` belongs to: the longest cycle name equal to the
/// version or followed by `.` (`16` for `16.4`, `1.31` for `v1.31.2+k3s1`).
fn running_cycle<'a>(cycles: &'a [Cycle], version: &str) -> Option<&'a Cycle> {
    let v = version.strip_prefix('v').unwrap_or(version);
    let v = v.split('+').next().unwrap_or(v);
    cycles
        .iter()
        .filter(|c| {
            v == c.cycle
                || v.starts_with(&format!("{}.", c.cycle))
                || v.starts_with(&format!("{}-", c.cycle))
        })
        .max_by_key(|c| c.cycle.len())
}

/// Insert a finding, or re-open a resolved one with the same key. Returns its
/// id when it is a new occurrence (None when already open). The columns are
/// all separate arguments on purpose: a one-use struct would hide them.
#[allow(clippy::too_many_arguments)]
pub(super) async fn open_finding(
    tx: &mut PgConnection,
    k: &str,
    kind: FindingKind,
    realm: &str,
    ref_id: &str,
    severity: Severity,
    details: &Value,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<i64>> {
    let id = sqlx::query_scalar(
        "INSERT INTO findings (key, kind, realm, ref_id, severity, details, opened_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (key) DO UPDATE SET status = 'open', opened_at = EXCLUDED.opened_at, \
             resolved_at = NULL, notified_at = NULL, details = EXCLUDED.details \
         WHERE findings.status = 'resolved' \
         RETURNING id",
    )
    .bind(k)
    .bind(kind)
    .bind(realm)
    .bind(ref_id)
    .bind(severity)
    .bind(details)
    .bind(now)
    .fetch_optional(&mut *tx)
    .await?;
    Ok(id)
}

async fn resolve(tx: &mut PgConnection, id: i64, now: DateTime<Utc>) -> anyhow::Result<usize> {
    let n = sqlx::query("UPDATE findings SET status = 'resolved', resolved_at = $2 WHERE id = $1")
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    Ok(n as usize)
}
