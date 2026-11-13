//! Gjallarhorn: announces findings in Teams.
//!
//! - this file: which findings alert, how they are grouped into one card per
//!   advisory or release, and routing them into the outbox.
//! - `teams`: the Adaptive Card payloads.
//! - `outbox`: sending queued cards, paced, with retries.
//! - `digest`: the weekly digest of everything that did not alert.
//!
//! A finding is announced once: `notified_at` is set in the same transaction
//! that queues its card, so a crash either queues and marks or does neither.

pub mod digest;
pub mod outbox;
pub mod teams;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgPool};

use crate::config::{HeimdallConfig, TeamsRoute};
use crate::model::{FindingKind, Severity};

/// One finding on a card.
#[derive(Debug, Clone, PartialEq, FromRow)]
pub struct AlertItem {
    pub finding_id: i64,
    pub kind: FindingKind,
    pub realm: String,
    /// None for findings not tied to a service (releases, Kubernetes CVEs).
    pub service: Option<String>,
    pub severity: Severity,
    /// The finding's `details`, as the matcher or watcher wrote them.
    pub details: Value,
}

/// What the card shows about the advisory itself.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AdvisoryInfo {
    pub summary: String,
    /// `{"osv": 7.5, "nvd": 9.8}`
    pub scores: Value,
}

/// What the card shows about a release's notes.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ReleaseInfo {
    pub notes_url: Option<String>,
    pub breaking: Vec<String>,
}

/// One card: every pending finding of one kind about one advisory or release.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertGroup {
    pub kind: FindingKind,
    pub ref_id: String,
    pub items: Vec<AlertItem>,
    /// Findings this card also announces without showing them separately
    /// (a FixAvailable whose Vuln card already shows the fix advice).
    pub absorbed: Vec<i64>,
    pub advisory: Option<AdvisoryInfo>,
    pub release: Option<ReleaseInfo>,
}

impl AlertGroup {
    /// The worst severity among the items.
    pub fn worst(&self) -> Severity {
        self.items
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::Unknown)
    }

    /// The severity routes compare against. Releases, end of support and
    /// Kubernetes CVEs count as High. A release-note CVE always alerts, so it
    /// never routes below High.
    pub fn routing_severity(&self) -> Severity {
        match self.kind {
            FindingKind::MajorRelease | FindingKind::Eol | FindingKind::K8sCve => Severity::High,
            FindingKind::ReleaseNoteCve => self.worst().max(Severity::High),
            _ => self.worst(),
        }
    }

    /// The `(kind, ref_id)` grouping key. A release's ref_id (version, cycle)
    /// is only unique per target, so the target is part of the key for those.
    fn key(&self) -> String {
        group_key(self.items.first(), self.kind, &self.ref_id)
    }
}

fn group_key(item: Option<&AlertItem>, kind: FindingKind, ref_id: &str) -> String {
    let detail = |name: &str| {
        item.and_then(|i| i.details[name].as_str())
            .unwrap_or_default()
            .to_string()
    };
    let k = kind_name(kind);
    match kind {
        FindingKind::MajorRelease | FindingKind::Eol => {
            format!("{k}|{}|{ref_id}", detail("target"))
        }
        FindingKind::ReleaseNoteCve => {
            format!("{k}|{}|{}|{ref_id}", detail("target"), detail("version"))
        }
        _ => format!("{k}|{ref_id}"),
    }
}

/// The lowercase name stored in the database.
fn kind_name(kind: FindingKind) -> &'static str {
    match kind {
        FindingKind::Vuln => "vuln",
        FindingKind::FixAvailable => "fixavailable",
        FindingKind::MajorRelease => "majorrelease",
        FindingKind::OathExpired => "oathexpired",
        FindingKind::Eol => "eol",
        FindingKind::K8sCve => "k8scve",
        FindingKind::ReleaseNoteCve => "releasenotecve",
    }
}

/// Queue a card for every alertable finding not announced yet, one per
/// advisory or release and route, and mark the findings notified, all in one
/// transaction. Returns the number of outbox rows queued.
///
/// With no Teams route configured nothing is marked, so the alerts are not
/// lost: they go out once a route exists.
pub async fn enqueue_alerts(pool: &PgPool, cfg: &HeimdallConfig) -> anyhow::Result<usize> {
    if cfg.teams.is_empty() {
        return Ok(0);
    }
    let mut tx = pool.begin().await?;
    lock_realms(&mut tx, cfg).await?;

    let items = pending(&mut tx).await?;
    if items.is_empty() {
        return Ok(0);
    }
    let mut ids: Vec<i64> = items.iter().map(|(_, i)| i.finding_id).collect();
    let mut groups = group(items);
    for g in &mut groups {
        load_extras(&mut tx, g).await?;
        ids.extend(&g.absorbed);
    }

    let mut queued = 0;
    for g in &groups {
        for route in &cfg.teams {
            let Some(sub) = for_route(g, route) else {
                continue;
            };
            let card = teams::card(&sub);
            outbox::push(&mut tx, &format!("alert|{}", g.key()), &card, &route.name).await?;
            queued += 1;
        }
    }
    mark_notified(&mut tx, &ids).await?;
    tx.commit().await?;
    Ok(queued)
}

/// The "Heimdall has opened his eyes" card for `realm`: open findings counted
/// by severity, queued once per realm (kv `first_run|<realm>`) to every route
/// covering the realm. The scheduler calls it before the realm's first
/// `enqueue_alerts`, so it is the first card sent. Returns whether it queued.
pub async fn enqueue_first_run_summary(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    realm: &str,
) -> anyhow::Result<bool> {
    let routes: Vec<&TeamsRoute> = cfg.teams.iter().filter(|r| covers(r, realm)).collect();
    if routes.is_empty() {
        return Ok(false);
    }
    let mut tx = pool.begin().await?;
    let first: Option<String> = sqlx::query_scalar(
        "INSERT INTO kv (key, value) VALUES ($1, 'sent') ON CONFLICT (key) DO NOTHING RETURNING key",
    )
    .bind(format!("first_run|{realm}"))
    .fetch_optional(&mut *tx)
    .await?;
    if first.is_none() {
        return Ok(false);
    }
    let counts: Vec<(Severity, i64)> = sqlx::query_as(
        "SELECT severity, count(*) FROM findings WHERE realm = $1 AND status = 'open' \
         GROUP BY severity",
    )
    .bind(realm)
    .fetch_all(&mut *tx)
    .await?;
    let card = teams::summary_card(realm, &counts);
    for route in routes {
        outbox::push(&mut tx, &format!("first_run|{realm}"), &card, &route.name).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Take every realm's matcher lock (sorted, like the watchers), so no matcher
/// run re-opens a finding between our read and our `notified_at` write.
async fn lock_realms(tx: &mut PgConnection, cfg: &HeimdallConfig) -> anyhow::Result<()> {
    let mut realms: BTreeSet<String> = cfg.realms.iter().cloned().collect();
    // Findings of a realm since removed from the config still alert.
    let stored: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT realm FROM findings WHERE status = 'open' AND notified_at IS NULL",
    )
    .fetch_all(&mut *tx)
    .await?;
    realms.extend(stored);
    for realm in &realms {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('matcher:' || $1))")
            .bind(realm)
            .execute(&mut *tx)
            .await?;
    }
    Ok(())
}

/// A pending finding and the advisory or release id it is grouped by.
#[derive(FromRow)]
struct Pending {
    ref_id: Option<String>,
    #[sqlx(flatten)]
    item: AlertItem,
}

/// Open, not yet announced findings that deserve an immediate alert: a Vuln
/// of high or worse not under an oath, and every finding of the other kinds.
async fn pending(tx: &mut PgConnection) -> anyhow::Result<Vec<(String, AlertItem)>> {
    let rows: Vec<Pending> = sqlx::query_as(
        "SELECT f.id AS finding_id, f.ref_id, f.kind, f.realm, s.name AS service, f.severity, f.details \
         FROM findings f LEFT JOIN services s ON s.id = f.service_id \
         WHERE f.status = 'open' AND f.notified_at IS NULL \
           AND (f.kind <> 'vuln' \
                OR (f.severity IN ('critical', 'high') \
                    AND coalesce(f.details->'oath', 'null'::jsonb) = 'null'::jsonb)) \
         ORDER BY f.id \
         FOR UPDATE OF f",
    )
    .fetch_all(&mut *tx)
    .await?;
    Ok(rows
        .into_iter()
        .map(|p| (p.ref_id.unwrap_or_default(), p.item))
        .collect())
}

/// Group findings into cards, worst first:
/// - one group per `(kind, ref_id)` (plus target for releases);
/// - a FixAvailable whose service already has a Vuln card for the same
///   advisory is absorbed into that card, which shows the fix advice;
/// - a Vuln card for an advisory whose oath just expired merges into the
///   "Oath expired" card, so the advisory gives one card, not two.
pub fn group(items: Vec<(String, AlertItem)>) -> Vec<AlertGroup> {
    let mut groups: BTreeMap<String, AlertGroup> = BTreeMap::new();
    for (ref_id, item) in items {
        let k = group_key(Some(&item), item.kind, &ref_id);
        groups
            .entry(k)
            .or_insert_with(|| AlertGroup {
                kind: item.kind,
                ref_id,
                items: Vec::new(),
                absorbed: Vec::new(),
                advisory: None,
                release: None,
            })
            .items
            .push(item);
    }

    let advisories: Vec<String> = groups
        .values()
        .filter(|g| g.kind == FindingKind::FixAvailable)
        .map(|g| g.ref_id.clone())
        .collect();
    for adv in advisories {
        let fix_key = format!("fixavailable|{adv}");
        let Some(vuln) = groups.get(&format!("vuln|{adv}")) else {
            continue;
        };
        let covered: BTreeSet<(String, Option<String>)> = vuln
            .items
            .iter()
            .map(|i| (i.realm.clone(), i.service.clone()))
            .collect();
        let fix = groups.get_mut(&fix_key).expect("collected above");
        let (folded, kept): (Vec<AlertItem>, Vec<AlertItem>) = fix
            .items
            .drain(..)
            .partition(|i| covered.contains(&(i.realm.clone(), i.service.clone())));
        fix.items = kept;
        let folded_ids: Vec<i64> = folded.iter().map(|i| i.finding_id).collect();
        if fix.items.is_empty() {
            groups.remove(&fix_key);
        }
        if let Some(vuln) = groups.get_mut(&format!("vuln|{adv}")) {
            vuln.absorbed.extend(folded_ids);
        }
    }

    let expired: Vec<String> = groups
        .values()
        .filter(|g| g.kind == FindingKind::OathExpired)
        .map(|g| g.ref_id.clone())
        .collect();
    for adv in expired {
        if let Some(vuln) = groups.remove(&format!("vuln|{adv}")) {
            let oath = groups
                .get_mut(&format!("oathexpired|{adv}"))
                .expect("collected above");
            oath.items.extend(vuln.items);
            oath.absorbed.extend(vuln.absorbed);
        }
    }

    let mut out: Vec<AlertGroup> = groups.into_values().collect();
    out.sort_by_key(|g| {
        let first = g.items.iter().map(|i| i.finding_id).min().unwrap_or(0);
        (std::cmp::Reverse(g.routing_severity()), first)
    });
    out
}

/// Advisory summary and scores, and release notes, for the card.
async fn load_extras(tx: &mut PgConnection, g: &mut AlertGroup) -> anyhow::Result<()> {
    let advisory_kinds = [
        FindingKind::Vuln,
        FindingKind::FixAvailable,
        FindingKind::OathExpired,
        FindingKind::ReleaseNoteCve,
    ];
    if advisory_kinds.contains(&g.kind) {
        let row: Option<(String, Value)> =
            sqlx::query_as("SELECT summary, scores FROM advisories WHERE id = $1")
                .bind(&g.ref_id)
                .fetch_optional(&mut *tx)
                .await?;
        g.advisory = row.map(|(summary, scores)| AdvisoryInfo { summary, scores });
    }
    if matches!(
        g.kind,
        FindingKind::MajorRelease | FindingKind::ReleaseNoteCve
    ) {
        let Some(first) = g.items.first() else {
            return Ok(());
        };
        let target = first.details["target"].as_str().unwrap_or_default();
        let version = first.details["version"].as_str().unwrap_or_default();
        let row: Option<(Option<String>, Option<Value>)> = sqlx::query_as(
            "SELECT notes_url, excerpt FROM releases WHERE target = $1 AND version = $2",
        )
        .bind(target)
        .bind(version)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some((notes_url, excerpt)) = row {
            let breaking = excerpt
                .as_ref()
                .and_then(|e| e["breaking"].as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|l| l.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            g.release = Some(ReleaseInfo {
                notes_url,
                breaking,
            });
        }
    }
    Ok(())
}

/// Does the route cover this realm? An empty realm list covers all.
fn covers(route: &TeamsRoute, realm: &str) -> bool {
    route.realms.is_empty() || route.realms.iter().any(|r| r == realm)
}

/// The part of `g` this route receives: only the items of realms it covers,
/// and only when that part is severe enough for it.
fn for_route(g: &AlertGroup, route: &TeamsRoute) -> Option<AlertGroup> {
    let mut sub = g.clone();
    sub.items.retain(|i| covers(route, &i.realm));
    if sub.items.is_empty() || sub.routing_severity() < route.min_severity {
        return None;
    }
    Some(sub)
}

/// Mark findings announced. One-shot kinds (OathExpired, K8sCve,
/// ReleaseNoteCve) are resolved at the same time: nothing else ever resolves
/// them, and they would count as open forever.
async fn mark_notified(tx: &mut PgConnection, ids: &[i64]) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE findings SET notified_at = now(), \
             status = CASE WHEN kind IN ('oathexpired', 'k8scve', 'releasenotecve') \
                           THEN 'resolved' ELSE status END, \
             resolved_at = CASE WHEN kind IN ('oathexpired', 'k8scve', 'releasenotecve') \
                                THEN now() ELSE resolved_at END \
         WHERE id = ANY($1)",
    )
    .bind(ids)
    .execute(&mut *tx)
    .await?;
    Ok(())
}
