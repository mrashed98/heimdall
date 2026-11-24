//! Gjallarhorn: announces findings on the configured alert channels (Teams,
//! Slack, Discord, Telegram, PagerDuty, Alertmanager, a generic webhook,
//! email).
//!
//! - this file: which findings alert, and routing them into the outbox.
//! - `group`: how findings are grouped into one alert per advisory or release.
//! - `alert`: the neutral alert model every channel renders.
//! - `teams`: the Teams formatter (Adaptive Cards).
//! - `channels`: the other formatters, and the requests that send them.
//! - `outbox`: sending queued payloads, paced, with retries.
//! - `digest`: the weekly digest of everything that did not alert.
//!
//! A finding is announced once: `notified_at` is set in the same transaction
//! that queues its alerts, so a crash either queues and marks or does neither.

pub mod alert;
pub mod channels;
pub mod digest;
mod group;
pub mod outbox;
pub mod store;
pub mod teams;

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;
use std::sync::Mutex;

use serde_json::Value;
use sqlx::{FromRow, PgConnection, PgPool};

use crate::config::{ChannelConfig, HeimdallConfig};
use crate::model::{FindingKind, Severity};
use alert::Alert;
use store::Channels;

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
    /// Kubernetes CVEs count as High. Kinds that always alert (an expired
    /// oath, a release-note CVE, a fix that is worth an alert, see
    /// `FIX_ALERTS_AT_ONCE`) never route below High, so a high-only route
    /// does not drop them. A Vuln routes at its own severity.
    pub fn routing_severity(&self) -> Severity {
        match self.kind {
            FindingKind::MajorRelease | FindingKind::Eol | FindingKind::K8sCve => Severity::High,
            FindingKind::FixAvailable | FindingKind::OathExpired | FindingKind::ReleaseNoteCve => {
                self.worst().max(Severity::High)
            }
            FindingKind::Vuln => self.worst(),
        }
    }

    /// The `(kind, ref_id)` grouping key. A release's ref_id (version, cycle)
    /// is only unique per target, so the target is part of the key for those.
    fn key(&self) -> String {
        group::group_key(self.items.first(), self.kind, &self.ref_id)
    }
}

/// Queue an alert for every alertable finding not announced yet, one per
/// advisory or release and channel, and mark the findings notified, all in
/// one transaction. Returns the number of outbox rows queued.
///
/// A finding of a realm no channel covers stays pending (and is warned about
/// once), so it goes out once a channel covers the realm. A finding every
/// covering channel filters out by `min_severity` is marked: that is an
/// explicit opt-out.
pub async fn enqueue_alerts(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    chans: &Channels,
) -> anyhow::Result<usize> {
    let chans = &chans.list;
    if chans.is_empty() {
        return Ok(0);
    }
    let mut tx = pool.begin().await?;
    lock_realms(&mut tx, cfg).await?;

    let items: Vec<(String, AlertItem)> = pending(&mut tx)
        .await?
        .into_iter()
        .filter(|(_, i)| realm_has_route(chans, &i.realm))
        .collect();
    if items.is_empty() {
        return Ok(0);
    }
    let mut ids: Vec<i64> = items.iter().map(|(_, i)| i.finding_id).collect();
    let mut groups = group::group(items);
    for g in &mut groups {
        load_extras(&mut tx, g).await?;
        ids.extend(&g.absorbed);
    }

    let mut queued = 0;
    for g in &groups {
        for ch in chans {
            let Some(sub) = for_route(g, ch) else {
                continue;
            };
            let payload = channels::render(ch, &Alert::from_group(&sub));
            outbox::push(&mut tx, &format!("alert|{}", g.key()), &payload, ch).await?;
            queued += 1;
        }
    }
    mark_notified(&mut tx, &ids).await?;
    tx.commit().await?;
    Ok(queued)
}

/// The "Heimdall has opened his eyes" card for `realm`: open findings counted
/// by severity, queued once per realm (kv `first_run|<realm>`) to every
/// channel covering the realm that takes the digest (`wants_digest`). The
/// scheduler calls it before the realm's
/// first `enqueue_alerts`, so it is the first alert sent. Returns whether it
/// queued.
pub async fn enqueue_first_run_summary(
    pool: &PgPool,
    _cfg: &HeimdallConfig,
    chans: &Channels,
    realm: &str,
) -> anyhow::Result<bool> {
    let routes: Vec<&ChannelConfig> = chans
        .list
        .iter()
        .filter(|c| c.covers(realm) && c.wants_digest())
        .collect();
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
    let summary = Alert::first_run(realm, &counts);
    for ch in routes {
        let payload = channels::render(ch, &summary);
        outbox::push(&mut tx, &format!("first_run|{realm}"), &payload, ch).await?;
    }
    tx.commit().await?;
    Ok(true)
}

/// Baseline: mark every open, not yet announced finding of `realm` as
/// announced without queuing anything, so a channel added to a realm with a
/// backlog is not flooded. The findings stay open in the UI, API and counts;
/// one-shot kinds resolve as if sent. Afterwards only new findings and state
/// changes (a fix appears, an oath expires, severity rises) alert. Audited.
/// Returns how many findings were marked.
pub async fn baseline(pool: &PgPool, cfg: &HeimdallConfig, realm: &str) -> anyhow::Result<usize> {
    anyhow::ensure!(
        cfg.realms.iter().any(|r| r == realm),
        "unknown realm {realm:?} (configured: {})",
        cfg.realms.join(", ")
    );
    let mut tx = pool.begin().await?;
    lock_realms(&mut tx, cfg).await?;
    let ids: Vec<i64> = sqlx::query_scalar(
        "SELECT id FROM findings WHERE realm = $1 AND status = 'open' \
         AND notified_at IS NULL FOR UPDATE",
    )
    .bind(realm)
    .fetch_all(&mut *tx)
    .await?;
    mark_notified(&mut tx, &ids).await?;
    sqlx::query(
        "INSERT INTO audit_log (action, method, detail) VALUES ('findings_baseline', 'cli', \
         jsonb_build_object('realm', $1::text, 'findings', $2::bigint))",
    )
    .bind(realm)
    .bind(ids.len() as i64)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(ids.len())
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

/// SQL condition on a FixAvailable `f`: it deserves an immediate alert.
/// That is when its Vuln is High or worse (the FixAvailable carries the
/// Vuln's severity), or when the fix came out after the Vuln was first
/// opened: the Vuln of the same component and advisory was opened by an
/// earlier matcher run. A medium or low Vuln that had a fix from the start
/// gets both into the weekly digest instead.
pub(crate) const FIX_ALERTS_AT_ONCE: &str = "(f.severity IN ('critical', 'high') \
     OR EXISTS (SELECT 1 FROM findings v \
                WHERE v.kind = 'vuln' AND v.realm = f.realm \
                  AND v.service_id IS NOT DISTINCT FROM f.service_id \
                  AND v.component_id IS NOT DISTINCT FROM f.component_id \
                  AND v.ref_id = f.ref_id AND v.opened_at < f.opened_at))";

/// Open, not yet announced findings that deserve an immediate alert: a Vuln
/// of high or worse not under an oath, a FixAvailable that passes
/// `FIX_ALERTS_AT_ONCE`, and every finding of the other kinds.
async fn pending(tx: &mut PgConnection) -> anyhow::Result<Vec<(String, AlertItem)>> {
    let sql = format!(
        "SELECT f.id AS finding_id, f.ref_id, f.kind, f.realm, s.name AS service, f.severity, f.details \
         FROM findings f LEFT JOIN services s ON s.id = f.service_id \
         WHERE f.status = 'open' AND f.notified_at IS NULL \
           AND (f.kind <> 'vuln' \
                OR (f.severity IN ('critical', 'high') \
                    AND coalesce(f.details->'oath', 'null'::jsonb) = 'null'::jsonb)) \
           AND (f.kind <> 'fixavailable' OR {FIX_ALERTS_AT_ONCE}) \
         ORDER BY f.id \
         FOR UPDATE OF f"
    );
    let rows: Vec<Pending> = sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .fetch_all(&mut *tx)
        .await?;
    Ok(rows
        .into_iter()
        .map(|p| (p.ref_id.unwrap_or_default(), p.item))
        .collect())
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

/// Does any channel (a `teams:` route, a `channels:` entry or a UI channel)
/// cover this realm? Warns once per realm when none does.
pub(crate) fn realm_has_route(chans: &[ChannelConfig], realm: &str) -> bool {
    let covered = chans.iter().any(|c| c.covers(realm));
    if !covered {
        warn_once(
            &format!("realm|{realm}"),
            &format!("no alert channel covers realm {realm}; its findings stay pending"),
        );
    }
    covered
}

/// Warnings already logged, by key, so a condition checked every few
/// seconds is logged once per process.
static WARNED: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());

pub(crate) fn warn_once(key: &str, message: &str) {
    // A poisoned lock only means another thread panicked mid-insert; the set
    // is still usable.
    let mut warned = WARNED.lock().unwrap_or_else(|e| e.into_inner());
    if warned.insert(key.to_string()) {
        tracing::warn!("{message}");
    }
}

/// The part of `g` this channel receives: only the items of realms it
/// covers, and only when that part is severe enough for it.
fn for_route(g: &AlertGroup, ch: &ChannelConfig) -> Option<AlertGroup> {
    let mut sub = g.clone();
    sub.items.retain(|i| ch.covers(&i.realm));
    if sub.items.is_empty() || sub.routing_severity() < ch.min_severity() {
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
