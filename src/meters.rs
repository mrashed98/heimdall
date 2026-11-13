//! Prometheus metrics (`GET /metrics`).
//!
//! Gauges are read from the database and recomputed after each matcher run
//! (`recompute`). Counters and the watcher durations are bumped by the
//! scheduler from what each run reports. Values go to whichever `metrics`
//! recorder is active: the global one `install` sets in `serve`, or a test's
//! local recorder.

use std::collections::BTreeSet;
use std::sync::{Mutex, OnceLock};

use anyhow::Context;
use chrono::{DateTime, Utc};
use metrics::{counter, gauge, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use sqlx::PgPool;

use crate::config::HeimdallConfig;
use crate::notify::outbox::DrainResult;
use crate::watchers::{self, WatchReport};

/// Labels of one `heimdall_findings_open` series: realm, service, kind,
/// severity. A finding without a service has service "".
type FindingLabels = (String, String, String, String);

/// The gauge values, read from the database.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Gauges {
    pub findings_open: Vec<(FindingLabels, i64)>,
    /// `(realm, target, releases behind)`.
    pub versions_behind: Vec<(String, String, u64)>,
    pub outbox_pending: i64,
    pub oaths_snooze: i64,
    pub oaths_ignore: i64,
    /// The soonest an active oath expires or comes up for review.
    pub oath_next_expiry: Option<DateTime<Utc>>,
}

/// Read every gauge value.
pub async fn gauges(pool: &PgPool, cfg: &HeimdallConfig) -> anyhow::Result<Gauges> {
    let findings: Vec<(String, String, String, String, i64)> = sqlx::query_as(
        "SELECT f.realm, coalesce(s.name, ''), f.kind, f.severity, count(*) \
         FROM findings f LEFT JOIN services s ON s.id = f.service_id \
         WHERE f.status = 'open' \
         GROUP BY 1, 2, 3, 4",
    )
    .fetch_all(pool)
    .await
    .context("counting open findings")?;
    let outbox_pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM outbox WHERE sent_at IS NULL")
            .fetch_one(pool)
            .await?;
    let (oaths_snooze, oaths_ignore, oath_next_expiry): (i64, i64, Option<DateTime<Utc>>) =
        sqlx::query_as(
            "SELECT count(*) FILTER (WHERE kind = 'snooze'), \
                    count(*) FILTER (WHERE kind = 'ignore'), \
                    min(CASE kind WHEN 'snooze' THEN expires_at ELSE review_at END) \
             FROM oaths WHERE status = 'active'",
        )
        .fetch_one(pool)
        .await?;
    let versions_behind = watchers::versions_behind(pool, cfg)
        .await
        .context("counting versions behind")?;
    Ok(Gauges {
        findings_open: findings
            .into_iter()
            .map(|(realm, service, kind, severity, n)| ((realm, service, kind, severity), n))
            .collect(),
        versions_behind,
        outbox_pending,
        oaths_snooze,
        oaths_ignore,
        oath_next_expiry,
    })
}

/// Set the gauges to `g`. Series in `previous` that `g` no longer has are set
/// to 0, so a resolved finding does not stay counted.
pub fn publish(g: &Gauges, previous: Option<&Gauges>) {
    let now_findings: BTreeSet<&FindingLabels> = g.findings_open.iter().map(|(l, _)| l).collect();
    if let Some(prev) = previous {
        for (labels, _) in &prev.findings_open {
            if !now_findings.contains(labels) {
                findings_gauge(labels).set(0.0);
            }
        }
        let now_targets: BTreeSet<(&String, &String)> =
            g.versions_behind.iter().map(|(r, t, _)| (r, t)).collect();
        for (realm, target, _) in &prev.versions_behind {
            if !now_targets.contains(&(realm, target)) {
                behind_gauge(realm, target).set(0.0);
            }
        }
    }
    for (labels, n) in &g.findings_open {
        findings_gauge(labels).set(*n as f64);
    }
    for (realm, target, n) in &g.versions_behind {
        behind_gauge(realm, target).set(*n as f64);
    }
    gauge!("heimdall_outbox_pending").set(g.outbox_pending as f64);
    gauge!("heimdall_oaths_active", "kind" => "snooze").set(g.oaths_snooze as f64);
    gauge!("heimdall_oaths_active", "kind" => "ignore").set(g.oaths_ignore as f64);
    // 0 means no active oath has a date.
    let next = g.oath_next_expiry.map_or(0.0, |t| t.timestamp() as f64);
    gauge!("heimdall_oath_next_expiry_timestamp_seconds").set(next);
}

fn findings_gauge(labels: &FindingLabels) -> metrics::Gauge {
    let (realm, service, kind, severity) = labels.clone();
    gauge!("heimdall_findings_open",
        "realm" => realm, "service" => service, "kind" => kind, "severity" => severity)
}

fn behind_gauge(realm: &str, target: &str) -> metrics::Gauge {
    gauge!("heimdall_versions_behind",
        "realm" => realm.to_string(), "target" => target.to_string())
}

/// What the last `recompute` published, to zero series that disappear.
static LAST: Mutex<Option<Gauges>> = Mutex::new(None);

/// Read the gauges and publish them. Called after each matcher run.
pub async fn recompute(pool: &PgPool, cfg: &HeimdallConfig) -> anyhow::Result<()> {
    let g = gauges(pool, cfg).await?;
    // A poisoned lock only means a panic elsewhere; the value is still usable.
    let mut last = LAST.lock().unwrap_or_else(|e| e.into_inner());
    publish(&g, last.as_ref());
    *last = Some(g);
    Ok(())
}

/// Add one watchers run to the failure counters and duration histograms.
pub fn record_watch(r: &WatchReport) {
    for (watcher, n) in &r.failures {
        counter!("heimdall_watcher_failures_total", "watcher" => watcher.clone()).increment(*n);
    }
    for (watcher, d) in &r.durations {
        histogram!("heimdall_watcher_duration_seconds", "watcher" => watcher.clone())
            .record(d.as_secs_f64());
    }
}

/// Count cards Teams rejected.
pub fn record_drain(r: &DrainResult) {
    // Registered even at 0 so the series exists before the first failure.
    counter!("heimdall_teams_failures_total").increment(r.failed as u64);
}

/// Install the global Prometheus recorder (once per process) and return the
/// handle `/metrics` renders.
pub fn install() -> anyhow::Result<PrometheusHandle> {
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    if let Some(h) = HANDLE.get() {
        return Ok(h.clone());
    }
    let handle = PrometheusBuilder::new()
        .install_recorder()
        .context("installing the prometheus recorder")?;
    Ok(HANDLE.get_or_init(|| handle).clone())
}
