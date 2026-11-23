//! The scheduled loops of `heimdall serve`.
//!
//! On start, each realm gets its first run in order: Sight (the in-process
//! realm only), OSV refresh, matcher, the first-run summary card, then
//! alerts. Only then do the loops start, so no alert can beat a realm's
//! summary. Each loop is a `tokio::time::interval` that skips missed ticks;
//! its first tick is immediate, except for the loops the first run just did.
//!
//! An iteration runs as its own task: an error is logged, a panic is logged
//! as a `JoinError`, and the loop goes on either way. Several loops call the
//! matcher; it takes a per-realm advisory lock, so that is safe.
//!
//! Oath expiries have no loop of their own: the matcher processes them, and
//! it runs after every OSV refresh, at least every 15 minutes.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::Context;
use chrono::Utc;
use tokio::task::JoinSet;
use tokio::time::{interval, MissedTickBehavior};
use tracing::Instrument;
use url::Url;

use crate::config::HeimdallConfig;
use crate::inventory::{sight, store};
use crate::notify::{self, digest, outbox};
use crate::vuln::{epss, k8s_feed, nvd, osv};
use crate::{matcher, meters, retention, watchers, AppState};

/// Where the Kubernetes CVE feed lives.
const K8S_FEED_BASE: &str = "https://kubernetes.io";

/// What every job needs. Cheap to clone: the state is shared handles.
#[derive(Clone)]
struct Ctx {
    state: AppState,
    /// The realm in-process Sight scans; None when no cluster is reachable.
    sight_realm: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Job {
    Sight,
    Osv,
    K8sFeed,
    Watchers,
    Outbox,
    Digest,
    Nvd,
    Epss,
    Retention,
}

/// The longest the OSV loop waits. Its matcher run also expires oaths, so
/// this bounds how late a lapsed oath is noticed.
const MAX_OSV_MINUTES: u32 = 15;

impl Job {
    const ALL: [Job; 9] = [
        Job::Sight,
        Job::Osv,
        Job::K8sFeed,
        Job::Watchers,
        Job::Outbox,
        Job::Digest,
        Job::Nvd,
        Job::Epss,
        Job::Retention,
    ];

    fn name(self) -> &'static str {
        match self {
            Job::Sight => "sight",
            Job::Osv => "osv",
            Job::K8sFeed => "k8s_feed",
            Job::Watchers => "watchers",
            Job::Outbox => "outbox",
            Job::Digest => "digest",
            Job::Nvd => "nvd",
            Job::Epss => "epss",
            Job::Retention => "retention",
        }
    }

    fn period(self, cfg: &HeimdallConfig) -> Duration {
        // `interval` panics on a zero period, so a 0 in the config means 1.
        let minutes = |m: u32| Duration::from_secs(u64::from(m.max(1)) * 60);
        match self {
            Job::Sight => minutes(cfg.schedules.sight_minutes),
            Job::Osv => minutes(cfg.schedules.osv_minutes.min(MAX_OSV_MINUTES)),
            Job::K8sFeed => minutes(cfg.schedules.k8s_cve_minutes),
            Job::Watchers => minutes(cfg.schedules.watchers_minutes),
            Job::Outbox => Duration::from_secs(2),
            Job::Digest => minutes(1),
            Job::Nvd => minutes(cfg.nvd.minutes),
            // FIRST publishes one file a day.
            Job::Epss => minutes(24 * 60),
            Job::Retention => minutes(24 * 60),
        }
    }

    /// The first run already did these, so their loop waits one period.
    fn done_at_startup(self) -> bool {
        matches!(self, Job::Sight | Job::Osv)
    }
}

/// Run the first run, then every loop, until the task is aborted (which
/// drops the `JoinSet` and so aborts the loops with it).
pub async fn run(state: AppState) {
    let sight_realm = sight_realm(&state.cfg).await;
    let ctx = Ctx { state, sight_realm };
    first_run(&ctx).await;

    let mut loops = JoinSet::new();
    for job in Job::ALL {
        if job == Job::Sight && ctx.sight_realm.is_none() {
            continue;
        }
        loops.spawn(run_loop(job, ctx.clone()));
    }
    // Loops never end; this only wakes if one dies outside an iteration.
    while let Some(ended) = loops.join_next().await {
        tracing::error!("a scheduler loop ended: {ended:?}");
    }
}

/// The realm in-process Sight scans, when a cluster client can be made
/// (in-cluster or kubeconfig). Otherwise it is logged once and skipped.
async fn sight_realm(cfg: &HeimdallConfig) -> Option<String> {
    let realm = cfg.sight_realm()?.to_string();
    if !cfg.realms.contains(&realm) {
        tracing::error!(realm = %realm, "sight.realm is not a configured realm; sight is off");
        return None;
    }
    match kube::Client::try_default().await {
        Ok(_) => Some(realm),
        Err(e) => {
            tracing::info!(realm = %realm, "no cluster client ({e}); in-process sight is off");
            None
        }
    }
}

async fn first_run(ctx: &Ctx) {
    let st = &ctx.state;
    let span = tracing::info_span!("first_run");
    async {
        tracing::info!("first run started");
        if let Some(realm) = &ctx.sight_realm {
            log_failure("sight", sight_once(st, realm).await);
        }
        log_failure("osv", osv_refresh(st).await);
        let matched = match_all(st).await;
        log_failure("alerts", announce(st, &matched).await);
        log_failure("gauges", meters::recompute(&st.pool, &st.cfg).await);
        tracing::info!("first run done");
    }
    .instrument(span)
    .await
}

async fn run_loop(job: Job, ctx: Ctx) {
    let period = job.period(&ctx.state.cfg);
    tracing::info!(
        job = job.name(),
        period_secs = period.as_secs(),
        "loop started"
    );
    let mut tick = interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
    if job.done_at_startup() {
        // The first tick completes at once; the first run stood in for it.
        tick.tick().await;
    }
    loop {
        tick.tick().await;
        // A JoinSet of one: dropping it (when this loop is aborted) aborts
        // the iteration too, and a panic comes back as a JoinError.
        let mut one = JoinSet::new();
        let span = tracing::info_span!("job", job = job.name());
        one.spawn(run_job(job, ctx.clone()).instrument(span));
        match one.join_next().await {
            Some(Ok(Ok(()))) | None => {}
            Some(Ok(Err(e))) => tracing::error!(job = job.name(), "iteration failed: {e:#}"),
            Some(Err(e)) => tracing::error!(job = job.name(), "iteration panicked: {e}"),
        }
    }
}

async fn run_job(job: Job, ctx: Ctx) -> anyhow::Result<()> {
    let st = &ctx.state;
    let now = Utc::now();
    match job {
        Job::Sight => {
            let realm = ctx.sight_realm.as_deref().context("sight has no realm")?;
            sight_once(st, realm).await
        }
        Job::Osv => {
            // Stale advisories still match: the matcher runs either way.
            log_failure("osv", osv_refresh(st).await);
            rematch(st).await
        }
        Job::Nvd => {
            log_failure("nvd", nvd_refresh(st).await);
            rematch(st).await
        }
        Job::Epss => {
            // Scores only annotate findings: nothing to rematch or announce.
            let r = epss::refresh(&st.pool, &st.http, epss::FEED_URL).await?;
            tracing::info!(kept = r.kept, total = r.total, date = %r.date, "epss refresh ran");
            record_sync(st, "epss").await
        }
        Job::K8sFeed => {
            let base = Url::parse(K8S_FEED_BASE).context("k8s feed url")?;
            // Fetched once, then filed per realm. An empty feed is an error,
            // logged as a warning; nothing is recorded until a good one.
            let cves = match k8s_feed::fetch(&st.http, &base).await {
                Ok(cves) => cves,
                Err(e) => {
                    tracing::warn!("k8s feed skipped: {e:#}");
                    return Ok(());
                }
            };
            let mut success = true;
            for realm in &st.cfg.realms {
                match k8s_feed::run(&st.pool, realm, &cves, now).await {
                    Ok(ids) => tracing::info!(realm = %realm, opened = ids.len(), "k8s feed ran"),
                    Err(e) => {
                        success = false;
                        tracing::error!(realm = %realm, "k8s feed failed: {e:#}");
                    }
                }
            }
            if success {
                record_sync(st, "k8s").await?;
            }
            announce(st, &st.cfg.realms).await
        }
        Job::Watchers => {
            let r = watchers::run_all(st, now).await?;
            meters::record_watch(&r);
            tracing::info!(
                targets = r.targets,
                new_releases = r.new_releases,
                opened = r.opened.len(),
                resolved = r.resolved,
                failures = r.failures.values().sum::<u64>(),
                "watchers ran"
            );
            announce(st, &st.cfg.realms).await
        }
        Job::Outbox => {
            let chans = channels(st).await?;
            let r = outbox::drain_once(&st.pool, &st.http, &st.cfg, &chans, now).await?;
            meters::record_drain(&r);
            // Every 2 s: quiet unless something happened.
            if r.sent + r.retry + r.failed > 0 {
                tracing::info!(
                    sent = r.sent,
                    retry = r.retry,
                    failed = r.failed,
                    "outbox drained"
                );
            } else {
                tracing::debug!("outbox idle");
            }
            Ok(())
        }
        Job::Digest => {
            let chans = channels(st).await?;
            if digest::maybe_send(&st.pool, &st.cfg, &chans, now).await? {
                tracing::info!("weekly digest queued");
            } else {
                tracing::debug!("no digest due");
            }
            Ok(())
        }
        Job::Retention => {
            let r = retention::cleanup(&st.pool, &st.cfg, now).await?;
            tracing::info!(
                findings = r.findings,
                releases = r.releases,
                outbox = r.outbox,
                scan_attempts = r.scan_attempts,
                "retention cleanup ran"
            );
            Ok(())
        }
    }
}

/// Matcher for every realm, then alerts, then the gauges.
async fn rematch(st: &AppState) -> anyhow::Result<()> {
    let matched = match_all(st).await;
    let alerts = announce(st, &matched).await;
    meters::recompute(&st.pool, &st.cfg).await?;
    alerts
}

async fn sight_once(st: &AppState, realm: &str) -> anyhow::Result<()> {
    let out = sight::run(Some(st), realm, None).await?;
    tracing::info!(
        realm = %realm,
        services = out.services,
        added = out.added,
        removed = out.removed,
        "sight ran"
    );
    record_sync(st, "sight").await?;
    Ok(())
}

async fn record_sync(st: &AppState, feed: &str) -> anyhow::Result<()> {
    sqlx::query("INSERT INTO kv (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value")
        .bind(format!("sync|{feed}")).bind(Utc::now().to_rfc3339()).execute(&st.pool).await?;
    Ok(())
}

/// Ask OSV about every component any realm runs, once each.
async fn osv_refresh(st: &AppState) -> anyhow::Result<()> {
    // Only (id, purl) is kept; each realm's full rows are dropped right away.
    let mut components: BTreeMap<i64, String> = BTreeMap::new();
    for realm in &st.cfg.realms {
        for c in store::effective_components(&st.pool, realm).await? {
            components.insert(c.component_id, c.purl);
        }
    }
    let list: Vec<(i64, String)> = components.into_iter().collect();
    let client = osv::OsvClient::new(st.http.clone());
    let r = osv::refresh(&st.pool, &client, &list).await?;
    tracing::info!(
        checked = r.checked,
        new_links = r.new_links,
        fetched = r.fetched,
        "osv refresh ran"
    );
    record_sync(st, "osv").await?;
    Ok(())
}

async fn nvd_refresh(st: &AppState) -> anyhow::Result<()> {
    // Without a key NVD still answers, only more slowly.
    let key = std::env::var(&st.cfg.nvd.api_key_env).unwrap_or_default();
    let client = nvd::NvdClient::new(st.http.clone(), key);
    let targets = nvd::target_cpes(&st.cfg);
    let r = nvd::refresh(&st.pool, &client, &targets, Utc::now()).await?;
    tracing::info!(
        changed = r.changed,
        matched = r.matched,
        uncomparable = r.uncomparable,
        "nvd refresh ran"
    );
    record_sync(st, "nvd").await?;
    Ok(())
}

/// Run the matcher for each realm; returns the realms it succeeded for.
async fn match_all(st: &AppState) -> Vec<String> {
    let mut ok = Vec::new();
    for realm in &st.cfg.realms {
        match matcher::run(&st.pool, realm, Utc::now()).await {
            Ok(r) => {
                tracing::info!(
                    realm = %realm,
                    opened = r.opened.len(),
                    resolved = r.resolved,
                    "matcher ran"
                );
                ok.push(realm.clone());
            }
            Err(e) => tracing::error!(realm = %realm, "matcher failed: {e:#}"),
        }
    }
    ok
}

/// Queue the first-run summary of each of `realms` (a no-op once sent), then
/// the alerts. If a summary could not be queued, alerts wait for the next
/// round so they never go out before it.
async fn announce(st: &AppState, realms: &[String]) -> anyhow::Result<()> {
    let chans = channels(st).await?;
    for realm in realms {
        if notify::enqueue_first_run_summary(&st.pool, &st.cfg, &chans, realm)
            .await
            .with_context(|| format!("first-run summary of {realm}; alerts wait"))?
        {
            tracing::info!(realm = %realm, "first-run summary queued");
        }
    }
    let queued = notify::enqueue_alerts(&st.pool, &st.cfg, &chans).await?;
    if queued > 0 {
        tracing::info!(queued, "alerts queued");
    }
    Ok(())
}

/// The config and UI alert channels, loaded once per tick.
async fn channels(st: &AppState) -> anyhow::Result<notify::store::Channels> {
    notify::store::load(&st.pool, &st.cfg, st.secret_key.as_deref()).await
}

fn log_failure(step: &str, r: anyhow::Result<()>) {
    if let Err(e) = r {
        tracing::error!(step, "{e:#}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(yaml: &str) -> HeimdallConfig {
        serde_saphyr::from_str(yaml).unwrap()
    }

    #[test]
    fn oath_expiry_waits_at_most_15_minutes() {
        // No loop of its own: the matcher after each OSV refresh processes
        // expiries, so that loop never waits longer than 15 minutes.
        assert!(!Job::ALL.iter().any(|j| j.name() == "oaths"));
        let quarter = Duration::from_secs(15 * 60);
        assert_eq!(Job::Osv.period(&cfg("realms: [prod]\n")), quarter);
        let slow = cfg("realms: [prod]\nschedules: {osv_minutes: 60}\n");
        assert_eq!(Job::Osv.period(&slow), quarter);
        let fast = cfg("realms: [prod]\nschedules: {osv_minutes: 5}\n");
        assert_eq!(Job::Osv.period(&fast), Duration::from_secs(5 * 60));
    }
}
