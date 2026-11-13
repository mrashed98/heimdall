//! Watchers: poll outside sources for new releases of what we run, record
//! them, and open MajorRelease and Eol findings.
//!
//! One run (`run_all`):
//! 1. builds the target list: images, charts and direct Go/npm libraries from
//!    the inventory, plus the targets configured under `watchers:`;
//! 2. fetches each target on its own (a failure is logged and counted, the
//!    rest go on) and stores releases newer than the version we run;
//! 3. opens and resolves findings in one transaction.
//!
//! Finding lifecycle (the matcher never touches these kinds):
//! - MajorRelease (`major_release|target|version`): at most one per target and
//!   major line, for the first release of the line. When one run finds several
//!   new lines (first sight of 16 -> 17, 18) only the highest alerts and the
//!   lower ones are marked done (`kv` `majorlines_done|<target>`). Resolves
//!   when the running version reaches that major, or when the target leaves
//!   the inventory. Go majors are separate modules (`/v2`), so the next one
//!   is probed as well.
//! - Eol (`eol|realm|target|cycle`): the realm runs a cycle whose end of
//!   support is within 60 days. Resolves when the realm stops running it.
//!
//! Both are High, so they are announced at once.

pub mod endoflife;
mod findings;
pub mod github;
pub mod go_proxy;
pub mod helm;
mod http;
pub mod npm;
pub mod oci;
mod plan;
pub mod tf_registry;

#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};

use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use sqlx::PgPool;
use url::Url;

use crate::config::{HeimdallConfig, TfKind};
use crate::inventory::store::{effective_components, EffectiveComponent};
use crate::version::{compare, is_major, is_prerelease, parse_tag};
use endoflife::Cycle;
use findings::update_findings;
use plan::plan;

/// Sent on every watcher request; GitHub rejects requests without one.
const UA: &str = "heimdall-watcher";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseInfo {
    pub version: String,
    pub published_at: Option<DateTime<Utc>>,
}

/// What one source call returned. `not_modified` means the ETag matched and
/// `releases` is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    pub releases: Vec<ReleaseInfo>,
    pub etag: Option<String>,
    pub not_modified: bool,
}

impl Fetched {
    fn not_modified(etag: Option<&str>) -> Fetched {
        Fetched {
            releases: Vec::new(),
            etag: etag.map(str::to_string),
            not_modified: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WatchKind {
    Github,
    Endoflife,
    Oci,
    Helm,
    TfRegistry,
    GoProxy,
    Npm,
}

impl WatchKind {
    /// The `watcher` label on the failure counter.
    pub fn label(self) -> &'static str {
        match self {
            WatchKind::Github => "github",
            WatchKind::Endoflife => "endoflife",
            WatchKind::Oci => "oci",
            WatchKind::Helm => "helm",
            WatchKind::TfRegistry => "tf_registry",
            WatchKind::GoProxy => "go_proxy",
            WatchKind::Npm => "npm",
        }
    }

    /// The ordering used to compare its versions.
    fn ecosystem(self) -> &'static str {
        match self {
            WatchKind::GoProxy => "Go",
            WatchKind::Npm => "npm",
            _ => "generic",
        }
    }
}

/// Something we watch for releases. `name` is the `releases.target` value:
/// the inventory name for configured targets (`kubernetes`), `host/repo` for
/// images, the name_key for charts and libraries, `registry/source` for
/// Terraform. `current` is the lowest version we run (None when nothing in
/// the inventory matches).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchTarget {
    pub name: String,
    pub kind: WatchKind,
    pub current: Option<String>,
    pub major_component: u8,
    /// GitHub `owner/repo` for release notes, when known.
    pub repo: Option<String>,
    pub name_key: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WatchReport {
    pub targets: usize,
    pub new_releases: usize,
    /// Findings inserted or re-opened; Gjallarhorn alerts on these.
    pub opened: Vec<i64>,
    pub resolved: usize,
    /// Failed targets per watcher.
    // TODO(Task 17): export as `heimdall_watcher_failures_total{watcher}`.
    pub failures: BTreeMap<String, u64>,
}

/// Base URLs of the outside services. Tests point them all at one mock.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub github: Url,
    pub endoflife: Url,
    pub npm: Url,
    pub go_proxy: Url,
    /// Replaces every OCI and Terraform registry host (tests only).
    pub registry_override: Option<Url>,
}

impl Default for Endpoints {
    fn default() -> Self {
        let url = |s: &str| Url::parse(s).expect("static url");
        Endpoints {
            github: url("https://api.github.com"),
            endoflife: url("https://endoflife.date"),
            npm: url("https://registry.npmjs.org"),
            go_proxy: url("https://proxy.golang.org"),
            registry_override: None,
        }
    }
}

/// Where a target's releases come from.
#[derive(Debug, Clone)]
enum Origin {
    Github {
        repo: String,
    },
    Endoflife {
        product: String,
    },
    Oci {
        host: String,
        repository: String,
    },
    Helm {
        repo_url: String,
        chart: String,
    },
    Tf {
        registry: String,
        kind: TfKind,
        source: String,
    },
    GoProxy {
        module: String,
    },
    Npm {
        name: String,
    },
}

/// A target with what this run needs to fetch it and file its findings.
#[derive(Debug, Clone)]
struct Planned {
    target: WatchTarget,
    origin: Origin,
    /// The realm a MajorRelease finding is filed in: where `current` runs.
    realm: Option<String>,
    /// False for an endoflife target whose releases a GitHub target of the
    /// same name already tracks (it is still checked for end of support).
    track_releases: bool,
}

/// One component a realm runs.
type Running = (String, EffectiveComponent);

pub async fn run_all(state: &crate::AppState, now: DateTime<Utc>) -> anyhow::Result<WatchReport> {
    run_with(
        &state.pool,
        &state.http,
        &state.cfg,
        &Endpoints::default(),
        now,
    )
    .await
}

/// `run_all` with explicit endpoints.
pub async fn run_with(
    pool: &PgPool,
    http: &Client,
    cfg: &HeimdallConfig,
    ep: &Endpoints,
    now: DateTime<Utc>,
) -> anyhow::Result<WatchReport> {
    let mut running: Vec<Running> = Vec::new();
    for realm in &cfg.realms {
        for c in effective_components(pool, realm).await? {
            running.push((realm.clone(), c));
        }
    }
    let planned = plan(cfg, &running);
    let mut report = WatchReport {
        targets: planned.len(),
        ..WatchReport::default()
    };

    // Cycles of each endoflife target that answered, for the Eol check.
    let mut cycles: HashMap<String, Vec<Cycle>> = HashMap::new();
    for p in &planned {
        match fetch_target(pool, http, cfg, ep, p, now).await {
            Ok((releases, fetched_cycles)) => {
                if p.track_releases {
                    report.new_releases += store_releases(pool, &p.target, &releases).await?;
                }
                if let Some(c) = fetched_cycles {
                    cycles.insert(p.target.name.clone(), c);
                }
            }
            Err(e) => {
                let label = p.target.kind.label();
                eprintln!("warning: watcher {label} {}: {e:#}", p.target.name);
                *report.failures.entry(label.to_string()).or_default() += 1;
            }
        }
    }

    let (opened, resolved) = update_findings(pool, cfg, &planned, &running, &cycles, now).await?;
    report.opened = opened;
    report.resolved = resolved;
    Ok(report)
}

// ---- fetching -------------------------------------------------------------

/// Fetch one target: its releases (kept only when newer than what we run and
/// not a pre-release) and, for endoflife, its cycles. Reads and updates the
/// target's `watcher_state`.
async fn fetch_target(
    pool: &PgPool,
    http: &Client,
    cfg: &HeimdallConfig,
    ep: &Endpoints,
    p: &Planned,
    now: DateTime<Utc>,
) -> anyhow::Result<(Vec<ReleaseInfo>, Option<Vec<Cycle>>)> {
    // A GitHub and an endoflife target may share a name, so the state key
    // carries the watcher too.
    let state_key = format!("{}:{}", p.target.kind.label(), p.target.name);
    let etag: Option<String> =
        sqlx::query_scalar("SELECT etag FROM watcher_state WHERE target = $1")
            .bind(&state_key)
            .fetch_optional(pool)
            .await?
            .flatten();
    let etag = etag.as_deref();

    let mut cycles = None;
    let fetched = match &p.origin {
        Origin::Github { repo } => {
            let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
            github::fetch(http, &ep.github, repo, token.as_deref(), etag).await?
        }
        Origin::Endoflife { product } => {
            let c = endoflife::fetch(http, &ep.endoflife, product).await?;
            let releases = c
                .iter()
                .filter_map(|c| {
                    Some(ReleaseInfo {
                        version: c.latest.clone()?,
                        published_at: c
                            .latest_date
                            .map(|d| d.and_time(Default::default()).and_utc()),
                    })
                })
                .collect();
            cycles = Some(c);
            Fetched {
                releases,
                etag: None,
                not_modified: false,
            }
        }
        Origin::Oci { host, repository } => {
            let base = registry_base(ep, host)?;
            let creds = cfg.registries.iter().find(|r| &r.host == host);
            oci::tags(http, &base, repository, creds, etag).await?
        }
        Origin::Helm { repo_url, chart } => match repo_url.strip_prefix("oci://") {
            Some(rest) => {
                let (host, path) = rest
                    .trim_end_matches('/')
                    .split_once('/')
                    .unwrap_or((rest, ""));
                let base = registry_base(ep, host)?;
                let creds = cfg.registries.iter().find(|r| r.host == host);
                let repository = if path.is_empty() {
                    chart.clone()
                } else {
                    format!("{path}/{chart}")
                };
                oci::tags(http, &base, &repository, creds, etag).await?
            }
            None => {
                let url =
                    Url::parse(repo_url).with_context(|| format!("bad chart repo {repo_url}"))?;
                helm::fetch_index(http, &url, chart, etag).await?
            }
        },
        Origin::Tf {
            registry,
            kind,
            source,
        } => tf_registry::fetch(http, &registry_base(ep, registry)?, *kind, source, etag).await?,
        Origin::GoProxy { module } => {
            let mut f = go_proxy::fetch(http, &ep.go_proxy, module, etag).await?;
            // Asked every run (no ETag): the next major is a separate module.
            f.releases
                .extend(go_proxy::fetch_next_major(http, &ep.go_proxy, module).await?);
            f
        }
        Origin::Npm { name } => npm::fetch(http, &ep.npm, name, etag).await?,
    };

    let releases = newer_releases(&p.target, fetched.releases);
    sqlx::query(
        "INSERT INTO watcher_state (target, etag, last_checked, last_seen) VALUES ($1, $2, $3, $4) \
         ON CONFLICT (target) DO UPDATE SET etag = EXCLUDED.etag, last_checked = EXCLUDED.last_checked, \
             last_seen = COALESCE(EXCLUDED.last_seen, watcher_state.last_seen)",
    )
    .bind(&state_key)
    .bind(&fetched.etag)
    .bind(now)
    .bind(newest(&p.target, &releases))
    .execute(pool)
    .await?;
    Ok((releases, cycles))
}

/// `https://{host}`; Docker Hub's API lives on `registry-1.docker.io`.
fn registry_base(ep: &Endpoints, host: &str) -> anyhow::Result<Url> {
    if let Some(u) = &ep.registry_override {
        return Ok(u.clone());
    }
    let host = if host == "docker.io" {
        "registry-1.docker.io"
    } else {
        host
    };
    Url::parse(&format!("https://{host}")).with_context(|| format!("bad registry host {host}"))
}

/// Normalise versions and keep the ones worth recording: newer than what we
/// run (everything, when we run nothing) and not pre-releases. GitHub tags
/// lose a leading `v` and a `{name}-` prefix (`kube-prometheus-stack-65.1.0`).
/// Images keep only tags with the running tag's suffix (`-alpine`), which also
/// rules out pre-release tags such as `18-rc1`.
fn newer_releases(t: &WatchTarget, releases: Vec<ReleaseInfo>) -> Vec<ReleaseInfo> {
    let mut out = Vec::new();
    for mut r in releases {
        if t.kind == WatchKind::Github {
            let v = r
                .version
                .strip_prefix(&format!("{}-", t.name))
                .unwrap_or(&r.version);
            r.version = v.strip_prefix('v').unwrap_or(v).to_string();
            if !r.version.starts_with(|c: char| c.is_ascii_digit()) {
                continue;
            }
        }
        let keep = if t.kind == WatchKind::Oci {
            let current = t.current.as_deref().and_then(parse_tag);
            match (parse_tag(&r.version), current) {
                (Some(tag), Some(cur)) => tag.suffix == cur.suffix && tag.version > cur.version,
                _ => false,
            }
        } else {
            !is_prerelease(&r.version)
                && t.current.as_deref().is_none_or(|cur| {
                    compare(t.kind.ecosystem(), &r.version, cur) == Some(Ordering::Greater)
                })
        };
        if keep {
            out.push(r);
        }
    }
    out
}

fn newest(t: &WatchTarget, releases: &[ReleaseInfo]) -> Option<String> {
    let mut best: Option<&str> = None;
    for r in releases {
        if best
            .is_none_or(|b| compare(t.kind.ecosystem(), &r.version, b) == Some(Ordering::Greater))
        {
            best = Some(&r.version);
        }
    }
    best.map(str::to_string)
}

/// Insert releases not seen before; returns how many were new.
async fn store_releases(
    pool: &PgPool,
    t: &WatchTarget,
    releases: &[ReleaseInfo],
) -> anyhow::Result<usize> {
    let mut new = 0;
    for r in releases {
        let major = t
            .current
            .as_deref()
            .is_some_and(|cur| is_major(cur, &r.version, t.major_component));
        let inserted = sqlx::query(
            "INSERT INTO releases (target, version, published_at, is_major) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (target, version) DO NOTHING",
        )
        .bind(&t.name)
        .bind(&r.version)
        .bind(r.published_at)
        .bind(major)
        .execute(pool)
        .await?
        .rows_affected();
        new += inserted as usize;
    }
    Ok(new)
}
