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
//! - MajorRelease (`major_release|target|version`): one per target and major
//!   line, for the first release of the line. Resolves when the running
//!   version reaches that major, or when the target leaves the inventory.
//! - Eol (`eol|realm|target|cycle`): the realm runs a cycle whose end of
//!   support is within 60 days. Resolves when the realm stops running it.
//!
//! Both are High, so they are announced at once.

pub mod endoflife;
pub mod github;
pub mod go_proxy;
pub mod helm;
pub mod npm;
pub mod oci;
pub mod tf_registry;

#[cfg(test)]
mod tests;

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use packageurl::PackageUrl;
use reqwest::header::{ETAG, IF_NONE_MATCH, USER_AGENT};
use reqwest::{Client, Response, StatusCode};
use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use url::Url;

use crate::config::{HeimdallConfig, TfKind};
use crate::inventory::store::{effective_components, EffectiveComponent};
use crate::matcher::key;
use crate::model::{FindingKind, Severity};
use crate::version::{compare, is_major, is_prerelease, major_line, parse_tag};
use crate::vuln::retry;
use endoflife::Cycle;

/// Sent on every watcher request; GitHub rejects requests without one.
const UA: &str = "heimdall-watcher";

/// End of support this close (or already past) opens an Eol finding.
const EOL_WINDOW_DAYS: i64 = 60;

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

// ---- target list ----------------------------------------------------------

/// Inventory-derived targets (merged across realms, keeping the lowest
/// running version) followed by the configured ones.
fn plan(cfg: &HeimdallConfig, running: &[Running]) -> Vec<Planned> {
    let mut derived: BTreeMap<String, Planned> = BTreeMap::new();
    for (realm, c) in running {
        let Some(p) = inventory_target(cfg, realm, c) else {
            continue;
        };
        match derived.get_mut(&p.target.name) {
            Some(existing) if !is_lower(&p, existing) => {}
            Some(existing) => *existing = p,
            None => {
                derived.insert(p.target.name.clone(), p);
            }
        }
    }
    let mut out: Vec<Planned> = derived.into_values().collect();

    for g in &cfg.watchers.github {
        let (current, realm) = lowest_generic(running, &g.inventory_name);
        out.push(Planned {
            target: WatchTarget {
                name: g.inventory_name.clone(),
                kind: WatchKind::Github,
                current,
                major_component: g.major_component,
                repo: Some(g.repo.clone()),
                name_key: Some(generic_key(&g.inventory_name)),
            },
            origin: Origin::Github {
                repo: g.repo.clone(),
            },
            realm,
            track_releases: true,
        });
    }
    for e in &cfg.watchers.endoflife {
        let (current, realm) = lowest_generic(running, &e.inventory_name);
        let shadowed = cfg
            .watchers
            .github
            .iter()
            .any(|g| g.inventory_name == e.inventory_name);
        out.push(Planned {
            target: WatchTarget {
                name: e.inventory_name.clone(),
                kind: WatchKind::Endoflife,
                current,
                major_component: e.major_component,
                repo: e.repo.clone(),
                name_key: Some(generic_key(&e.inventory_name)),
            },
            origin: Origin::Endoflife {
                product: e.product.clone(),
            },
            realm,
            track_releases: !shadowed,
        });
    }
    for t in &cfg.watchers.tf_registry {
        out.push(Planned {
            target: WatchTarget {
                name: format!("{}/{}", t.registry, t.source),
                kind: WatchKind::TfRegistry,
                current: Some(t.current.clone()),
                major_component: 0,
                repo: None,
                name_key: None,
            },
            origin: Origin::Tf {
                registry: t.registry.clone(),
                kind: t.kind,
                source: t.source.clone(),
            },
            // Configured with no realm: filed under the first realm.
            realm: cfg.realms.first().cloned(),
            track_releases: true,
        });
    }
    out
}

fn generic_key(inventory_name: &str) -> String {
    format!("pkg:generic/{inventory_name}")
}

/// The target a running component stands for, if it is watched: images not
/// from our own registries, charts, and direct Go/npm libraries.
fn inventory_target(cfg: &HeimdallConfig, realm: &str, c: &EffectiveComponent) -> Option<Planned> {
    let purl = PackageUrl::from_str(&c.purl).ok()?;
    // The parser percent-decodes qualifier values and the namespace.
    let qualifier = |k: &str| purl.qualifiers().get(k).map(|v| v.to_string());
    let joined = || match purl.namespace() {
        Some(ns) => format!("{ns}/{}", purl.name()),
        None => purl.name().to_string(),
    };
    let (kind, name, current, origin) = match purl.ty() {
        "oci" => {
            let (host, repository) = image_ref(&qualifier("repository_url")?)?;
            let name = format!("{host}/{repository}");
            if is_own(cfg, &name) {
                return None;
            }
            // Only tags we can read as a version can be compared.
            let tag = qualifier("tag").filter(|t| parse_tag(t).is_some())?;
            (WatchKind::Oci, name, tag, Origin::Oci { host, repository })
        }
        "helm" => {
            let origin = Origin::Helm {
                repo_url: qualifier("repository_url")?,
                chart: purl.name().to_string(),
            };
            (
                WatchKind::Helm,
                c.name_key.clone(),
                purl.version()?.to_string(),
                origin,
            )
        }
        "golang" if c.direct => {
            let origin = Origin::GoProxy { module: joined() };
            (
                WatchKind::GoProxy,
                c.name_key.clone(),
                purl.version()?.to_string(),
                origin,
            )
        }
        "npm" if c.direct => {
            let origin = Origin::Npm { name: joined() };
            (
                WatchKind::Npm,
                c.name_key.clone(),
                purl.version()?.to_string(),
                origin,
            )
        }
        _ => return None,
    };
    Some(Planned {
        target: WatchTarget {
            name,
            kind,
            current: Some(current),
            major_component: 0,
            repo: None,
            name_key: Some(c.name_key.clone()),
        },
        origin,
        realm: Some(realm.to_string()),
        track_releases: true,
    })
}

/// `(host, repository)` of an image reference, Docker Hub short names
/// expanded: `postgres` -> `("docker.io", "library/postgres")`.
fn image_ref(reference: &str) -> Option<(String, String)> {
    let r = reference.trim().trim_start_matches("oci://");
    let r = r.split('@').next()?;
    let (host, rest) = match r.split_once('/') {
        Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => (first, rest),
        _ => ("docker.io", r),
    };
    let host = match host {
        "index.docker.io" | "registry-1.docker.io" => "docker.io",
        h => h,
    };
    // Drop a `:tag` on the last segment (a `:` before a `/` is a port).
    let mut repository = match rest.rsplit_once(':') {
        Some((before, after)) if !after.contains('/') => before.to_string(),
        _ => rest.to_string(),
    };
    if host == "docker.io" && !repository.contains('/') {
        repository = format!("library/{repository}");
    }
    (!repository.is_empty()).then(|| (host.to_string(), repository))
}

/// True when `image` (`host/repo`) is under one of `own_registries`, given
/// as a host or a host/org prefix.
fn is_own(cfg: &HeimdallConfig, image: &str) -> bool {
    cfg.own_registries.iter().any(|own| {
        let own = own.trim_end_matches('/');
        image == own || image.starts_with(&format!("{own}/"))
    })
}

/// True when `a` runs an older version than `b` (same target).
fn is_lower(a: &Planned, b: &Planned) -> bool {
    match (&a.target.current, &b.target.current) {
        (Some(x), Some(y)) => compare(a.target.kind.ecosystem(), x, y) == Some(Ordering::Less),
        _ => false,
    }
}

/// The lowest version of `pkg:generic/{inventory_name}` running in any realm,
/// and that realm.
fn lowest_generic(running: &[Running], inventory_name: &str) -> (Option<String>, Option<String>) {
    let key = generic_key(inventory_name);
    let mut best: Option<(String, String)> = None;
    for (realm, c) in running.iter().filter(|(_, c)| c.name_key == key) {
        let Some(v) = purl_version(&c.purl) else {
            continue;
        };
        let lower = best
            .as_ref()
            .is_none_or(|(b, _)| compare("generic", &v, b) == Some(Ordering::Less));
        if lower {
            best = Some((v, realm.clone()));
        }
    }
    match best {
        Some((v, r)) => (Some(v), Some(r)),
        None => (None, None),
    }
}

fn purl_version(purl: &str) -> Option<String> {
    Some(PackageUrl::from_str(purl).ok()?.version()?.to_string())
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
        Origin::GoProxy { module } => go_proxy::fetch(http, &ep.go_proxy, module, etag).await?,
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

// ---- findings -------------------------------------------------------------

/// Open and resolve MajorRelease and Eol findings in one transaction, holding
/// every realm's matcher lock so no matcher run interleaves.
async fn update_findings(
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
    let done: HashSet<String> = sqlx::query_scalar::<_, Option<String>>(
        "SELECT details->>'line' FROM findings WHERE kind = 'majorrelease' AND details->>'target' = $1",
    )
    .bind(&t.name)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .flatten()
    .collect();
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

    let mut opened = Vec::new();
    for (line, version) in lines {
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
                open_finding(tx, &k, FindingKind::Eol, realm, &cycle.cycle, &details, now).await?,
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

/// Insert a High finding, or re-open a resolved one with the same key.
/// Returns its id when it is a new occurrence (None when already open).
async fn open_finding(
    tx: &mut PgConnection,
    k: &str,
    kind: FindingKind,
    realm: &str,
    ref_id: &str,
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
    .bind(Severity::High)
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

// ---- HTTP helpers shared by the sources -----------------------------------

/// `base` plus `path`, keeping any path `base` already has (a chart repo URL
/// such as `https://x/charts` must not lose `charts`, as `Url::join` would).
fn endpoint(base: &Url, path: &str) -> anyhow::Result<Url> {
    let s = format!("{}/{}", base.as_str().trim_end_matches('/'), path);
    Url::parse(&s).with_context(|| format!("bad url {s}"))
}

/// GET through the shared retry helper, with `If-None-Match` when we hold an
/// ETag and a Bearer token when given. `Ok(None)` means 304 Not Modified.
async fn get(
    http: &Client,
    what: &str,
    url: Url,
    etag: Option<&str>,
    bearer: Option<&str>,
) -> anyhow::Result<Option<Response>> {
    let resp = retry::send(what, || {
        let mut req = http.get(url.clone()).header(USER_AGENT, UA);
        if let Some(e) = etag {
            req = req.header(IF_NONE_MATCH, e);
        }
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        req
    })
    .await?;
    if resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    Ok(Some(resp))
}

fn etag_of(resp: &Response) -> Option<String> {
    resp.headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}
