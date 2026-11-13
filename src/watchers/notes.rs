//! Release notes: for every stored release, find its notes (GitHub Releases
//! or Artifact Hub), classify them by pattern matching, and keep the class,
//! the mentioned CVE/GHSA ids and a short excerpt on the `releases` row.
//! Gjallarhorn reads those for the digest and the major-release cards.
//!
//! Notes that mention an id currently affecting us (an advisory id or alias of
//! an open Vuln finding) open a ReleaseNoteCve finding at once. It is one-shot
//! and never auto-resolved.
//!
//! A fetch failure is logged and leaves `notes_class` NULL, so the next run
//! retries it; "no notes found" stores class `none` with no URL.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::LazyLock;

use anyhow::Context;
use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::{Client, Response};
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use url::Url;

use super::findings::open_finding;
use super::http::{endpoint, get, is_not_found};
use super::{oci, registry_base, Endpoints, Origin, Planned};
use crate::config::HeimdallConfig;
use crate::matcher::key;
use crate::model::{FindingKind, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotesClass {
    CveAffecting,
    Security,
    Bugfix,
    Plain,
    None,
}

impl NotesClass {
    /// The `releases.notes_class` value.
    pub fn as_str(self) -> &'static str {
        match self {
            NotesClass::CveAffecting => "cve_affecting",
            NotesClass::Security => "security",
            NotesClass::Bugfix => "bugfix",
            NotesClass::Plain => "plain",
            NotesClass::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotesSource {
    GithubRepo(String),
    ArtifactHub { repo: String, chart: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notes {
    pub url: String,
    pub body: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    pub class: NotesClass,
    pub mentioned_ids: Vec<String>,
    pub fix_lines: Vec<String>,
    pub breaking_lines: Vec<String>,
}

/// An id that affects us (an advisory id or alias of an open Vuln finding).
#[derive(Debug, Clone)]
pub(super) struct AffectedId {
    severity: Severity,
    realm: String,
    services: BTreeSet<String>,
}

/// `owner/repo` of a GitHub URL in any of the shapes npm and OCI labels use:
/// `git+https://github.com/o/r.git`, `git@github.com:o/r.git`, `github:o/r`,
/// `https://github.com/o/r/tree/main/x`. Other hosts give None.
pub fn github_repo(url: &str) -> Option<String> {
    let url = url.trim();
    let path = match url.strip_prefix("github:") {
        Some(rest) => rest,
        None => {
            let at = url.find("github.com")?;
            // `notgithub.com` must not match: the host starts after `/` or `@`.
            if at > 0 && !url[..at].ends_with(['/', '@']) {
                return None;
            }
            url[at + "github.com".len()..].trim_start_matches([':', '/'])
        }
    };
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let owner = parts.next()?;
    let repo = parts.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    (!repo.is_empty()).then(|| format!("{owner}/{repo}"))
}

// ---- classification -------------------------------------------------------

/// `CVE-2026-1234` and `GHSA-xxxx-xxxx-xxxx` (GitHub's alphabet leaves out
/// vowels and look-alikes), either case.
static ID_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}").expect("id regex")
});
static SECURITY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(security|vulnerabilit(?:y|ies)|exploit\w*)\b").expect("security regex")
});

const MAX_LINES: usize = 5;

/// Which kind of heading the lines below belong to.
#[derive(Clone, Copy, PartialEq)]
enum Section {
    Fixes,
    Breaking,
    Other,
}

/// Classify release notes. `affecting_ids` holds the ids that affect us,
/// uppercased and including advisory aliases. An empty body has no notes.
pub fn classify(body: &str, affecting_ids: &HashSet<String>) -> Classified {
    let mut mentioned_ids: Vec<String> = Vec::new();
    for m in ID_RE.find_iter(body) {
        let id = m.as_str().to_uppercase();
        if !mentioned_ids.contains(&id) {
            mentioned_ids.push(id);
        }
    }

    let mut fix_lines = Vec::new();
    let mut breaking_lines = Vec::new();
    let mut section = Section::Other;
    for raw in body.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if is_heading(line) {
            let title = line.trim_matches(['#', '*', ':', ' ']).to_lowercase();
            section = if title.contains("breaking") {
                Section::Breaking
            } else if matches!(
                title.as_str(),
                "fixes" | "fixed" | "bug fixes" | "bug fix" | "bugfixes" | "bugfix"
            ) {
                Section::Fixes
            } else {
                Section::Other
            };
            continue;
        }
        let text = strip_bullet(line);
        let lower = text.to_lowercase();
        if section == Section::Fixes || lower.starts_with("fix") || lower.starts_with("bug") {
            fix_lines.push(text.to_string());
        }
        if section == Section::Breaking || lower.contains("breaking") {
            breaking_lines.push(text.to_string());
        }
    }
    let had_fix_lines = !fix_lines.is_empty();
    fix_lines.truncate(MAX_LINES);
    breaking_lines.truncate(MAX_LINES);

    let class = if body.trim().is_empty() {
        NotesClass::None
    } else if mentioned_ids.iter().any(|id| affecting_ids.contains(id)) {
        NotesClass::CveAffecting
    } else if !mentioned_ids.is_empty() || SECURITY_RE.is_match(body) {
        NotesClass::Security
    } else if had_fix_lines {
        NotesClass::Bugfix
    } else {
        NotesClass::Plain
    };
    Classified {
        class,
        mentioned_ids,
        fix_lines,
        breaking_lines,
    }
}

/// A markdown heading (`## Bug Fixes`) or a bold-only line (`**Bug Fixes**`).
fn is_heading(line: &str) -> bool {
    line.starts_with('#') || (line.len() > 4 && line.starts_with("**") && line.ends_with("**"))
}

/// `- text` and `* text` lose their bullet.
fn strip_bullet(line: &str) -> &str {
    for bullet in ["- ", "* "] {
        if let Some(rest) = line.strip_prefix(bullet) {
            return rest.trim();
        }
    }
    line
}

// ---- locating -------------------------------------------------------------

/// Where this target's release notes live, trying in order: the configured
/// repo (or GitHub watcher), the npm `repository.url`, a `github.com/` Go
/// module path, an image's `org.opencontainers.image.source` label, and
/// Artifact Hub for charts. Takes the whole `Planned` (not just the target)
/// because the origin holds the npm name, module path, image and chart repo.
pub(super) async fn locate(
    p: &Planned,
    http: &Client,
    ep: &Endpoints,
    cfg: &HeimdallConfig,
) -> anyhow::Result<Option<NotesSource>> {
    if let Some(repo) = &p.target.repo {
        return Ok(Some(NotesSource::GithubRepo(repo.clone())));
    }
    match &p.origin {
        Origin::Github { repo } => Ok(Some(NotesSource::GithubRepo(repo.clone()))),
        Origin::Npm { name } => {
            let url = endpoint(&ep.npm, &name.replace('/', "%2f"))?;
            let Some(resp) = get_or_404(http, &format!("npm {name}"), url, None).await? else {
                return Ok(None);
            };
            let doc: Packument = resp.json().await.context("npm packument")?;
            let url = match doc.repository {
                Some(Repository::Url(u)) => Some(u),
                Some(Repository::Object { url }) => url,
                None => None,
            };
            Ok(url
                .and_then(|u| github_repo(&u))
                .map(NotesSource::GithubRepo))
        }
        Origin::GoProxy { module } => Ok(module
            .strip_prefix("github.com/")
            .and_then(|rest| github_repo(&format!("github.com/{rest}")))
            .map(NotesSource::GithubRepo)),
        Origin::Oci { host, repository } => {
            // The tag we run is a version of the same image.
            let Some(tag) = &p.target.current else {
                return Ok(None);
            };
            let base = registry_base(ep, host)?;
            let creds = cfg.registries.iter().find(|r| &r.host == host);
            let label = oci::image_label(http, &base, repository, tag, SOURCE_LABEL, creds).await?;
            Ok(label
                .and_then(|l| github_repo(&l))
                .map(NotesSource::GithubRepo))
        }
        Origin::Helm { repo_url, chart } => artifact_hub_source(http, ep, repo_url, chart).await,
        Origin::Endoflife { .. } | Origin::Tf { .. } => Ok(None),
    }
}

/// The label an image's build sets to name its source repository.
const SOURCE_LABEL: &str = "org.opencontainers.image.source";

#[derive(Deserialize)]
struct Packument {
    repository: Option<Repository>,
}

/// npm accepts `"repository": "github:o/r"` as well as `{ "url": ... }`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Repository {
    Url(String),
    Object { url: Option<String> },
}

/// Artifact Hub names a chart `{repo}/{chart}` where `repo` is whatever the
/// publisher called it, which the chart URL only hints at. Try the likely
/// names and keep the first Artifact Hub knows.
async fn artifact_hub_source(
    http: &Client,
    ep: &Endpoints,
    repo_url: &str,
    chart: &str,
) -> anyhow::Result<Option<NotesSource>> {
    let mut candidates: Vec<String> = Vec::new();
    let trimmed = repo_url.trim_start_matches("oci://");
    let trimmed = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let mut parts = trimmed.trim_end_matches('/').split('/');
    if let Some(host) = parts.next() {
        // `prometheus-community.github.io` -> `prometheus-community`
        candidates.extend(host.split('.').next().map(str::to_string));
    }
    candidates.extend(parts.next_back().map(str::to_string));
    candidates.push(chart.to_string());

    let mut tried: HashSet<String> = HashSet::new();
    for repo in candidates {
        if repo.is_empty() || !tried.insert(repo.clone()) {
            continue;
        }
        let url = endpoint(
            &ep.artifacthub,
            &format!("api/v1/packages/helm/{repo}/{chart}"),
        )?;
        if get_or_404(http, &format!("artifacthub {repo}/{chart}"), url, None)
            .await?
            .is_some()
        {
            return Ok(Some(NotesSource::ArtifactHub {
                repo,
                chart: chart.to_string(),
            }));
        }
    }
    Ok(None)
}

/// GET where a 404 is an answer ("not there"), not a failure.
async fn get_or_404(
    http: &Client,
    what: &str,
    url: Url,
    bearer: Option<&str>,
) -> anyhow::Result<Option<Response>> {
    match get(http, what, url, None, bearer).await {
        Ok(resp) => Ok(resp),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---- fetching -------------------------------------------------------------

#[derive(Deserialize)]
struct GhRelease {
    body: Option<String>,
    html_url: Option<String>,
}

#[derive(Deserialize)]
struct HubPackage {
    #[serde(default)]
    changes: Vec<HubChange>,
}

#[derive(Deserialize)]
struct HubChange {
    kind: Option<String>,
    description: String,
}

/// The notes of one release, or None when the source has none. GitHub tags
/// are `v{version}` or plain `{version}`; both are tried, in that order.
pub(super) async fn fetch(
    source: &NotesSource,
    version: &str,
    http: &Client,
    ep: &Endpoints,
) -> anyhow::Result<Option<Notes>> {
    match source {
        NotesSource::GithubRepo(repo) => {
            let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
            for tag in [format!("v{version}"), version.to_string()] {
                let url = endpoint(&ep.github, &format!("repos/{repo}/releases/tags/{tag}"))?;
                let what = format!("github notes {repo}@{tag}");
                let Some(resp) = get_or_404(http, &what, url, token.as_deref()).await? else {
                    continue;
                };
                let rel: GhRelease = resp.json().await.with_context(|| format!("{what}: body"))?;
                let body = rel.body.unwrap_or_default();
                if body.trim().is_empty() {
                    return Ok(None);
                }
                let url = rel
                    .html_url
                    .unwrap_or_else(|| format!("https://github.com/{repo}/releases/tag/{tag}"));
                return Ok(Some(Notes { url, body }));
            }
            Ok(None)
        }
        NotesSource::ArtifactHub { repo, chart } => {
            let url = endpoint(
                &ep.artifacthub,
                &format!("api/v1/packages/helm/{repo}/{chart}/{version}"),
            )?;
            let what = format!("artifacthub {repo}/{chart}@{version}");
            let Some(resp) = get_or_404(http, &what, url, None).await? else {
                return Ok(None);
            };
            let pkg: HubPackage = resp.json().await.with_context(|| format!("{what}: body"))?;
            // One line per change, `fixed: ...`, so it reads like release notes.
            let body: String = pkg
                .changes
                .iter()
                .map(|c| match &c.kind {
                    Some(kind) => format!("{}: {}\n", kind.to_lowercase(), c.description),
                    None => format!("{}\n", c.description),
                })
                .collect();
            if body.trim().is_empty() {
                return Ok(None);
            }
            let url = format!("https://artifacthub.io/packages/helm/{repo}/{chart}/{version}");
            Ok(Some(Notes { url, body }))
        }
    }
}

// ---- the run --------------------------------------------------------------

/// Releases looked at per target per run. A first sight can store hundreds of
/// versions; the newest are the ones worth reading, and the rest are picked
/// up by later runs only if they are still NULL, which is fine: they are old.
const PER_TARGET_LIMIT: i64 = 20;

/// Fetch, classify and store notes for every release of the watched targets
/// that has none yet, and open ReleaseNoteCve findings. Returns the ids of
/// the findings it opened. A failure for one target or release is logged and
/// leaves its class NULL for the next run; only database errors propagate.
pub(super) async fn run(
    pool: &PgPool,
    http: &Client,
    cfg: &HeimdallConfig,
    ep: &Endpoints,
    planned: &[Planned],
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<i64>> {
    let affecting = affecting_ids(pool).await?;
    let ids: HashSet<String> = affecting.keys().cloned().collect();
    let mut opened = Vec::new();

    for p in planned.iter().filter(|p| p.track_releases) {
        let name = &p.target.name;
        let pending: Vec<String> = sqlx::query_scalar(
            "SELECT version FROM releases WHERE target = $1 AND notes_class IS NULL \
             ORDER BY id DESC LIMIT $2",
        )
        .bind(name)
        .bind(PER_TARGET_LIMIT)
        .fetch_all(pool)
        .await?;
        if pending.is_empty() {
            continue;
        }
        let source = match locate(p, http, ep, cfg).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("warning: release notes {name}: {e:#}");
                continue;
            }
        };
        for version in pending {
            let notes = match &source {
                Some(src) => match fetch(src, &version, http, ep).await {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("warning: release notes {name} {version}: {e:#}");
                        continue;
                    }
                },
                None => None,
            };
            let Some(notes) = notes else {
                store(pool, name, &version, None, &classify("", &ids)).await?;
                continue;
            };
            let c = classify(&notes.body, &ids);
            store(pool, name, &version, Some(&notes.url), &c).await?;
            if c.class != NotesClass::CveAffecting {
                continue;
            }
            for id in c.mentioned_ids.iter().filter(|id| ids.contains(*id)) {
                let Some(info) = affecting.get(id) else {
                    continue;
                };
                opened
                    .extend(open_note_cve(pool, name, &version, id, &notes.url, info, now).await?);
            }
        }
    }
    Ok(opened)
}

async fn store(
    pool: &PgPool,
    target: &str,
    version: &str,
    url: Option<&str>,
    c: &Classified,
) -> anyhow::Result<()> {
    let excerpt = json!({"fix": c.fix_lines, "breaking": c.breaking_lines});
    sqlx::query(
        "UPDATE releases SET notes_url = $3, notes_class = $4, mentioned_ids = $5, excerpt = $6 \
         WHERE target = $1 AND version = $2",
    )
    .bind(target)
    .bind(version)
    .bind(url)
    .bind(c.class.as_str())
    .bind(&c.mentioned_ids)
    .bind(excerpt)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
struct VulnRow {
    ref_id: String,
    aliases: Vec<String>,
    severity: Severity,
    realm: String,
    service: Option<String>,
}

/// Every advisory id and alias (uppercased) of an open Vuln finding, with the
/// advisory's severity and the realm and services running it.
async fn affecting_ids(pool: &PgPool) -> anyhow::Result<HashMap<String, AffectedId>> {
    let rows: Vec<VulnRow> = sqlx::query_as(
        "SELECT f.ref_id, a.aliases, a.severity, f.realm, s.name AS service \
         FROM findings f \
         JOIN advisories a ON a.id = f.ref_id \
         LEFT JOIN services s ON s.id = f.service_id \
         WHERE f.kind = 'vuln' AND f.status = 'open' \
         ORDER BY f.realm, s.name",
    )
    .fetch_all(pool)
    .await?;
    let mut out: HashMap<String, AffectedId> = HashMap::new();
    for row in rows {
        let VulnRow {
            ref_id,
            aliases,
            severity,
            realm,
            service,
        } = row;
        for id in std::iter::once(ref_id).chain(aliases) {
            let entry = out.entry(id.to_uppercase()).or_insert_with(|| AffectedId {
                severity,
                realm: realm.clone(),
                services: BTreeSet::new(),
            });
            // The same id can reach us through several advisories: the worst
            // severity wins; the realm stays the first (sorted) one.
            entry.severity = entry.severity.max(severity);
            entry.services.extend(service.clone());
        }
    }
    Ok(out)
}

/// Open the one-shot finding under the realm's matcher lock, like the other
/// watcher findings.
async fn open_note_cve(
    pool: &PgPool,
    target: &str,
    version: &str,
    id: &str,
    notes_url: &str,
    info: &AffectedId,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<i64>> {
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('matcher:' || $1))")
        .bind(&info.realm)
        .execute(&mut *tx)
        .await?;
    let details = json!({
        "notes_url": notes_url,
        "id": id,
        "services": info.services,
        "target": target,
        "version": version,
    });
    let k = key(FindingKind::ReleaseNoteCve, &[target, version, id]);
    let opened = open_finding(
        &mut tx,
        &k,
        FindingKind::ReleaseNoteCve,
        &info.realm,
        id,
        info.severity,
        &details,
        now,
    )
    .await?;
    tx.commit().await?;
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
    use crate::model::Source;
    use crate::watchers::{Origin, WatchKind, WatchTarget};

    fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/notes/{name}")).unwrap()
    }

    /// The `body` of a GitHub release fixture.
    fn body_of(name: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(&fixture(name)).unwrap();
        v["body"].as_str().unwrap().to_string()
    }

    fn ids(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn endpoints(server: &MockServer) -> Endpoints {
        let b = Url::parse(&server.uri()).unwrap();
        Endpoints {
            github: b.clone(),
            endoflife: b.clone(),
            npm: b.clone(),
            go_proxy: b.clone(),
            artifacthub: b.clone(),
            registry_override: Some(b),
        }
    }

    fn cfg() -> HeimdallConfig {
        serde_yaml::from_str("realms: [prod]").unwrap()
    }

    fn planned(name: &str, kind: WatchKind, origin: Origin) -> Planned {
        Planned {
            target: WatchTarget {
                name: name.to_string(),
                kind,
                current: Some("1.0.0".to_string()),
                major_component: 0,
                repo: None,
                name_key: None,
            },
            origin,
            realm: Some("prod".to_string()),
            track_releases: true,
        }
    }

    fn gh_planned(name: &str) -> Planned {
        planned(
            name,
            WatchKind::Github,
            Origin::Github {
                repo: "acme/widget".to_string(),
            },
        )
    }

    async fn add_release(pool: &PgPool, target: &str, version: &str) {
        sqlx::query("INSERT INTO releases (target, version) VALUES ($1, $2)")
            .bind(target)
            .bind(version)
            .execute(pool)
            .await
            .unwrap();
    }

    fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap()
    }

    // ---- classify ---------------------------------------------------------

    #[test]
    fn classify_cve_affecting() {
        let c = classify("Fixes CVE-2026-1234", &ids(&["CVE-2026-1234"]));
        assert_eq!(c.class, NotesClass::CveAffecting);
        assert_eq!(c.mentioned_ids, vec!["CVE-2026-1234"]);
    }

    #[test]
    fn classify_ghsa_lowercase_normalised() {
        let c = classify(
            "see ghsa-c2c2-f3f3-g4g4 and cve-2026-1234, again GHSA-C2C2-F3F3-G4G4",
            &ids(&["GHSA-C2C2-F3F3-G4G4"]),
        );
        assert_eq!(c.class, NotesClass::CveAffecting);
        // Uppercased, deduplicated, in order of appearance.
        assert_eq!(
            c.mentioned_ids,
            vec!["GHSA-C2C2-F3F3-G4G4", "CVE-2026-1234"]
        );
    }

    #[test]
    fn classify_security_not_affecting() {
        let c = classify("Fixes CVE-2026-9999", &ids(&["CVE-2026-1234"]));
        assert_eq!(c.class, NotesClass::Security);
        assert_eq!(c.mentioned_ids, vec!["CVE-2026-9999"]);
        let words = classify("Hardened the parser against exploit attempts", &ids(&[]));
        assert_eq!(words.class, NotesClass::Security);
    }

    #[test]
    fn classify_bugfix_lines_capped_at_5() {
        let body: String = (1..=8).map(|i| format!("- fix: thing {i}\n")).collect();
        let c = classify(&body, &ids(&[]));
        assert_eq!(c.class, NotesClass::Bugfix);
        assert_eq!(c.fix_lines.len(), 5);
        assert_eq!(c.fix_lines[0], "fix: thing 1");

        let c = classify(&body_of("gh_release_bugfix.json"), &ids(&[]));
        assert_eq!(c.class, NotesClass::Bugfix);
        assert_eq!(
            c.fix_lines,
            vec!["Correct off-by-one in pager", "Handle empty config file"]
        );
    }

    #[test]
    fn breaking_lines_extracted() {
        let c = classify(&body_of("gh_release_breaking.json"), &ids(&[]));
        assert_eq!(
            c.breaking_lines,
            vec![
                "The `--legacy` flag is removed",
                "Config key `port` is now `listen.port`",
                "BREAKING: minimum Go version is 1.22",
            ]
        );
        assert_eq!(c.class, NotesClass::Plain);
    }

    #[test]
    fn classify_plain_and_empty() {
        assert_eq!(
            classify("- New plugin API", &ids(&[])).class,
            NotesClass::Plain
        );
        assert_eq!(classify("  \n", &ids(&[])).class, NotesClass::None);
    }

    #[test]
    fn github_repo_from_urls() {
        for url in [
            "git+https://github.com/vuejs/core.git",
            "https://github.com/vuejs/core",
            "git://github.com/vuejs/core.git",
            "git@github.com:vuejs/core.git",
            "github:vuejs/core",
            "https://github.com/vuejs/core/tree/main/packages/vue",
        ] {
            assert_eq!(github_repo(url).as_deref(), Some("vuejs/core"), "{url}");
        }
        assert_eq!(github_repo("https://gitlab.com/vuejs/core"), None);
        assert_eq!(github_repo("https://notgithub.com/a/b"), None);
    }

    // ---- locate and fetch -------------------------------------------------

    #[tokio::test]
    async fn locate_npm_repository_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vue"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture("npm_pkg_repo.json")))
            .mount(&server)
            .await;
        let p = planned(
            "pkg:npm/vue",
            WatchKind::Npm,
            Origin::Npm {
                name: "vue".to_string(),
            },
        );
        let got = locate(&p, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(got, Some(NotesSource::GithubRepo("vuejs/core".to_string())));
    }

    #[tokio::test]
    async fn locate_go_module_and_configured_repo() {
        let server = MockServer::start().await;
        let go = planned(
            "pkg:golang/github.com/gin-gonic/gin",
            WatchKind::GoProxy,
            Origin::GoProxy {
                module: "github.com/gin-gonic/gin/v2".to_string(),
            },
        );
        let got = locate(&go, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::GithubRepo("gin-gonic/gin".to_string()))
        );

        // A configured repo wins over anything derived.
        let mut kube = planned(
            "kubernetes",
            WatchKind::Endoflife,
            Origin::Endoflife {
                product: "kubernetes".to_string(),
            },
        );
        kube.target.repo = Some("kubernetes/kubernetes".to_string());
        let got = locate(&kube, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::GithubRepo("kubernetes/kubernetes".to_string()))
        );
    }

    #[tokio::test]
    async fn locate_oci_source_label_through_config_blob() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/acme/widget/manifests/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": {"digest": "sha256:abc"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/acme/widget/blobs/sha256:abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": {"Labels": {
                    "org.opencontainers.image.source": "https://github.com/acme/widget"
                }}
            })))
            .mount(&server)
            .await;
        let p = planned(
            "ghcr.io/acme/widget",
            WatchKind::Oci,
            Origin::Oci {
                host: "ghcr.io".to_string(),
                repository: "acme/widget".to_string(),
            },
        );
        let got = locate(&p, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::GithubRepo("acme/widget".to_string()))
        );
    }

    #[tokio::test]
    async fn artifact_hub_chart_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/packages/helm/prometheus-community/kube-prometheus-stack",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/packages/helm/prometheus-community/kube-prometheus-stack/65.1.0",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(fixture("artifacthub_chart.json")),
            )
            .mount(&server)
            .await;
        let p = planned(
            "pkg:helm/kube-prometheus-stack",
            WatchKind::Helm,
            Origin::Helm {
                repo_url: "https://prometheus-community.github.io/helm-charts".to_string(),
                chart: "kube-prometheus-stack".to_string(),
            },
        );
        let ep = endpoints(&server);
        let source = locate(&p, &Client::new(), &ep, &cfg())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            source,
            NotesSource::ArtifactHub {
                repo: "prometheus-community".to_string(),
                chart: "kube-prometheus-stack".to_string()
            }
        );
        let notes = fetch(&source, "65.1.0", &Client::new(), &ep)
            .await
            .unwrap()
            .unwrap();
        assert!(notes.body.contains("fixed: Alertmanager config reload"));
        let c = classify(&notes.body, &ids(&["CVE-2026-1234"]));
        assert_eq!(c.class, NotesClass::CveAffecting);
    }

    #[tokio::test]
    async fn fetch_tries_v_prefix_then_plain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/v1.2.3"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/1.2.3"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(fixture("gh_release_security.json")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let source = NotesSource::GithubRepo("acme/widget".to_string());
        let notes = fetch(&source, "1.2.3", &Client::new(), &endpoints(&server))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            notes.url,
            "https://github.com/acme/widget/releases/tag/v1.2.3"
        );
        assert!(notes.body.contains("CVE-2026-1234"));
    }

    #[tokio::test]
    async fn fetch_missing_release_is_none() {
        let server = MockServer::start().await;
        let source = NotesSource::GithubRepo("acme/widget".to_string());
        // Unmocked paths answer 404 on both tags.
        let got = fetch(&source, "9.9.9", &Client::new(), &endpoints(&server))
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    // ---- run (database) ---------------------------------------------------

    #[sqlx::test(migrations = "./migrations")]
    async fn no_notes_class_none(pool: PgPool) {
        let server = MockServer::start().await;
        // An npm package whose packument names no repository.
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"versions": {}})))
            .mount(&server)
            .await;
        add_release(&pool, "pkg:npm/left-pad", "1.1.0").await;
        let p = planned(
            "pkg:npm/left-pad",
            WatchKind::Npm,
            Origin::Npm {
                name: "left-pad".to_string(),
            },
        );
        let opened = run(
            &pool,
            &Client::new(),
            &cfg(),
            &endpoints(&server),
            &[p],
            now(),
        )
        .await
        .unwrap();
        assert!(opened.is_empty());
        let (class, url): (Option<String>, Option<String>) =
            sqlx::query_as("SELECT notes_class, notes_url FROM releases WHERE version = '1.1.0'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(class.as_deref(), Some("none"));
        assert_eq!(url, None);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn failed_fetch_leaves_class_null_for_retry(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        add_release(&pool, "widget", "1.2.3").await;
        let opened = run(
            &pool,
            &Client::new(),
            &cfg(),
            &endpoints(&server),
            &[gh_planned("widget")],
            now(),
        )
        .await
        .unwrap();
        assert!(opened.is_empty());
        let class: Option<String> =
            sqlx::query_scalar("SELECT notes_class FROM releases WHERE version = '1.2.3'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(class, None);
    }

    /// One open Vuln finding for advisory GHSA-gin-0001 (alias CVE-2026-1234).
    async fn seed_vuln(pool: &PgPool) {
        let svc = upsert_service(pool, "prod", "api").await.unwrap();
        let item = InventoryItem {
            purl: "pkg:golang/github.com/gin-gonic/gin@1.9.0".to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        };
        replace_components(pool, svc, Source::Git, &[item])
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO advisories (id, aliases, severity, summary, source) \
             VALUES ('GHSA-gin-0001', ARRAY['CVE-2026-1234'], 'critical', 's', 'osv')",
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO component_advisories (component_id, advisory_id, match_source) \
             SELECT id, 'GHSA-gin-0001', 'osv' FROM components",
        )
        .execute(pool)
        .await
        .unwrap();
        crate::matcher::run(pool, "prod", now()).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn release_note_cve_finding_opened_once(pool: PgPool) {
        seed_vuln(&pool).await;
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/v1.2.3"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(fixture("gh_release_security.json")),
            )
            .mount(&server)
            .await;
        add_release(&pool, "widget", "1.2.3").await;
        let p = gh_planned("widget");
        let go = || async {
            run(
                &pool,
                &Client::new(),
                &cfg(),
                &endpoints(&server),
                std::slice::from_ref(&p),
                now(),
            )
            .await
            .unwrap()
        };

        let opened = go().await;
        assert_eq!(opened.len(), 1);
        let (key, severity, realm, details): (String, String, String, serde_json::Value) =
            sqlx::query_as(
                "SELECT key, severity, realm, details FROM findings WHERE kind = 'releasenotecve'",
            )
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(key, "relnote|widget|1.2.3|CVE-2026-1234");
        assert_eq!(severity, "critical");
        assert_eq!(realm, "prod");
        assert_eq!(details["id"], "CVE-2026-1234");
        assert_eq!(details["services"], json!(["api"]));
        assert_eq!(details["target"], "widget");
        assert_eq!(details["version"], "1.2.3");
        assert_eq!(
            details["notes_url"],
            "https://github.com/acme/widget/releases/tag/v1.2.3"
        );

        let (class, ids, excerpt): (String, Vec<String>, serde_json::Value) = sqlx::query_as(
            "SELECT notes_class, mentioned_ids, excerpt FROM releases WHERE version = '1.2.3'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(class, "cve_affecting");
        assert_eq!(ids, vec!["CVE-2026-1234", "GHSA-C2C2-F3F3-G4G4"]);
        assert!(excerpt["fix"].is_array() && excerpt["breaking"].is_array());

        // Classified again (class reset): the finding is not re-announced.
        sqlx::query("UPDATE releases SET notes_class = NULL")
            .execute(&pool)
            .await
            .unwrap();
        assert!(go().await.is_empty());
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM findings WHERE kind = 'releasenotecve'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 1);
    }
}
