//! Release notes: for every stored release, find its notes (GitHub Releases
//! or Artifact Hub), classify them by pattern matching, and keep the class,
//! the mentioned CVE/GHSA ids and a short excerpt on the `releases` row.
//! Gjallarhorn reads those for the digest and the major-release cards.
//!
//! Notes that mention an id currently affecting us (an advisory id or alias of
//! an open Vuln finding) open one ReleaseNoteCve finding per advisory at once.
//! It is one-shot and never auto-resolved.
//!
//! A fetch failure is logged and leaves `notes_class` NULL, so the next run
//! retries it, up to `MAX_ATTEMPTS` runs, after which the class is `none`.
//! "No notes found" stores class `none` with no URL.
//!
//! - `classify`: the pure pattern matching.
//! - `source`: where the notes are and how to fetch them.
//! - this file: the run, and writing results and findings.

mod classify;
mod source;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::json;
use sqlx::{PgConnection, PgPool};

use super::findings::open_finding;
use super::http::is_rate_limited;
use super::{Endpoints, Planned};
use crate::config::HeimdallConfig;
use crate::matcher::key;
use crate::model::{FindingKind, Severity};
use classify::{classify, Classified, NotesClass};
use source::{fetch, locate, NotesSource};

/// Releases looked at per target per run: the newest by publish time. A first
/// sight can store hundreds of versions; the rest follow on later runs, since
/// they still have no class.
const PER_TARGET_LIMIT: i64 = 20;

/// Failed runs after which a release's notes are given up on (class `none`).
const MAX_ATTEMPTS: i32 = 5;

/// An id that affects us (an advisory id or alias of an open Vuln finding).
#[derive(Debug, Clone)]
struct AffectedId {
    advisory_id: String,
    severity: Severity,
    realm: String,
    services: BTreeSet<String>,
}

/// One affecting advisory that some release notes mention, under whichever
/// ids (CVE, GHSA) the notes used for it.
struct Hit<'a> {
    info: &'a AffectedId,
    mentioned: Vec<&'a str>,
}

/// Fetch, classify and store notes for every release of the watched targets
/// that has none yet, and open ReleaseNoteCve findings. Returns the ids of
/// the findings it opened. A failure for one target or release is logged and
/// counted against it; only database errors propagate. A 403 or 429 from GitHub
/// ends the whole run (the rate limit is shared by every GitHub target).
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

    'targets: for p in planned.iter().filter(|p| p.track_releases) {
        let name = &p.target.name;
        let pending: Vec<String> = sqlx::query_scalar(
            "SELECT version FROM releases WHERE target = $1 AND notes_class IS NULL \
             ORDER BY published_at DESC NULLS LAST, id DESC LIMIT $2",
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
                // Locating asks npm, a registry or Artifact Hub, never GitHub:
                // a 403 here is this target's problem, not a rate limit.
                tracing::warn!("release notes {name}: {e:#}");
                record_failure(pool, name, &pending).await?;
                continue 'targets;
            }
        };
        for version in &pending {
            let notes = match &source {
                Some(src) => match fetch(src, version, http, ep).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::warn!("release notes {name} {version}: {e:#}");
                        // Not a 404: count it, and leave the rest of this
                        // target for the next run.
                        record_failure(pool, name, std::slice::from_ref(version)).await?;
                        // GitHub's rate limit is shared by every GitHub
                        // target, so asking more only makes it worse. Any
                        // other source's 403 is just that target failing.
                        if matches!(src, NotesSource::GithubRepo(_)) && is_rate_limited(&e) {
                            break 'targets;
                        }
                        continue 'targets;
                    }
                },
                None => None,
            };
            let Some(notes) = notes else {
                let none = classify("", &ids);
                save(pool, name, version, None, &none, &[], now).await?;
                continue;
            };
            let c = classify(&notes.body, &ids);
            let hits = if c.class == NotesClass::CveAffecting {
                hits(&c, &affecting)
            } else {
                Vec::new()
            };
            opened.extend(save(pool, name, version, Some(&notes.url), &c, &hits, now).await?);
        }
    }
    Ok(opened)
}

/// The affecting advisories `c` mentions, one entry per advisory.
fn hits<'a>(c: &'a Classified, affecting: &'a HashMap<String, AffectedId>) -> Vec<Hit<'a>> {
    let mut by_advisory: BTreeMap<&str, Hit> = BTreeMap::new();
    for id in &c.mentioned_ids {
        let Some(info) = affecting.get(id) else {
            continue;
        };
        by_advisory
            .entry(info.advisory_id.as_str())
            .or_insert_with(|| Hit {
                info,
                mentioned: Vec::new(),
            })
            .mentioned
            .push(id.as_str());
    }
    by_advisory.into_values().collect()
}

/// Count one failed run against these releases; at `MAX_ATTEMPTS` the class
/// becomes `none` so they are not tried forever.
async fn record_failure(pool: &PgPool, target: &str, versions: &[String]) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE releases SET notes_attempts = notes_attempts + 1, \
             notes_class = CASE WHEN notes_attempts + 1 >= $3 THEN 'none' ELSE NULL END \
         WHERE target = $1 AND version = ANY($2) AND notes_class IS NULL",
    )
    .bind(target)
    .bind(versions)
    .bind(MAX_ATTEMPTS)
    .execute(pool)
    .await?;
    Ok(())
}

/// Store the classification and open the findings in one transaction, so a
/// failure cannot leave the release marked `cve_affecting` with no finding
/// (the alert would be lost: the release would never be looked at again).
/// The realm matcher locks are taken first, in sorted order like the other
/// watcher findings.
async fn save(
    pool: &PgPool,
    target: &str,
    version: &str,
    url: Option<&str>,
    c: &Classified,
    hits: &[Hit<'_>],
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<i64>> {
    let mut tx = pool.begin().await?;
    let realms: BTreeSet<&str> = hits.iter().map(|h| h.info.realm.as_str()).collect();
    for realm in realms {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext('matcher:' || $1))")
            .bind(realm)
            .execute(&mut *tx)
            .await?;
    }
    store(&mut tx, target, version, url, c).await?;
    let mut opened = Vec::new();
    for hit in hits {
        opened.extend(open_note_cve(&mut tx, target, version, url, hit, now).await?);
    }
    tx.commit().await?;
    Ok(opened)
}

async fn store(
    tx: &mut PgConnection,
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
    .execute(&mut *tx)
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
/// advisory, its severity and the realm and services running it.
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
        for id in std::iter::once(ref_id.clone()).chain(aliases) {
            let entry = out.entry(id.to_uppercase()).or_insert_with(|| AffectedId {
                advisory_id: ref_id.clone(),
                severity,
                realm: realm.clone(),
                services: BTreeSet::new(),
            });
            // The same id can reach us through several findings: the worst
            // severity wins; the realm stays the first (sorted) one.
            entry.severity = entry.severity.max(severity);
            entry.services.extend(service.clone());
        }
    }
    Ok(out)
}

/// The one-shot finding for an advisory the notes mention, keyed by the
/// advisory so a CVE and its GHSA in the same notes give one alert.
async fn open_note_cve(
    tx: &mut PgConnection,
    target: &str,
    version: &str,
    notes_url: Option<&str>,
    hit: &Hit<'_>,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<i64>> {
    let advisory = hit.info.advisory_id.as_str();
    let details = json!({
        "notes_url": notes_url,
        "id": hit.mentioned.first(),
        "ids": hit.mentioned,
        "advisory": advisory,
        "services": hit.info.services,
        "target": target,
        "version": version,
    });
    let k = key(FindingKind::ReleaseNoteCve, &[target, version, advisory]);
    open_finding(
        tx,
        &k,
        FindingKind::ReleaseNoteCve,
        &hit.info.realm,
        advisory,
        hit.info.severity,
        &details,
        now,
    )
    .await
}

#[cfg(test)]
mod testutil {
    //! Helpers shared by the tests of `notes` and its children.

    use std::collections::HashSet;

    use chrono::{TimeZone, Utc};
    use sqlx::PgPool;
    use url::Url;
    use wiremock::MockServer;

    use crate::config::HeimdallConfig;
    use crate::watchers::{Endpoints, Origin, Planned, WatchKind, WatchTarget};

    pub(super) fn fixture(name: &str) -> String {
        std::fs::read_to_string(format!("tests/fixtures/notes/{name}")).unwrap()
    }

    pub(super) fn ids(list: &[&str]) -> HashSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    pub(super) fn endpoints(server: &MockServer) -> Endpoints {
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

    pub(super) fn cfg() -> HeimdallConfig {
        serde_yaml::from_str("realms: [prod]").unwrap()
    }

    pub(super) fn planned(name: &str, kind: WatchKind, origin: Origin) -> Planned {
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

    pub(super) fn gh_planned(name: &str) -> Planned {
        planned(
            name,
            WatchKind::Github,
            Origin::Github {
                repo: "acme/widget".to_string(),
            },
        )
    }

    pub(super) async fn add_release(pool: &PgPool, target: &str, version: &str) {
        sqlx::query("INSERT INTO releases (target, version) VALUES ($1, $2)")
            .bind(target)
            .bind(version)
            .execute(pool)
            .await
            .unwrap();
    }

    pub(super) fn now() -> chrono::DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sqlx::PgPool;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::testutil::*;
    use super::*;
    use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
    use crate::model::Source;
    use crate::watchers::{Origin, WatchKind};

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
            .respond_with(ResponseTemplate::new(400))
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
        assert_eq!(attempts(&pool, "1.2.3").await, 1);
    }

    async fn attempts(pool: &PgPool, version: &str) -> i32 {
        sqlx::query_scalar("SELECT notes_attempts FROM releases WHERE version = $1")
            .bind(version)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn run_gh(pool: &PgPool, server: &MockServer, targets: &[&str]) -> Vec<i64> {
        let planned: Vec<_> = targets.iter().map(|t| gh_planned(t)).collect();
        run(
            pool,
            &Client::new(),
            &cfg(),
            &endpoints(server),
            &planned,
            now(),
        )
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gives_up_after_5_failed_runs(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        add_release(&pool, "widget", "1.2.3").await;
        for attempt in 1..=5 {
            run_gh(&pool, &server, &["widget"]).await;
            let class: Option<String> =
                sqlx::query_scalar("SELECT notes_class FROM releases WHERE version = '1.2.3'")
                    .fetch_one(&pool)
                    .await
                    .unwrap();
            assert_eq!(attempts(&pool, "1.2.3").await, attempt);
            // Still retried until the fifth failure.
            assert_eq!(
                class.as_deref(),
                if attempt < 5 { None } else { Some("none") }
            );
        }
        // Given up: a sixth run makes no request.
        let before = server.received_requests().await.unwrap().len();
        run_gh(&pool, &server, &["widget"]).await;
        assert_eq!(server.received_requests().await.unwrap().len(), before);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn stops_the_whole_run_on_403(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        add_release(&pool, "widget", "1.2.3").await;
        add_release(&pool, "gadget", "2.0.0").await;
        run_gh(&pool, &server, &["widget", "gadget"]).await;
        // One request in all: the second target is not even tried.
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
        // The attempt is still counted, so a permanent 403 reaches the ceiling.
        assert_eq!(attempts(&pool, "1.2.3").await, 1);
        assert_eq!(attempts(&pool, "2.0.0").await, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn non_github_403_counts_and_continues(pool: PgPool) {
        let server = MockServer::start().await;
        // Target A's npm lookup is refused; B's GitHub notes do not exist.
        Mock::given(method("GET"))
            .and(path("/a"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        add_release(&pool, "pkg:npm/a", "1.1.0").await;
        add_release(&pool, "widget", "1.2.3").await;
        let a = planned(
            "pkg:npm/a",
            WatchKind::Npm,
            Origin::Npm {
                name: "a".to_string(),
            },
        );
        run(
            &pool,
            &Client::new(),
            &cfg(),
            &endpoints(&server),
            &[a, gh_planned("widget")],
            now(),
        )
        .await
        .unwrap();
        assert_eq!(attempts(&pool, "1.1.0").await, 1);
        // B was still processed (no release found: class none).
        let class: Option<String> =
            sqlx::query_scalar("SELECT notes_class FROM releases WHERE version = '1.2.3'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(class.as_deref(), Some("none"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn newest_published_releases_go_first(pool: PgPool) {
        let server = MockServer::start().await;
        // No source for this target: every looked-at release becomes `none`.
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"versions": {}})))
            .mount(&server)
            .await;
        // 22 releases, the later ones inserted first so id order is the
        // opposite of publish order, plus one with no publish time.
        for i in (1..=22).rev() {
            sqlx::query(
                "INSERT INTO releases (target, version, published_at) \
                 VALUES ('pkg:npm/p', $1, '2026-01-01'::timestamptz + make_interval(days => $2))",
            )
            .bind(format!("1.0.{i}"))
            .bind(i)
            .execute(&pool)
            .await
            .unwrap();
        }
        add_release(&pool, "pkg:npm/p", "0.0.1").await;
        let p = planned(
            "pkg:npm/p",
            WatchKind::Npm,
            Origin::Npm {
                name: "p".to_string(),
            },
        );
        run(
            &pool,
            &Client::new(),
            &cfg(),
            &endpoints(&server),
            &[p],
            now(),
        )
        .await
        .unwrap();
        let mut left: Vec<String> = sqlx::query_scalar(
            "SELECT version FROM releases WHERE notes_class IS NULL ORDER BY version",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        left.sort();
        // The 20 newest were done; the oldest two and the undated one wait.
        assert_eq!(left, vec!["0.0.1", "1.0.1", "1.0.2"]);
    }

    /// One open Vuln finding for advisory GHSA-gin-0001 (aliases CVE-2026-1234 and a GHSA).
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
             VALUES ('GHSA-gin-0001', ARRAY['CVE-2026-1234', 'GHSA-C2C2-F3F3-G4G4'], 'critical', 's', 'osv')",
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
        assert_eq!(key, "relnote|widget|1.2.3|GHSA-gin-0001");
        assert_eq!(severity, "critical");
        assert_eq!(realm, "prod");
        assert_eq!(details["id"], "CVE-2026-1234");
        // The notes cite the CVE and the GHSA of one advisory: one finding.
        assert_eq!(
            details["ids"],
            json!(["CVE-2026-1234", "GHSA-C2C2-F3F3-G4G4"])
        );
        assert_eq!(details["advisory"], "GHSA-gin-0001");
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
