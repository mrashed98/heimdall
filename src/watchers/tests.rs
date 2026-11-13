//! Watcher tests: each source against wiremock, and `run_with` against a real
//! database (sqlx::test) with every outside service served by one mock.

use chrono::{Duration, TimeZone, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use url::Url;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plan::image_ref;
use super::*;
use crate::config::HeimdallConfig;
use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
use crate::model::Source;

fn fixture(name: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/watchers/{name}")).unwrap()
}

fn base(server: &MockServer) -> Url {
    Url::parse(&server.uri()).unwrap()
}

/// Every outside service is the one mock server.
fn endpoints(server: &MockServer) -> Endpoints {
    let b = base(server);
    Endpoints {
        github: b.clone(),
        endoflife: b.clone(),
        npm: b.clone(),
        go_proxy: b.clone(),
        artifacthub: b.clone(),
        registry_override: Some(b),
    }
}

fn cfg(yaml: &str) -> HeimdallConfig {
    serde_yaml::from_str(yaml).unwrap()
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap()
}

/// Give `service` in `realm` exactly these (purl, direct) components.
async fn components(pool: &PgPool, realm: &str, service: &str, items: &[(&str, bool)]) {
    let svc = upsert_service(pool, realm, service).await.unwrap();
    let items: Vec<InventoryItem> = items
        .iter()
        .map(|(purl, direct)| InventoryItem {
            purl: purl.to_string(),
            cpes: vec![],
            direct: *direct,
            via_image_digest: None,
        })
        .collect();
    replace_components(pool, svc, Source::Cluster, &items)
        .await
        .unwrap();
}

async fn open_keys(pool: &PgPool, kind: &str) -> Vec<String> {
    sqlx::query_scalar("SELECT key FROM findings WHERE kind = $1 AND status = 'open' ORDER BY key")
        .bind(kind)
        .fetch_all(pool)
        .await
        .unwrap()
}

fn gh_release(tag: &str) -> Value {
    json!({"tag_name": tag, "draft": false, "prerelease": false,
           "published_at": "2026-11-01T00:00:00Z"})
}

// ---- sources ------------------------------------------------------------

#[tokio::test]
async fn github_skips_prereleases_and_drafts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/kubernetes/kubernetes/releases"))
        .and(query_param("per_page", "30"))
        .and(header("authorization", "Bearer s3cret"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("github_releases.json")))
        .expect(1)
        .mount(&server)
        .await;
    let got = github::fetch(
        &reqwest::Client::new(),
        &base(&server),
        "kubernetes/kubernetes",
        Some("s3cret"),
        None,
    )
    .await
    .unwrap();
    let versions: Vec<&str> = got.releases.iter().map(|r| r.version.as_str()).collect();
    // v1.38.0-beta.0 / -alpha.3 are prereleases; v1.36.6 is a draft.
    assert_eq!(versions, ["v1.37.2", "v1.35.10", "v1.34.13"]);
    assert!(got.releases[0].published_at.is_some());
}

#[tokio::test]
async fn github_304_not_modified_uses_etag() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/o/r/releases"))
        .and(header("if-none-match", "W/\"abc\""))
        .respond_with(ResponseTemplate::new(304))
        .expect(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/o/r/releases"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "W/\"abc\"")
                .set_body_json(json!([gh_release("v1.0.0")])),
        )
        .expect(1)
        .mount(&server)
        .await;
    let http = reqwest::Client::new();
    let first = github::fetch(&http, &base(&server), "o/r", None, None)
        .await
        .unwrap();
    assert!(!first.not_modified);
    assert_eq!(first.etag.as_deref(), Some("W/\"abc\""));
    let second = github::fetch(&http, &base(&server), "o/r", None, first.etag.as_deref())
        .await
        .unwrap();
    assert!(second.not_modified);
    assert!(second.releases.is_empty());
}

#[tokio::test]
async fn go_module_path_escaping() {
    assert_eq!(
        go_proxy::escape("github.com/BurntSushi/toml"),
        "github.com/!burnt!sushi/toml"
    );
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github.com/!burnt!sushi/toml/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("go_proxy_list.txt")))
        .expect(1)
        .mount(&server)
        .await;
    let got = go_proxy::fetch(
        &reqwest::Client::new(),
        &base(&server),
        "github.com/BurntSushi/toml",
        None,
    )
    .await
    .unwrap();
    assert_eq!(got.releases.len(), 16);
    assert!(got.releases.iter().any(|r| r.version == "v1.6.0"));
}

#[tokio::test]
async fn npm_versions_carry_publish_time() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("npm_left-pad.json")))
        .mount(&server)
        .await;
    let got = npm::fetch(&reqwest::Client::new(), &base(&server), "left-pad", None)
        .await
        .unwrap();
    assert_eq!(got.releases.len(), 15);
    let r = got.releases.iter().find(|r| r.version == "1.3.0").unwrap();
    assert_eq!(
        r.published_at.unwrap().to_rfc3339(),
        "2018-04-09T01:10:45.796+00:00"
    );
}

#[tokio::test]
async fn helm_index_lists_one_chart() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/charts/index.yaml"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("helm_index.yaml")))
        .mount(&server)
        .await;
    let repo = Url::parse(&format!("{}/charts", server.uri())).unwrap();
    let got = helm::fetch_index(&reqwest::Client::new(), &repo, "kyverno", None)
        .await
        .unwrap();
    let versions: Vec<&str> = got.releases.iter().map(|r| r.version.as_str()).collect();
    assert_eq!(versions[0], "3.10.0");
    assert_eq!(versions.len(), 5);
}

#[tokio::test]
async fn tf_registry_providers_and_modules() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/providers/hashicorp/random/versions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("tf_provider_versions.json")),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/modules/terraform-aws-modules/vpc/aws/versions"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("tf_module_versions.json")),
        )
        .mount(&server)
        .await;
    let http = reqwest::Client::new();
    let p = tf_registry::fetch(
        &http,
        &base(&server),
        TfKind::Provider,
        "hashicorp/random",
        None,
    )
    .await
    .unwrap();
    assert_eq!(p.releases[0].version, "3.6.3");
    let m = tf_registry::fetch(
        &http,
        &base(&server),
        TfKind::Module,
        "terraform-aws-modules/vpc/aws",
        None,
    )
    .await
    .unwrap();
    assert_eq!(m.releases.len(), 6);
}

#[tokio::test]
async fn endoflife_v1_cycles() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/products/postgresql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_string(fixture("endoflife_postgresql.json")),
        )
        .mount(&server)
        .await;
    let cycles = endoflife::fetch(&reqwest::Client::new(), &base(&server), "postgresql")
        .await
        .unwrap();
    assert_eq!(cycles.len(), 3);
    assert_eq!(cycles[1].cycle, "16");
    assert_eq!(cycles[1].latest.as_deref(), Some("16.11"));
    assert_eq!(
        cycles[1].eol,
        Some(chrono::NaiveDate::from_ymd_opt(2028, 11, 9).unwrap())
    );
}

#[tokio::test]
async fn oci_tags_handshake_and_paging() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/token"))
        .and(query_param("scope", "repository:library/postgres:pull"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"token": "t0k"})))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/library/postgres/tags/list"))
        .and(query_param("last", "10.0"))
        .and(header("authorization", "Bearer t0k"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(
                json!({"name": "library/postgres", "tags": ["17.0", "17.0-alpine"]}),
            ),
        )
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/library/postgres/tags/list"))
        .and(header("authorization", "Bearer t0k"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"p1\"")
                .insert_header(
                    "link",
                    "</v2/library/postgres/tags/list?last=10.0&n=20>; rel=\"next\"",
                )
                .set_body_string(fixture("oci_tags_page1.json")),
        )
        .with_priority(2)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/library/postgres/tags/list"))
        .respond_with(ResponseTemplate::new(401).insert_header(
            "www-authenticate",
            format!(
                "Bearer realm=\"{}/token\",service=\"registry.docker.io\",scope=\"repository:library/postgres:pull\"",
                server.uri()
            ),
        ))
        .with_priority(3)
        .mount(&server)
        .await;
    let got = oci::tags(
        &reqwest::Client::new(),
        &base(&server),
        "library/postgres",
        None,
        None,
    )
    .await
    .unwrap();
    let tags: Vec<&str> = got.releases.iter().map(|r| r.version.as_str()).collect();
    assert_eq!(tags.first(), Some(&"10"));
    assert_eq!(&tags[tags.len() - 2..], ["17.0", "17.0-alpine"]);
    // Page 1's ETag says nothing about page 2, so none is kept.
    assert_eq!(got.etag, None);
}

#[tokio::test]
async fn oci_single_page_keeps_etag() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/acme/app/tags/list"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("etag", "\"one\"")
                .set_body_json(json!({"tags": ["1.0.0"]})),
        )
        .mount(&server)
        .await;
    let got = oci::tags(
        &reqwest::Client::new(),
        &base(&server),
        "acme/app",
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(got.etag.as_deref(), Some("\"one\""));
}

#[test]
fn image_refs_normalise() {
    assert_eq!(
        image_ref("postgres"),
        Some(("docker.io".to_string(), "library/postgres".to_string()))
    );
    assert_eq!(
        image_ref("docker.io/library/postgres"),
        Some(("docker.io".to_string(), "library/postgres".to_string()))
    );
    assert_eq!(
        image_ref("ghcr.io/acme/api"),
        Some(("ghcr.io".to_string(), "acme/api".to_string()))
    );
    assert_eq!(
        image_ref("localhost:5000/x"),
        Some(("localhost:5000".to_string(), "x".to_string()))
    );
}

// ---- run_with -----------------------------------------------------------

const ONE_REALM: &str = "realms: [dev]\n";

#[sqlx::test(migrations = "./migrations")]
async fn oci_major_only_same_suffix(pool: PgPool) {
    components(
        &pool,
        "dev",
        "db",
        &[(
            "pkg:oci/postgres@sha256%3Aabc?repository_url=docker.io/library/postgres&tag=16.4-alpine",
            true,
        )],
    )
    .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/library/postgres/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "library/postgres",
            "tags": ["16.5-alpine", "17.0-alpine", "17.0-bookworm", "latest"]
        })))
        .expect(1)
        .mount(&server)
        .await;
    let report = run_with(
        &pool,
        &reqwest::Client::new(),
        &cfg(ONE_REALM),
        &endpoints(&server),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(report.failures, BTreeMap::new());
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|docker.io/library/postgres|17.0-alpine"]
    );
    // The minor is recorded for the digest, the other suffix is not.
    let stored: Vec<String> = sqlx::query_scalar("SELECT version FROM releases ORDER BY version")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(stored, ["16.5-alpine", "17.0-alpine"]);
}

const K8S: &str = "realms: [dev]
watchers:
  github:
    - { repo: kubernetes/kubernetes, inventory_name: kubernetes, major_component: 1 }
";

#[sqlx::test(migrations = "./migrations")]
async fn k8s_minor_is_major(pool: PgPool) {
    components(
        &pool,
        "dev",
        "cluster",
        &[("pkg:generic/kubernetes@1.31.2", false)],
    )
    .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/kubernetes/kubernetes/releases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            gh_release("v1.32.0"),
            gh_release("v1.32.1"),
            gh_release("v1.31.3")
        ])))
        .mount(&server)
        .await;
    let http = reqwest::Client::new();
    let ep = endpoints(&server);
    run_with(&pool, &http, &cfg(K8S), &ep, now()).await.unwrap();
    // One finding per major line, for its first release; a rerun adds nothing.
    run_with(&pool, &http, &cfg(K8S), &ep, now()).await.unwrap();
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|kubernetes|1.32.0"]
    );
    let sev: String = sqlx::query_scalar("SELECT severity FROM findings")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sev, "high");

    // Upgrading to that major resolves it.
    components(
        &pool,
        "dev",
        "cluster",
        &[("pkg:generic/kubernetes@1.32.1", false)],
    )
    .await;
    let report = run_with(&pool, &http, &cfg(K8S), &ep, now()).await.unwrap();
    assert_eq!(report.resolved, 1);
    assert!(open_keys(&pool, "majorrelease").await.is_empty());
}

const PG_EOL: &str = "realms: [dev]
watchers:
  endoflife:
    - { product: postgresql, inventory_name: postgresql }
";

async fn mount_eol(server: &MockServer, days: i64) {
    let mut body: Value = serde_json::from_str(&fixture("endoflife_postgresql.json")).unwrap();
    let eol = (now() + Duration::days(days)).date_naive().to_string();
    body["result"]["releases"][1]["eolFrom"] = json!(eol);
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/products/postgresql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[sqlx::test(migrations = "./migrations")]
async fn eol_within_60_days(pool: PgPool) {
    components(
        &pool,
        "dev",
        "pg-vm",
        &[("pkg:generic/postgresql@16.4", false)],
    )
    .await;
    let server = MockServer::start().await;
    let http = reqwest::Client::new();
    let ep = endpoints(&server);

    mount_eol(&server, 90).await;
    run_with(&pool, &http, &cfg(PG_EOL), &ep, now())
        .await
        .unwrap();
    assert!(open_keys(&pool, "eol").await.is_empty());

    mount_eol(&server, 30).await;
    run_with(&pool, &http, &cfg(PG_EOL), &ep, now())
        .await
        .unwrap();
    assert_eq!(open_keys(&pool, "eol").await, ["eol|dev|postgresql|16"]);

    // Moving off the cycle resolves it.
    components(
        &pool,
        "dev",
        "pg-vm",
        &[("pkg:generic/postgresql@18.1", false)],
    )
    .await;
    run_with(&pool, &http, &cfg(PG_EOL), &ep, now())
        .await
        .unwrap();
    assert!(open_keys(&pool, "eol").await.is_empty());
}

#[sqlx::test(migrations = "./migrations")]
async fn transitive_libraries_not_watched(pool: PgPool) {
    components(&pool, "dev", "web", &[("pkg:npm/left-pad@1.0.0", false)]).await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_string(fixture("npm_left-pad.json")))
        .expect(0)
        .mount(&server)
        .await;
    let report = run_with(
        &pool,
        &reqwest::Client::new(),
        &cfg(ONE_REALM),
        &endpoints(&server),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(report.targets, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn one_target_failure_does_not_stop_others(pool: PgPool) {
    components(
        &pool,
        "dev",
        "cluster",
        &[("pkg:generic/kubernetes@1.31.2", false)],
    )
    .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/repos/acme/broken/releases"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/repos/kubernetes/kubernetes/releases"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([gh_release("v1.32.0")])))
        .mount(&server)
        .await;
    let yaml = "realms: [dev]
watchers:
  github:
    - { repo: acme/broken, inventory_name: broken }
    - { repo: kubernetes/kubernetes, inventory_name: kubernetes, major_component: 1 }
";
    let report = run_with(
        &pool,
        &reqwest::Client::new(),
        &cfg(yaml),
        &endpoints(&server),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(report.failures.get("github"), Some(&1));
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|kubernetes|1.32.0"]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn own_registry_images_not_watched(pool: PgPool) {
    components(
        &pool,
        "dev",
        "api",
        &[
            (
                "pkg:oci/api@sha256%3Aa1?repository_url=ghcr.io/acme/api&tag=1.0.0",
                true,
            ),
            (
                "pkg:oci/postgres@sha256%3Ab2?repository_url=docker.io/library/postgres&tag=16.4",
                true,
            ),
        ],
    )
    .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v2/acme/api/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tags": ["2.0.0"]})))
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v2/library/postgres/tags/list"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tags": ["16.5"]})))
        .expect(1)
        .mount(&server)
        .await;
    let yaml = "realms: [dev]\nown_registries: [ghcr.io/acme]\n";
    let report = run_with(
        &pool,
        &reqwest::Client::new(),
        &cfg(yaml),
        &endpoints(&server),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(report.targets, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn zero_x_minor_is_major(pool: PgPool) {
    components(&pool, "dev", "web", &[("pkg:npm/left-pad@0.3.9", true)]).await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/left-pad"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "name": "left-pad",
            "versions": {"0.3.9": {}, "0.3.10": {}, "0.4.0": {}},
            "time": {"created": "2026-01-01T00:00:00Z", "0.4.0": "2026-11-01T00:00:00Z"}
        })))
        .mount(&server)
        .await;
    run_with(
        &pool,
        &reqwest::Client::new(),
        &cfg(ONE_REALM),
        &endpoints(&server),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|pkg:npm/left-pad|0.4.0"]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn first_sight_opens_only_highest_major_line(pool: PgPool) {
    components(&pool, "dev", "web", &[("pkg:npm/x@16.0.0", true)]).await;
    let server = MockServer::start().await;
    let http = reqwest::Client::new();
    let ep = endpoints(&server);
    let mount = |versions: Value| {
        let server = &server;
        async move {
            server.reset().await;
            Mock::given(method("GET"))
                .and(path("/x"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(json!({"versions": versions})),
                )
                .mount(server)
                .await;
        }
    };
    mount(json!({"17.0.0": {}, "17.1.0": {}, "18.0.0": {}})).await;
    run_with(&pool, &http, &cfg(ONE_REALM), &ep, now())
        .await
        .unwrap();
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|pkg:npm/x|18.0.0"]
    );
    // Line 17 was marked done on first sight: a later 17.x stays quiet.
    mount(json!({"17.0.0": {}, "17.1.0": {}, "17.2.0": {}, "18.0.0": {}})).await;
    run_with(&pool, &http, &cfg(ONE_REALM), &ep, now())
        .await
        .unwrap();
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|pkg:npm/x|18.0.0"]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn go_next_major_module_probed(pool: PgPool) {
    components(
        &pool,
        "dev",
        "svc",
        &[("pkg:golang/github.com/foo/bar@v1.5.0", true)],
    )
    .await;
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("v1.5.0\nv1.6.0\n"))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/v2/@v/list"))
        .respond_with(ResponseTemplate::new(200).set_body_string("v2.0.0\n"))
        .expect(1)
        .mount(&server)
        .await;
    let report = run_with(
        &pool,
        &reqwest::Client::new(),
        &cfg(ONE_REALM),
        &endpoints(&server),
        now(),
    )
    .await
    .unwrap();
    assert_eq!(report.failures, BTreeMap::new());
    assert_eq!(
        open_keys(&pool, "majorrelease").await,
        ["major_release|pkg:golang/github.com/foo/bar|v2.0.0"]
    );
}

#[test]
fn go_next_major_paths() {
    assert_eq!(
        go_proxy::next_major_module("github.com/foo/bar"),
        "github.com/foo/bar/v2"
    );
    assert_eq!(
        go_proxy::next_major_module("github.com/foo/bar/v2"),
        "github.com/foo/bar/v3"
    );
    assert_eq!(
        go_proxy::next_major_module("github.com/foo/v2go"),
        "github.com/foo/v2go/v2"
    );
}

#[tokio::test]
async fn go_next_major_absent_is_empty() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/github.com/foo/bar/v2/@v/list"))
        .respond_with(ResponseTemplate::new(410))
        .mount(&server)
        .await;
    let got = go_proxy::fetch_next_major(
        &reqwest::Client::new(),
        &base(&server),
        "github.com/foo/bar",
    )
    .await
    .unwrap();
    assert!(got.is_empty());
}

// ---- versions behind ------------------------------------------------------

#[sqlx::test(migrations = "./migrations")]
async fn versions_behind_counts_newer_stable_releases(pool: PgPool) {
    let cfg = cfg("realms: [prod]\nwatchers:\n  github:\n    - { repo: kubernetes/kubernetes, inventory_name: kubernetes, major_component: 1 }\n");
    components(
        &pool,
        "prod",
        "cluster",
        &[("pkg:generic/kubernetes@1.30.2", true)],
    )
    .await;
    for v in ["1.29.0", "1.30.2", "1.30.3", "1.31.0", "1.32.0-rc.1"] {
        sqlx::query("INSERT INTO releases (target, version) VALUES ('kubernetes', $1)")
            .bind(v)
            .execute(&pool)
            .await
            .unwrap();
    }
    let behind = versions_behind(&pool, &cfg).await.unwrap();
    assert_eq!(
        behind,
        vec![("prod".to_string(), "kubernetes".to_string(), 2)]
    );
}
