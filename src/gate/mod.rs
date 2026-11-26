//! Hofund: the CI gate. CI uploads an SBOM; the server ingests it, checks the
//! components live against OSV (the GitHub Advisory Database when OSV is
//! down), applies oaths and answers pass, fail or unverified.
//!
//! - this file: the route, the decision and the CLI helpers.
//! - `lookup`: asking OSV and the GitHub Advisory Database.
// Exception: predates AppState.clock; move these Utc::now() calls to it. Expires 2027-03-01, approval: pending (owner).
#![allow(clippy::disallowed_methods)]

mod lookup;

use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::{require, Authed, Scope};
use crate::error::ApiError;
use crate::ingest::api::{ingest_sbom_inner, SbomQuery, UploadSlot, BODY_LIMIT};
use crate::model::Severity;
use crate::purl::{name_key, OsvPackage};
use crate::vuln::ghsa::GhsaClient;
use crate::vuln::osv::OsvClient;
use crate::{oath, AppState};
use lookup::{checkable, ghsa_hits, osv_hits};

/// The whole gate answers within this, so a CI job never hangs on us.
const TOTAL_BUDGET: Duration = Duration::from_secs(60);
/// OSV gets most of it; the rest is left for the GHSA fallback.
const OSV_BUDGET: Duration = Duration::from_secs(40);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Fail,
    Unverified,
}

/// Which advisory database answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSource {
    Osv,
    Ghsa,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateFinding {
    pub advisory: String,
    pub severity: Severity,
    pub purl: String,
    /// The version to move to, when a fix exists.
    pub fixed: Option<String>,
    /// Id of the oath that covers this finding.
    pub oath: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResponse {
    pub verdict: Verdict,
    pub source: CheckSource,
    pub findings: Vec<GateFinding>,
    /// Purls nothing could vouch for (OSV down, GHSA does not cover them).
    pub unverified: Vec<String>,
}

/// Same as the `/ingest/sbom` query, plus the severity that fails the build.
#[derive(Debug, Clone, Deserialize)]
pub struct GateQuery {
    pub service: String,
    pub realm: String,
    pub branch: String,
    pub default_branch: String,
    pub fail_on: Severity,
    /// Accept an SBOM with no components (normally a 400: an empty SBOM
    /// would empty the service's inventory).
    #[serde(default)]
    pub allow_empty: bool,
}

/// The advisory clients one gate run uses, with its time budgets. Built per
/// request from `AppState`; tests point the clients at mock servers.
pub struct GateClients {
    pub osv: OsvClient,
    /// None when no `GITHUB_TOKEN` is set: the fallback is then unavailable.
    pub ghsa: Option<GhsaClient>,
    pub osv_budget: Duration,
    pub total_budget: Duration,
}

impl GateClients {
    pub fn from_state(state: &AppState) -> GateClients {
        let ghsa = std::env::var("GITHUB_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .map(|t| GhsaClient::new(state.http.clone(), t));
        GateClients {
            osv: OsvClient::new(state.http.clone()),
            ghsa,
            osv_budget: OSV_BUDGET,
            total_budget: TOTAL_BUDGET,
        }
    }
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/gate", post(gate))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

async fn gate(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<GateQuery>,
    _slot: UploadSlot,
    body: Bytes,
) -> Result<Json<GateResponse>, ApiError> {
    require(&authed, Scope::Ingest)?;
    let clients = GateClients::from_state(&state);
    Ok(Json(run(&state, &clients, &q, &body).await?))
}

/// Ingest the SBOM, check it and decide.
pub async fn run(
    state: &AppState,
    clients: &GateClients,
    q: &GateQuery,
    body: &[u8],
) -> Result<GateResponse, ApiError> {
    let started = Instant::now();
    let sbom_query = SbomQuery {
        service: q.service.clone(),
        realm: q.realm.clone(),
        branch: q.branch.clone(),
        default_branch: q.default_branch.clone(),
        allow_empty: q.allow_empty,
    };
    let outcome = ingest_sbom_inner(state, &sbom_query, body).await?;
    let checked = checkable(&outcome.purls);
    let pool = &state.pool;

    // Only OSV's own answer decides between OSV and the fallback. `timeout`
    // drops the query when the budget runs out, which also cancels any retry
    // backoff sleeping inside it.
    let pkgs: Vec<OsvPackage> = checked.iter().map(|c| c.pkg.clone()).collect();
    let batch = tokio::time::timeout(clients.osv_budget, clients.osv.query_batch(&pkgs)).await;
    let (source, hits, unverified) = match batch {
        Ok(Ok(all)) => {
            // OSV has answered: from here on its hits are kept whatever fails.
            let left = clients.total_budget.saturating_sub(started.elapsed());
            let (hits, unverified) = osv_hits(pool, &clients.osv, &checked, &all, left).await?;
            (CheckSource::Osv, hits, unverified)
        }
        failed => {
            let why = match failed {
                Ok(Err(e)) => format!("failed ({e:#})"),
                _ => "timed out".to_string(),
            };
            tracing::warn!("gate: osv {why}; falling back to the github advisory db");
            let left = clients.total_budget.saturating_sub(started.elapsed());
            let (hits, unverified) = ghsa_hits(pool, clients.ghsa.as_ref(), &checked, left).await?;
            (CheckSource::Ghsa, hits, unverified)
        }
    };

    let now = Utc::now();
    let mut findings = Vec::new();
    for h in hits {
        let oath = oath_for(pool, &h.oath_ids, &h.name_key, q, now).await?;
        findings.push(GateFinding {
            advisory: h.advisory,
            severity: h.severity,
            purl: h.purl,
            fixed: h.fixed,
            oath,
        });
    }
    // Worst first, so the table reads top-down.
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.advisory.cmp(&b.advisory))
            .then_with(|| a.purl.cmp(&b.purl))
    });

    Ok(GateResponse {
        verdict: verdict(&findings, &unverified, q.fail_on),
        source,
        findings,
        unverified,
    })
}

/// The first active oath filed under any of `ids` for this component.
async fn oath_for(
    pool: &PgPool,
    ids: &[String],
    name_key: &str,
    q: &GateQuery,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<i64>> {
    for id in ids {
        if let Some(o) = oath::active_for(pool, id, name_key, &q.service, &q.realm, now).await? {
            return Ok(Some(o.id));
        }
    }
    Ok(None)
}

/// `fail` if any finding at or above `fail_on` has no oath; else
/// `unverified` if anything could not be checked; else `pass`.
pub fn verdict(findings: &[GateFinding], unverified: &[String], fail_on: Severity) -> Verdict {
    if findings
        .iter()
        .any(|f| f.severity >= fail_on && f.oath.is_none())
    {
        Verdict::Fail
    } else if !unverified.is_empty() {
        Verdict::Unverified
    } else {
        Verdict::Pass
    }
}

/// CLI exit code: 0 pass, 1 fail, 2 unverified.
pub fn exit_code(v: Verdict) -> u8 {
    match v {
        Verdict::Pass => 0,
        Verdict::Fail => 1,
        Verdict::Unverified => 2,
    }
}

/// `repository.default_branch` from a GitHub Actions event file
/// (`$GITHUB_EVENT_PATH`). Ok(None) when the event has no such field.
pub fn default_branch_from_event(path: &Path) -> anyhow::Result<Option<String>> {
    use anyhow::Context;
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading event file {}", path.display()))?;
    let event: Value = serde_json::from_str(&text)
        .with_context(|| format!("parsing event file {}", path.display()))?;
    Ok(event
        .pointer("/repository/default_branch")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from))
}

/// `--fail-on` value: critical, high, medium, low or unknown.
pub fn parse_severity(s: &str) -> Result<Severity, String> {
    serde_json::from_value(Value::String(s.to_ascii_lowercase()))
        .map_err(|_| format!("unknown severity {s:?} (use critical, high, medium, low or unknown)"))
}

/// (name key, version) of a purl, for display.
pub fn split_purl(purl: &str) -> (String, String) {
    let version = packageurl::PackageUrl::from_str(purl)
        .ok()
        .and_then(|p| p.version().map(str::to_string))
        .unwrap_or_default();
    let package = name_key(purl).unwrap_or_else(|_| purl.to_string());
    (package, version)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::config::HeimdallConfig;

    const NPM: &str = "pkg:npm/widget@1.2.0";
    const DEB: &str = "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?upstream=openssl&distro=debian-12";
    const ADV: &str = "GHSA-h1gh-h1gh-h1gh";

    fn state(pool: PgPool) -> AppState {
        let cfg = HeimdallConfig::load(Path::new("heimdall.example.yaml")).unwrap();
        AppState::new(pool, Arc::new(cfg), reqwest::Client::new())
    }

    fn clients(osv: &MockServer, ghsa: Option<&MockServer>) -> GateClients {
        GateClients {
            osv: OsvClient {
                base: Url::parse(&osv.uri()).unwrap(),
                http: reqwest::Client::new(),
            },
            ghsa: ghsa.map(|s| {
                let mut c = GhsaClient::new(reqwest::Client::new(), "tok".into());
                c.base = Url::parse(&format!("{}/graphql", s.uri())).unwrap();
                c
            }),
            osv_budget: OSV_BUDGET,
            total_budget: TOTAL_BUDGET,
        }
    }

    fn query(fail_on: Severity) -> GateQuery {
        GateQuery {
            service: "api".into(),
            realm: "dev-k3s".into(),
            branch: "feat-x".into(),
            default_branch: "main".into(),
            fail_on,
            allow_empty: false,
        }
    }

    fn body(purls: &[&str]) -> Vec<u8> {
        let components: Vec<Value> = purls.iter().map(|p| json!({ "purl": p })).collect();
        let sbom = json!({ "bomFormat": "CycloneDX", "components": components });
        serde_json::to_vec(&json!({ "sbom": sbom, "direct": [] })).unwrap()
    }

    /// OSV knows one high advisory for widget, fixed in 1.9.1.
    async fn osv_with_high() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": ADV, "modified": "2026-05-01T00:00:00Z"}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{ADV}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": ADV,
                "modified": "2026-05-01T00:00:00Z",
                "database_specific": {"severity": "HIGH"},
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "widget"},
                    "ranges": [{"type": "SEMVER", "events": [
                        {"introduced": "0"}, {"fixed": "1.9.1"}
                    ]}]
                }]
            })))
            .mount(&server)
            .await;
        server
    }

    async fn osv_down() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        server
    }

    /// GHSA answering for one covered package (alias q0).
    async fn ghsa_with(nodes: Value) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {"q0": {"pageInfo": {"hasNextPage": false}, "nodes": nodes}}
            })))
            .mount(&server)
            .await;
        server
    }

    async fn oath_on(pool: &PgPool, advisory: &str) -> i64 {
        sqlx::query_scalar(
            "insert into oaths (advisory_id, name_key, service_name, realm, kind, reason, \
             version_at_creation, review_at, created_by) \
             values ($1, 'pkg:npm/widget', 'api', 'dev-k3s', 'ignore', 'not reachable', \
             '1.2.0', now() + interval '30 days', 'test') returning id",
        )
        .bind(advisory)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_fails_on_high(pool: PgPool) {
        let osv = osv_with_high().await;
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.source, CheckSource::Osv);
        assert_eq!(
            r.findings,
            vec![GateFinding {
                advisory: ADV.into(),
                severity: Severity::High,
                purl: NPM.into(),
                fixed: Some("1.9.1".into()),
                oath: None,
            }]
        );
        assert!(r.unverified.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_rejects_empty_sbom(pool: PgPool) {
        let osv = osv_with_high().await;
        let err = run(
            &state(pool.clone()),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[]),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&err, ApiError::BadRequest(m) if m.contains("empty SBOM")),
            "{err:?}"
        );
        let q = GateQuery {
            allow_empty: true,
            ..query(Severity::High)
        };
        let r = run(&state(pool), &clients(&osv, None), &q, &body(&[]))
            .await
            .unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
    }

    /// OSV knows widget's CVE-2026-5000 twice: a GO- record (low, fixed in
    /// 1.9.1) and a GHSA- record (high, no fix) that names the GO- one.
    async fn osv_with_twin_records() -> MockServer {
        let server = MockServer::start().await;
        let modified = "2026-05-01T00:00:00Z";
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [
                    {"id": "GO-2026-0001", "modified": modified},
                    {"id": ADV, "modified": modified},
                ]}]
            })))
            .mount(&server)
            .await;
        let record = |id: &str, aliases: Value, word: &str, events: Value| {
            json!({
                "id": id, "modified": modified, "aliases": aliases,
                "database_specific": {"severity": word},
                "affected": [{
                    "package": {"ecosystem": "npm", "name": "widget"},
                    "ranges": [{"type": "SEMVER", "events": events}]
                }]
            })
        };
        let go = record(
            "GO-2026-0001",
            json!(["CVE-2026-5000"]),
            "LOW",
            json!([{"introduced": "0"}, {"fixed": "1.9.1"}]),
        );
        let ghsa = record(
            ADV,
            json!(["CVE-2026-5000", "GO-2026-0001"]),
            "HIGH",
            json!([{"introduced": "0"}]),
        );
        for rec in [go, ghsa] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{}", rec["id"].as_str().unwrap())))
                .respond_with(ResponseTemplate::new(200).set_body_json(rec))
                .mount(&server)
                .await;
        }
        server
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_collapses_osv_aliases_to_one_finding(pool: PgPool) {
        let osv = osv_with_twin_records().await;
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(
            r.findings,
            vec![GateFinding {
                advisory: ADV.into(),
                severity: Severity::High,
                purl: NPM.into(),
                fixed: Some("1.9.1".into()),
                oath: None,
            }]
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_oath_filed_under_an_alias_applies(pool: PgPool) {
        let osv = osv_with_high().await;
        // The record names a CVE; the oath was filed under it.
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{ADV}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": ADV, "modified": "2026-05-01T00:00:00Z",
                "aliases": ["CVE-2026-6000"],
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"ecosystem": "npm", "name": "widget"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
            })))
            .with_priority(1)
            .mount(&osv)
            .await;
        let id = oath_on(&pool, "CVE-2026-6000").await;
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.findings[0].oath, Some(id));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_passes_below_fail_on(pool: PgPool) {
        let osv = osv_with_high().await;
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::Critical),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.findings.len(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_passes_when_oathed(pool: PgPool) {
        let osv = osv_with_high().await;
        let id = oath_on(&pool, ADV).await;
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.findings[0].oath, Some(id));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn stored_advisory_severity_wins_when_unchanged(pool: PgPool) {
        let osv = osv_with_high().await;
        // NVD already raised it to critical; same `modified`, so not refetched.
        sqlx::query(
            "insert into advisories (id, severity, source, modified, fixed) \
             values ($1, 'critical', 'osv', '2026-05-01T00:00:00Z', '{\"pkg:npm/widget\": [\"1.9.1\"]}')",
        )
        .bind(ADV)
        .execute(&pool)
        .await
        .unwrap();
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::Critical),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.findings[0].severity, Severity::Critical);
        assert_eq!(r.findings[0].fixed.as_deref(), Some("1.9.1"));
    }

    /// OSV's querybatch reports ADV for widget, but its record cannot be read.
    async fn osv_hit_without_record() -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": ADV, "modified": "2026-05-01T00:00:00Z"}]}]
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{ADV}")))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;
        server
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_hit_with_failed_record_fetch_is_not_pass(pool: PgPool) {
        let osv = osv_hit_without_record().await;
        let gh = ghsa_with(json!([])).await;
        let r = run(
            &state(pool),
            &clients(&osv, Some(&gh)),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_ne!(r.verdict, Verdict::Pass);
        assert_eq!(r.verdict, Verdict::Unverified);
        assert_eq!(r.source, CheckSource::Osv);
        assert_eq!(r.unverified, vec![NPM.to_string()]);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].advisory, ADV);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn failed_record_fetch_uses_stored_severity(pool: PgPool) {
        let osv = osv_hit_without_record().await;
        // Stored row is older than OSV's `modified`, so a refetch is wanted.
        sqlx::query(
            "insert into advisories (id, severity, source, modified, fixed) \
             values ($1, 'high', 'osv', '2026-01-01T00:00:00Z', '{\"pkg:npm/widget\": [\"1.9.1\"]}')",
        )
        .bind(ADV)
        .execute(&pool)
        .await
        .unwrap();
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Fail);
        assert_eq!(r.findings[0].severity, Severity::High);
        assert_eq!(r.findings[0].fixed.as_deref(), Some("1.9.1"));
        assert!(r.unverified.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn slow_record_fetch_is_bounded_and_kept(pool: PgPool) {
        let osv = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": ADV, "modified": "2026-05-01T00:00:00Z"}]}]
            })))
            .mount(&osv)
            .await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({}))
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(&osv)
            .await;
        let mut c = clients(&osv, None);
        c.total_budget = Duration::from_millis(500);
        let started = Instant::now();
        let r = run(&state(pool), &c, &query(Severity::High), &body(&[NPM]))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(r.source, CheckSource::Osv);
        assert_eq!(r.verdict, Verdict::Unverified);
        assert_eq!(r.findings.len(), 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_down_falls_back_to_ghsa_pass(pool: PgPool) {
        let osv = osv_down().await;
        let gh = ghsa_with(json!([])).await;
        let r = run(
            &state(pool),
            &clients(&osv, Some(&gh)),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Pass);
        assert_eq!(r.source, CheckSource::Ghsa);
        assert!(r.findings.is_empty());
        assert!(r.unverified.is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_down_with_debian_components_unverified(pool: PgPool) {
        let osv = osv_down().await;
        let gh = ghsa_with(json!([])).await;
        let r = run(
            &state(pool),
            &clients(&osv, Some(&gh)),
            &query(Severity::High),
            &body(&[NPM, DEB]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Unverified);
        assert_eq!(r.source, CheckSource::Ghsa);
        assert_eq!(r.unverified, vec![DEB.to_string()]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_and_ghsa_down_all_unverified(pool: PgPool) {
        let osv = osv_down().await;
        // No GITHUB_TOKEN: no fallback at all.
        let r = run(
            &state(pool),
            &clients(&osv, None),
            &query(Severity::High),
            &body(&[NPM, DEB]),
        )
        .await
        .unwrap();
        assert_eq!(r.verdict, Verdict::Unverified);
        assert_eq!(r.unverified, vec![NPM.to_string(), DEB.to_string()]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn slow_osv_is_cut_off_by_budget(pool: PgPool) {
        let osv = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"results": [{}]}))
                    .set_delay(Duration::from_secs(30)),
            )
            .mount(&osv)
            .await;
        let gh = ghsa_with(json!([])).await;
        let mut c = clients(&osv, Some(&gh));
        c.osv_budget = Duration::from_millis(300);
        let started = Instant::now();
        let r = run(&state(pool), &c, &query(Severity::High), &body(&[NPM]))
            .await
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert_eq!(r.source, CheckSource::Ghsa);
        assert_eq!(r.verdict, Verdict::Pass);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn ghsa_hit_oathed_by_stored_cve_alias(pool: PgPool) {
        let osv = osv_down().await;
        let gh = ghsa_with(json!([{
            "advisory": {"ghsaId": "GHSA-aaaa-bbbb-cccc", "severity": "HIGH"},
            "vulnerableVersionRange": "< 2.0.0",
            "firstPatchedVersion": {"identifier": "2.0.0"}
        }]))
        .await;
        sqlx::query(
            "insert into advisories (id, aliases, severity, source, cve_id) \
             values ('CVE-2026-7777', '{GHSA-aaaa-bbbb-cccc}', 'high', 'nvd', 'CVE-2026-7777')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let id = oath_on(&pool, "CVE-2026-7777").await;
        let r = run(
            &state(pool),
            &clients(&osv, Some(&gh)),
            &query(Severity::High),
            &body(&[NPM]),
        )
        .await
        .unwrap();
        assert_eq!(r.source, CheckSource::Ghsa);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].advisory, "GHSA-aaaa-bbbb-cccc");
        assert_eq!(r.findings[0].fixed.as_deref(), Some("2.0.0"));
        assert_eq!(r.findings[0].oath, Some(id));
        assert_eq!(r.verdict, Verdict::Pass);
    }

    #[test]
    fn exit_code_mapping() {
        assert_eq!(exit_code(Verdict::Pass), 0);
        assert_eq!(exit_code(Verdict::Fail), 1);
        assert_eq!(exit_code(Verdict::Unverified), 2);
    }

    #[test]
    fn default_branch_from_event_file() {
        let dir = std::env::temp_dir().join(format!("heimdall-gate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("event.json");
        std::fs::write(&file, r#"{"repository":{"default_branch":"main"}}"#).unwrap();
        assert_eq!(
            default_branch_from_event(&file).unwrap().as_deref(),
            Some("main")
        );
        std::fs::write(&file, r#"{"ref":"refs/heads/x"}"#).unwrap();
        assert_eq!(default_branch_from_event(&file).unwrap(), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn gate_route_requires_ingest_scope(pool: PgPool) {
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let read = crate::auth::create_key(&pool, &[], "viewer", Scope::Read)
            .await
            .unwrap();
        let app = crate::server::router(state(pool));
        let req = Request::builder()
            .method("POST")
            .uri("/api/v1/gate?service=api&realm=dev-k3s&branch=x&default_branch=main&fail_on=high")
            .header("authorization", format!("Bearer {read}"))
            .body(Body::from(body(&[NPM])))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn verdict_rules() {
        let f = |sev, oath| GateFinding {
            advisory: "A".into(),
            severity: sev,
            purl: NPM.into(),
            fixed: None,
            oath,
        };
        let unv = vec![DEB.to_string()];
        // An unoathed finding at fail_on beats unverified.
        assert_eq!(
            verdict(&[f(Severity::High, None)], &unv, Severity::High),
            Verdict::Fail
        );
        assert_eq!(
            verdict(&[f(Severity::High, Some(1))], &unv, Severity::High),
            Verdict::Unverified
        );
        assert_eq!(
            verdict(&[f(Severity::Medium, None)], &[], Severity::High),
            Verdict::Pass
        );
    }
}
