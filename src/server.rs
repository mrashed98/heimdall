//! The HTTP server: the router (every API route plus `/healthz` and
//! `/metrics`), the read API, and `serve`, which starts everything.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::auth::{require, Authed, Scope};
use crate::config::HeimdallConfig;
use crate::error::ApiError;
use crate::model::{FindingKind, Severity};
use crate::{auth, db, gate, ingest, meters, oath, scheduler, telemetry, AppState};

/// Fixed: the Service and probes point here.
const LISTEN: &str = "0.0.0.0:8080";

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(auth::routes())
        .merge(ingest::api::routes())
        .merge(gate::routes())
        .merge(oath::routes())
        .merge(read_routes())
        .route("/healthz", get(healthz))
        .with_state(state)
}

/// `router` plus `/metrics` (no auth: cluster-internal), rendered from
/// `metrics`.
pub fn app(state: AppState, metrics: PrometheusHandle) -> Router {
    router(state).route(
        "/metrics",
        get(move || async move {
            // Upkeep trims histogram samples; scraping is a natural moment.
            metrics.run_upkeep();
            metrics.render()
        }),
    )
}

/// Start Heimdall: config, telemetry, database, bootstrap key, declared
/// components, HTTP, then the scheduled loops. Returns after SIGTERM or
/// Ctrl-C once in-flight requests are done.
pub async fn serve(cfg_path: &Path) -> anyhow::Result<()> {
    let cfg = HeimdallConfig::load(cfg_path)?;
    // Kept until serve returns; dropping it flushes buffered spans.
    let _telemetry = telemetry::init("heimdall")?;
    let metrics = meters::install()?;

    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
    let pool = db::connect(&url).await?;
    match std::env::var("HEIMDALL_BOOTSTRAP_ADMIN_KEY") {
        Ok(key) if !key.is_empty() => auth::ensure_bootstrap(&pool, &key).await?,
        _ => tracing::info!("HEIMDALL_BOOTSTRAP_ADMIN_KEY is not set; no bootstrap key"),
    }
    crate::inventory::store::sync_declared(&pool, &cfg.declared)
        .await
        .context("syncing declared components")?;

    // A bound on every outside call, so a hung server cannot stall a loop.
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(120))
        .build()
        .context("building the http client")?;
    let state = AppState::new(pool, Arc::new(cfg), http);

    let listener = tokio::net::TcpListener::bind(LISTEN)
        .await
        .with_context(|| format!("binding {LISTEN}"))?;
    tracing::info!("listening on {LISTEN}");
    let loops = tokio::spawn(scheduler::run(state.clone()));

    // Stops accepting on the signal, then waits for in-flight requests.
    let served = axum::serve(listener, app(state, metrics))
        .with_graceful_shutdown(shutdown_signal())
        .await;
    loops.abort();
    tracing::info!("stopped");
    served.context("http server")
}

/// SIGTERM (Kubernetes) or Ctrl-C. Heimdall only runs on Unix.
async fn shutdown_signal() {
    let mut term = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("cannot listen for SIGTERM: {e}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = term.recv() => tracing::info!("SIGTERM received; shutting down"),
        _ = tokio::signal::ctrl_c() => tracing::info!("Ctrl-C received; shutting down"),
    }
}

/// 200 "ok" when the database answers, else 503.
async fn healthz(State(state): State<AppState>) -> (StatusCode, &'static str) {
    let ping = sqlx::query("SELECT 1").execute(&state.pool);
    match tokio::time::timeout(Duration::from_secs(5), ping).await {
        Ok(Ok(_)) => (StatusCode::OK, "ok"),
        Ok(Err(e)) => {
            tracing::warn!("healthz: database ping failed: {e}");
            (StatusCode::SERVICE_UNAVAILABLE, "database unavailable")
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "database timeout"),
    }
}

// ---- read API --------------------------------------------------------------

fn read_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/realms", get(realms_handler))
        .route("/api/v1/findings", get(findings_handler))
        .route("/api/v1/services", get(services_handler))
        .route("/api/v1/services/{id}/components", get(components_handler))
        .route("/api/v1/releases", get(releases_handler))
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct RealmRow {
    pub name: String,
    pub services: i64,
    pub open_findings: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingRow {
    pub id: i64,
    pub key: String,
    pub kind: FindingKind,
    pub realm: String,
    pub service: Option<String>,
    pub purl: Option<String>,
    pub ref_id: Option<String>,
    pub severity: Severity,
    pub status: String,
    pub opened_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ServiceRow {
    pub id: i64,
    pub realm: String,
    pub name: String,
    pub components: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ComponentRow {
    pub id: i64,
    pub purl: String,
    pub name_key: String,
    pub ecosystem: String,
    pub version: String,
    pub source: String,
    pub direct: bool,
    pub via_image_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ReleaseRow {
    pub id: i64,
    pub target: String,
    pub version: String,
    pub published_at: Option<DateTime<Utc>>,
    pub is_major: bool,
    pub notes_url: Option<String>,
    pub notes_class: Option<String>,
}

#[derive(Deserialize)]
struct FindingsQuery {
    realm: Option<String>,
    status: Option<String>,
    kind: Option<String>,
    min_severity: Option<String>,
    limit: Option<String>,
}

#[derive(Deserialize)]
struct RealmQuery {
    realm: Option<String>,
}

#[derive(Deserialize)]
struct ReleasesQuery {
    target: Option<String>,
    since: Option<String>,
    limit: Option<String>,
}

/// Empty query values count as absent (`?realm=`).
fn given(v: &Option<String>) -> Option<&str> {
    v.as_deref().filter(|s| !s.is_empty())
}

/// Rows a list returns: `limit`, default 500, at most 5000. Bounded so one
/// request cannot load a whole table into a 256 MB process.
fn parse_limit(v: &Option<String>) -> Result<i64, ApiError> {
    const DEFAULT: i64 = 500;
    const MAX: i64 = 5000;
    let Some(s) = given(v) else {
        return Ok(DEFAULT);
    };
    match s.parse::<i64>() {
        Ok(n) if (1..=MAX).contains(&n) => Ok(n),
        _ => Err(ApiError::BadRequest(format!(
            "limit {s:?} must be a number from 1 to {MAX}"
        ))),
    }
}

fn check_realm(cfg: &HeimdallConfig, realm: Option<&str>) -> Result<(), ApiError> {
    match realm {
        Some(r) if !cfg.realms.iter().any(|x| x == r) => {
            Err(ApiError::BadRequest(format!("unknown realm {r:?}")))
        }
        _ => Ok(()),
    }
}

fn severity_text(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Unknown => "unknown",
    }
}

async fn realms_handler(
    State(state): State<AppState>,
    authed: Authed,
) -> Result<Json<Vec<RealmRow>>, ApiError> {
    require(&authed, Scope::Read)?;
    let rows: Vec<RealmRow> = sqlx::query_as(
        "SELECT r.name, \
                (SELECT count(*) FROM services s WHERE s.realm = r.name) AS services, \
                (SELECT count(*) FROM findings f WHERE f.realm = r.name AND f.status = 'open') \
                    AS open_findings \
         FROM unnest($1::text[]) AS r(name)",
    )
    .bind(&state.cfg.realms)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn findings_handler(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<FindingsQuery>,
) -> Result<Json<Vec<FindingRow>>, ApiError> {
    require(&authed, Scope::Read)?;
    let realm = given(&q.realm);
    check_realm(&state.cfg, realm)?;
    let limit = parse_limit(&q.limit)?;
    let status = given(&q.status).unwrap_or("open");
    if status != "open" && status != "resolved" {
        return Err(ApiError::BadRequest(format!(
            "unknown status {status:?} (use open or resolved)"
        )));
    }
    let kind: Option<FindingKind> = match given(&q.kind) {
        Some(k) => Some(
            serde_json::from_value(serde_json::Value::String(k.to_string()))
                .map_err(|_| ApiError::BadRequest(format!("unknown kind {k:?}")))?,
        ),
        None => None,
    };
    let min = match given(&q.min_severity) {
        Some(s) => gate::parse_severity(s).map_err(ApiError::BadRequest)?,
        None => Severity::Low,
    };
    // Severity order is not alphabetical, so SQL gets the list to accept.
    let severities: Vec<&str> = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Unknown,
        Severity::Low,
    ]
    .into_iter()
    .filter(|s| *s >= min)
    .map(severity_text)
    .collect();
    let rows: Vec<FindingRow> = sqlx::query_as(
        "SELECT f.id, f.key, f.kind, f.realm, s.name AS service, c.purl, f.ref_id, \
                f.severity, f.status, f.opened_at, f.resolved_at, f.details \
         FROM findings f \
         LEFT JOIN services s ON s.id = f.service_id \
         LEFT JOIN components c ON c.id = f.component_id \
         WHERE f.status = $1 \
           AND ($2::text IS NULL OR f.realm = $2) \
           AND ($3::text IS NULL OR f.kind = $3) \
           AND f.severity = ANY($4) \
         ORDER BY f.opened_at DESC, f.id DESC \
         LIMIT $5",
    )
    .bind(status)
    .bind(realm)
    .bind(kind)
    .bind(&severities)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn services_handler(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<RealmQuery>,
) -> Result<Json<Vec<ServiceRow>>, ApiError> {
    require(&authed, Scope::Read)?;
    let realm = given(&q.realm);
    check_realm(&state.cfg, realm)?;
    let rows: Vec<ServiceRow> = sqlx::query_as(
        "SELECT s.id, s.realm, s.name, count(DISTINCT sc.component_id) AS components \
         FROM services s LEFT JOIN service_components sc ON sc.service_id = s.id \
         WHERE ($1::text IS NULL OR s.realm = $1) \
         GROUP BY s.id ORDER BY s.realm, s.name",
    )
    .bind(realm)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn components_handler(
    State(state): State<AppState>,
    authed: Authed,
    UrlPath(id): UrlPath<i64>,
) -> Result<Json<Vec<ComponentRow>>, ApiError> {
    require(&authed, Scope::Read)?;
    let exists: Option<i64> = sqlx::query_scalar("SELECT id FROM services WHERE id = $1")
        .bind(id)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound);
    }
    let rows: Vec<ComponentRow> = sqlx::query_as(
        "SELECT c.id, c.purl, c.name_key, c.ecosystem, c.version, sc.source, sc.direct, \
                sc.via_image_digest \
         FROM service_components sc JOIN components c ON c.id = sc.component_id \
         WHERE sc.service_id = $1 ORDER BY c.purl, sc.source",
    )
    .bind(id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

/// `since` is a date (`2026-01-31`, midnight UTC) or an RFC 3339 time.
fn parse_since(s: &str) -> Result<DateTime<Utc>, ApiError> {
    if let Ok(t) = s.parse::<DateTime<Utc>>() {
        return Ok(t);
    }
    s.parse::<NaiveDate>()
        .map(|d| d.and_time(chrono::NaiveTime::MIN).and_utc())
        .map_err(|_| ApiError::BadRequest(format!("since {s:?} is not a date or RFC 3339 time")))
}

async fn releases_handler(
    State(state): State<AppState>,
    authed: Authed,
    Query(q): Query<ReleasesQuery>,
) -> Result<Json<Vec<ReleaseRow>>, ApiError> {
    require(&authed, Scope::Read)?;
    let limit = parse_limit(&q.limit)?;
    let since = match given(&q.since) {
        Some(s) => Some(parse_since(s)?),
        None => None,
    };
    let rows: Vec<ReleaseRow> = sqlx::query_as(
        "SELECT id, target, version, published_at, is_major, notes_url, notes_class \
         FROM releases \
         WHERE ($1::text IS NULL OR target = $1) \
           AND ($2::timestamptz IS NULL OR published_at >= $2) \
         ORDER BY published_at DESC NULLS LAST, id DESC \
         LIMIT $3",
    )
    .bind(given(&q.target))
    .bind(since)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{create_key, Scope};
    use crate::meters;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn state(pool: PgPool) -> AppState {
        let cfg: crate::config::HeimdallConfig =
            serde_yaml::from_str("realms: [prod, dev]").unwrap();
        AppState::new(pool, Arc::new(cfg), reqwest::Client::new())
    }

    /// A recorder of this test's own, so parallel tests never share values.
    fn local_metrics() -> (
        metrics_exporter_prometheus::PrometheusRecorder,
        PrometheusHandle,
    ) {
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        (recorder, handle)
    }

    async fn get(app: &Router, path: &str, key: Option<&str>) -> (StatusCode, String) {
        let mut req = Request::builder().uri(path);
        if let Some(k) = key {
            req = req.header("authorization", format!("Bearer {k}"));
        }
        let resp = app
            .clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn seed_finding(pool: &PgPool, realm: &str, service: &str, key: &str, severity: &str) {
        let svc = crate::inventory::store::upsert_service(pool, realm, service)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO findings (key, kind, realm, service_id, ref_id, severity) \
             VALUES ($1, 'vuln', $2, $3, $1, $4)",
        )
        .bind(key)
        .bind(realm)
        .bind(svc)
        .bind(severity)
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn metrics_endpoint_exposes_findings_gauge(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "vuln|a", "high").await;
        let st = state(pool);
        let (recorder, handle) = local_metrics();
        let g = meters::gauges(&st.pool, &st.cfg).await.unwrap();
        metrics::with_local_recorder(&recorder, || meters::publish(&g, None));

        let app = app(st, handle);
        // No key: /metrics is cluster-internal and unauthenticated.
        let (status, body) = get(&app, "/metrics", None).await;
        assert_eq!(status, StatusCode::OK);
        let line = body
            .lines()
            .find(|l| l.starts_with("heimdall_findings_open{"))
            .unwrap_or_else(|| panic!("no findings gauge in:\n{body}"));
        assert!(line.contains("realm=\"prod\""), "{line}");
        assert!(line.contains("service=\"api\""), "{line}");
        assert!(line.contains("kind=\"vuln\""), "{line}");
        assert!(line.ends_with("severity=\"high\"} 1"), "{line}");
        assert!(body.contains("heimdall_outbox_pending 0"), "{body}");
        assert!(
            body.contains("heimdall_oaths_active{kind=\"snooze\"} 0"),
            "{body}"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn findings_filter_min_severity(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "vuln|crit", "critical").await;
        seed_finding(&pool, "prod", "api", "vuln|high", "high").await;
        seed_finding(&pool, "prod", "api", "vuln|med", "medium").await;
        seed_finding(&pool, "prod", "api", "vuln|unk", "unknown").await;
        seed_finding(&pool, "prod", "api", "vuln|low", "low").await;
        seed_finding(&pool, "dev", "api", "vuln|dev-crit", "critical").await;
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let (_, handle) = local_metrics();
        let app = app(state(pool), handle);

        let (status, body) = get(
            &app,
            "/api/v1/findings?realm=prod&min_severity=high",
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        let mut keys: Vec<&str> = rows.iter().map(|r| r["key"].as_str().unwrap()).collect();
        keys.sort();
        assert_eq!(keys, vec!["vuln|crit", "vuln|high"]);
        assert_eq!(rows[0]["service"], "api");

        // Unknown ranks above low: min_severity=unknown leaves out only low.
        let (_, body) = get(
            &app,
            "/api/v1/findings?realm=prod&min_severity=unknown",
            Some(&key),
        )
        .await;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.len(), 4);

        for bad in [
            "/api/v1/findings?min_severity=huge",
            "/api/v1/findings?status=closed",
            "/api/v1/findings?kind=nope",
            "/api/v1/findings?realm=elsewhere",
        ] {
            let (status, _) = get(&app, bad, Some(&key)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
        }
        let (status, _) = get(&app, "/api/v1/findings", None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn healthz_ok(pool: PgPool) {
        let (_, handle) = local_metrics();
        let app = app(state(pool.clone()), handle);
        let (status, body) = get(&app, "/healthz", None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");

        // A closed pool cannot be pinged: 503.
        pool.close().await;
        let (status, _) = get(&app, "/healthz", None).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn read_api_limit(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "vuln|1", "high").await;
        seed_finding(&pool, "prod", "api", "vuln|2", "high").await;
        seed_finding(&pool, "prod", "api", "vuln|3", "high").await;
        for (v, days) in [("1.0.0", 30), ("2.0.0", 20), ("3.0.0", 10)] {
            sqlx::query(
                "INSERT INTO releases (target, version, published_at) \
                 VALUES ('x', $1, now() - make_interval(days => $2))",
            )
            .bind(v)
            .bind(days)
            .execute(&pool)
            .await
            .unwrap();
        }
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let (_, handle) = local_metrics();
        let app = app(state(pool), handle);

        // Newest first, cut at the limit.
        let (status, body) = get(&app, "/api/v1/findings?limit=2", Some(&key)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        let keys: Vec<&str> = rows.iter().map(|r| r["key"].as_str().unwrap()).collect();
        assert_eq!(keys, vec!["vuln|3", "vuln|2"]);

        let (status, body) = get(&app, "/api/v1/releases?limit=1", Some(&key)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["version"], "3.0.0");

        let (_, body) = get(&app, "/api/v1/findings?limit=5000", Some(&key)).await;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.len(), 3);

        for path in ["/api/v1/findings", "/api/v1/releases"] {
            for bad in ["0", "5001", "-1", "many"] {
                let (status, _) = get(&app, &format!("{path}?limit={bad}"), Some(&key)).await;
                assert_eq!(status, StatusCode::BAD_REQUEST, "{path} limit={bad}");
            }
        }
    }
}
