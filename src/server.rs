//! The HTTP server: the router (every API route plus `/healthz` and
//! `/metrics`), the read API, and `serve`, which starts everything.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, NaiveDate, Utc};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::config::HeimdallConfig;
use crate::error::ApiError;
use crate::local_auth::Principal;
use crate::model::{FindingKind, Severity};
use crate::{auth, db, gate, ingest, meters, oath, scheduler, telemetry, AppState};

/// Fixed: the Service and probes point here.
const LISTEN: &str = "0.0.0.0:8080";

pub fn router(state: AppState) -> Router {
    Router::new()
        .merge(auth::routes())
        .merge(crate::admin::routes())
        .merge(crate::local_auth::routes())
        .merge(crate::oidc::routes())
        .merge(ingest::api::routes())
        .merge(gate::routes())
        .merge(oath::routes())
        .merge(read_routes())
        .route("/healthz", get(healthz))
        .fallback(ui_fallback)
        .with_state(state)
}

include!(concat!(env!("OUT_DIR"), "/ui_embed.rs"));

async fn ui_fallback(method: Method, uri: Uri) -> Response {
    let path = uri.path();
    // Reserved server namespaces must never turn missing routes into HTML.
    if ["/api", "/auth", "/healthz", "/readyz", "/metrics"]
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
    {
        return crate::error::ApiError::NotFound.into_response();
    }
    if method != Method::GET {
        return StatusCode::NOT_FOUND.into_response();
    }
    let requested = path.trim_start_matches('/');
    let (name, asset) = UiAssets::get(requested)
        .map(|asset| (requested, asset))
        .or_else(|| UiAssets::get("index.html").map(|asset| ("index.html", asset)))
        .expect("build script always provides index.html");
    let cache = if name.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mime = mime_guess::from_path(name).first_or_octet_stream();
    let mut response = (
        [
            (header::CONTENT_TYPE, mime.as_ref()),
            (header::CACHE_CONTROL, cache),
        ],
        asset.data.into_owned(),
    )
        .into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'".parse().unwrap());
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    headers.insert(header::REFERRER_POLICY, "same-origin".parse().unwrap());
    response
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
    if let Some(oidc) = cfg.auth.as_ref().and_then(|a| a.oidc.as_ref()) {
        std::env::var(&oidc.client_secret_env).with_context(|| {
            format!(
                "missing OIDC client secret environment variable {}",
                oidc.client_secret_env
            )
        })?;
    }
    // Kept until serve returns; dropping it flushes buffered spans.
    let _telemetry = telemetry::init("heimdall")?;
    log_auth_configuration(&cfg);
    let metrics = meters::install()?;

    let url = std::env::var("DATABASE_URL").context("DATABASE_URL is not set")?;
    let pool = db::connect(&url).await?;
    let bootstrap = std::env::var("HEIMDALL_BOOTSTRAP_ADMIN_KEY").ok();
    auth::sync_bootstrap(&pool, bootstrap.as_deref()).await?;
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
    let served = axum::serve(
        listener,
        app(state, metrics).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await;
    loops.abort();
    tracing::info!("stopped");
    served.context("http server")
}

fn log_auth_configuration(cfg: &HeimdallConfig) {
    if let Some(auth) = &cfg.auth {
        if (auth.local.enabled || auth.oidc.is_some()) && auth.trusted_proxies.is_empty() {
            tracing::warn!("auth.trusted_proxies is empty: behind an ingress or other proxy, all clients share the proxy IP for throttling and rate limits; set auth.trusted_proxies to trusted proxy CIDRs");
        }
        if auth
            .oidc
            .as_ref()
            .and_then(|oidc| oidc.scopes.as_ref())
            .is_some_and(|scopes| !scopes.iter().any(|scope| scope == "openid"))
        {
            tracing::info!("auth.oidc.scopes omits openid; adding it automatically");
        }
    }
}

#[cfg(test)]
mod auth_startup_log_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::prelude::*;

    #[derive(Clone)]
    struct Writer(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Writer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    fn logs(yaml: &str) -> String {
        let cfg = HeimdallConfig::from_yaml(yaml).unwrap();
        let output = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer(output.clone());
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .without_time()
                .with_writer(move || writer.clone()),
        );
        tracing::subscriber::with_default(subscriber, || log_auth_configuration(&cfg));
        let bytes = output.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    }
    #[test]
    fn warns_once_for_enabled_signin_without_trusted_proxies() {
        let local =
            "realms: [prod]\nauth: {public_url: 'http://localhost', local: {enabled: true}}";
        let output = logs(local);
        assert_eq!(output.matches("WARN").count(), 1);
        assert!(
            output.contains("throttling and rate limits")
                && output.contains("auth.trusted_proxies")
        );
        let oidc = "realms: [prod]\nauth:\n  public_url: http://localhost\n  oidc: {issuer: 'https://example.com', client_id: x, client_secret_env: SECRET, scopes: [profile]}\n";
        let output = logs(oidc);
        assert_eq!(output.matches("WARN").count(), 1);
        assert_eq!(output.matches("adding it automatically").count(), 1);
        assert!(!logs("realms: [prod]\n").contains("WARN"));
        assert!(!logs("realms: [prod]\nauth: {public_url: 'http://localhost'}\n").contains("WARN"));
        assert!(!logs("realms: [prod]\nauth: {public_url: 'http://localhost', local: {enabled: true}, trusted_proxies: ['10.0.0.0/8']}\n").contains("WARN"));
    }
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
        .route("/api/v1/status", get(status_handler))
        .route("/api/v1/findings", get(findings_handler))
        .route("/api/v1/findings/{id}", get(finding_detail_handler))
        .route("/api/v1/services", get(services_handler))
        .route("/api/v1/services/{id}/components", get(components_handler))
        .route("/api/v1/releases", get(releases_handler))
        .merge(ui_data_routes())
}

include!("ui_data.rs");

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
    #[sqlx(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_name: Option<String>,
    #[sqlx(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub component_version: Option<String>,
    /// EPSS score and percentile (0 to 1) of the finding's CVE; UI path only.
    #[sqlx(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
    #[sqlx(default)]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epss_percentile: Option<f32>,
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
    realms: Option<String>,
    view_status: Option<String>,
    status: Option<String>,
    kind: Option<String>,
    min_severity: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
    severity: Option<String>,
    service: Option<String>,
    search: Option<String>,
    has_fix: Option<bool>,
    sort: Option<String>,
    order: Option<String>,
    ui: Option<bool>,
}

#[derive(Deserialize)]
struct RealmQuery {
    realm: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
}

#[derive(Deserialize)]
struct ReleasesQuery {
    target: Option<String>,
    since: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
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

/// Zero-based position within a list. Empty values retain the default.
fn parse_offset(v: &Option<String>) -> Result<i64, ApiError> {
    let Some(s) = given(v) else {
        return Ok(0);
    };
    match s.parse::<i64>() {
        Ok(n) if n >= 0 => Ok(n),
        _ => Err(ApiError::BadRequest(format!(
            "offset {s:?} must be a non-negative integer"
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

#[derive(Deserialize)]
struct StatusQuery {
    realms: Option<String>,
}

#[derive(Serialize, FromRow)]
struct SeverityCount {
    realm: String,
    severity: String,
    count: i64,
}
#[derive(Serialize, FromRow)]
struct RiskRow {
    realm: String,
    service: String,
    critical: i64,
    high: i64,
    medium: i64,
    risk: i64,
}
#[derive(Serialize, FromRow)]
struct EolRow {
    realm: String,
    service: Option<String>,
    ref_id: Option<String>,
    details: serde_json::Value,
}
#[derive(Serialize)]
struct OverviewStatus {
    severity: Vec<SeverityCount>,
    fix_available: i64,
    services: Vec<RiskRow>,
    eol: Vec<EolRow>,
    sync: std::collections::BTreeMap<String, Option<String>>,
}

async fn status_handler(
    State(state): State<AppState>,
    authed: Principal,
    Query(q): Query<StatusQuery>,
) -> Result<Json<OverviewStatus>, ApiError> {
    authed.require_read()?;
    let allowed = authed.readable_realms(&state.cfg.realms);
    let selected: Vec<String> = match given(&q.realms) {
        Some(value) => {
            let mut selected = Vec::new();
            for realm in value.split(',') {
                check_realm(&state.cfg, Some(realm))?;
                if allowed.iter().any(|r| r == realm) && !selected.iter().any(|r| r == realm) {
                    selected.push(realm.to_string());
                }
            }
            selected
        }
        None => allowed,
    };
    let severity = sqlx::query_as::<_, SeverityCount>("SELECT r.realm, v.severity, count(f.id) AS count FROM unnest($1::text[]) AS r(realm) CROSS JOIN unnest(ARRAY['critical','high','medium','low','unknown']) AS v(severity) LEFT JOIN findings f ON f.realm=r.realm AND f.severity=v.severity AND f.status='open' GROUP BY r.realm, v.severity ORDER BY r.realm, v.severity")
        .bind(&selected).fetch_all(&state.pool).await?;
    let fix_available = sqlx::query_scalar::<_, i64>("SELECT count(*) FROM findings WHERE status='open' AND realm = ANY($1) AND (kind='fixavailable' OR (details->'advice' IS NOT NULL AND details->'advice' <> 'null'::jsonb))")
        .bind(&selected).fetch_one(&state.pool).await?;
    let services = sqlx::query_as::<_, RiskRow>("SELECT f.realm, s.name AS service, count(*) FILTER (WHERE f.severity='critical') AS critical, count(*) FILTER (WHERE f.severity='high') AS high, count(*) FILTER (WHERE f.severity='medium') AS medium, (count(*) FILTER (WHERE f.severity='critical') * 10 + count(*) FILTER (WHERE f.severity='high') * 3 + count(*) FILTER (WHERE f.severity='medium')) AS risk FROM findings f JOIN services s ON s.id=f.service_id WHERE f.status='open' AND f.realm = ANY($1) GROUP BY f.realm, s.id ORDER BY risk DESC, f.realm, s.name LIMIT 10")
        .bind(&selected).fetch_all(&state.pool).await?;
    let eol = sqlx::query_as::<_, EolRow>("SELECT f.realm, s.name AS service, f.ref_id, f.details FROM findings f LEFT JOIN services s ON s.id=f.service_id WHERE f.status='open' AND f.kind='eol' AND f.realm = ANY($1) ORDER BY f.opened_at DESC, f.id DESC LIMIT 10")
        .bind(&selected).fetch_all(&state.pool).await?;
    let entries: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM kv WHERE key = ANY($1)")
            .bind([
                "sync|osv",
                "sync|nvd",
                "sync|k8s",
                "sync|epss",
                "sync|sight",
            ])
            .fetch_all(&state.pool)
            .await?;
    let entries: std::collections::HashMap<_, _> = entries.into_iter().collect();
    let mut sync = std::collections::BTreeMap::new();
    for feed in ["osv", "nvd", "k8s", "epss", "sight"] {
        let visible = feed != "sight"
            || state
                .cfg
                .sight_realm()
                .is_some_and(|r| selected.iter().any(|s| s == r));
        sync.insert(
            feed.to_string(),
            if visible {
                entries.get(&format!("sync|{feed}")).cloned()
            } else {
                None
            },
        );
    }
    Ok(Json(OverviewStatus {
        severity,
        fix_available,
        services,
        eol,
        sync,
    }))
}

async fn realms_handler(
    State(state): State<AppState>,
    authed: Principal,
) -> Result<Json<Vec<RealmRow>>, ApiError> {
    authed.require_read()?;
    let rows: Vec<RealmRow> = sqlx::query_as(
        "SELECT r.name, \
                (SELECT count(*) FROM services s WHERE s.realm = r.name) AS services, \
                (SELECT count(*) FROM findings f WHERE f.realm = r.name AND f.status = 'open') \
                    AS open_findings \
         FROM unnest($1::text[]) AS r(name)",
    )
    .bind(authed.readable_realms(&state.cfg.realms))
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn findings_handler(
    State(state): State<AppState>,
    authed: Principal,
    Query(q): Query<FindingsQuery>,
) -> Result<Json<Vec<FindingRow>>, ApiError> {
    authed.require_read()?;
    let realm = given(&q.realm);
    check_realm(&state.cfg, realm)?;
    let limit = parse_limit(&q.limit)?;
    let offset = parse_offset(&q.offset)?;
    let status = given(&q.status).unwrap_or("open");
    if status != "open" && status != "resolved" {
        return Err(ApiError::BadRequest(format!(
            "unknown status {status:?} (use open or resolved)"
        )));
    }
    let selected = match given(&q.realms) {
        Some(value) => {
            let mut realms = Vec::new();
            for name in value.split(',') {
                check_realm(&state.cfg, Some(name))?;
                if authed.can("viewer", name) {
                    realms.push(name.to_owned());
                }
            }
            Some(realms)
        }
        None => None,
    };
    let view_status = given(&q.view_status);
    if view_status.is_some_and(|s| !["open", "snoozed", "ignored", "resolved"].contains(&s)) {
        return Err(ApiError::BadRequest("unknown view status".into()));
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
    let severity = match given(&q.severity) {
        Some(s) => Some(severity_text(
            gate::parse_severity(s).map_err(ApiError::BadRequest)?,
        )),
        None => None,
    };
    let sort = match given(&q.sort).unwrap_or("opened_at") {
        "opened_at" => "f.opened_at",
        "severity" => "CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END",
        "kind" => "f.kind",
        "realm" => "f.realm",
        "service" => "s.name",
        "advisory" => "f.ref_id",
        "epss" => "ep.score",
        _ => return Err(ApiError::BadRequest("unknown sort field".into())),
    };
    let direction = match given(&q.order).unwrap_or("desc") {
        "asc" => "ASC",
        "desc" => "DESC",
        _ => return Err(ApiError::BadRequest("unknown sort order".into())),
    };
    if authed.kind == "key"
        && q.offset.is_none()
        && q.realms.is_none()
        && q.view_status.is_none()
        && q.severity.is_none()
        && q.service.is_none()
        && q.search.is_none()
        && q.has_fix.is_none()
        && q.sort.is_none()
        && q.order.is_none()
        && !q.ui.unwrap_or(false)
    {
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
        return Ok(Json(rows));
    }
    // Only allowlisted SQL fragments are interpolated; all data is bound below.
    let joins = if view_status.is_some() || given(&q.search).is_some() {
        "LEFT JOIN advisories a ON a.id = f.ref_id LEFT JOIN LATERAL (SELECT o.kind FROM oaths o WHERE (o.advisory_id = f.ref_id OR o.advisory_id = ANY(a.aliases) OR EXISTS (SELECT 1 FROM advisories oa WHERE oa.id = o.advisory_id AND f.ref_id = ANY(oa.aliases))) AND o.name_key = c.name_key AND o.service_name = s.name AND (o.realm IS NULL OR o.realm = f.realm) AND o.status = 'active' AND COALESCE(o.expires_at, o.review_at) > now() ORDER BY o.id LIMIT 1) active_oath ON true"
    } else {
        ""
    };
    // The CVE is the advisory's, or the ref itself (Kubernetes feed, NVD).
    let (epss_cols, epss_join) = if q.ui.unwrap_or(false) || given(&q.sort) == Some("epss") {
        (
            ", ep.score AS epss, ep.percentile AS epss_percentile",
            "LEFT JOIN LATERAL (SELECT e.score, e.percentile FROM epss e WHERE e.cve_id = COALESCE((SELECT ea.cve_id FROM advisories ea WHERE ea.id = f.ref_id), f.ref_id)) ep ON true",
        )
    } else {
        ("", "")
    };
    let view_filter = if view_status.is_some() {
        "AND ($14::text = 'resolved' OR CASE WHEN $14 = 'open' THEN active_oath.kind IS NULL ELSE active_oath.kind = CASE $14 WHEN 'snoozed' THEN 'snooze' ELSE 'ignore' END END)"
    } else {
        ""
    };
    let search_filter = if given(&q.search).is_some() {
        "AND (f.ref_id ILIKE '%' || $11 || '%' OR c.purl ILIKE '%' || $11 || '%' OR EXISTS (SELECT 1 FROM unnest(a.aliases) alias WHERE alias ILIKE '%' || $11 || '%'))"
    } else {
        "AND $11::text IS NULL"
    };
    let secondary = if q.ui.unwrap_or(false) {
        "f.opened_at DESC, "
    } else {
        ""
    };
    let sql = format!(
        "SELECT f.id, f.key, f.kind, f.realm, s.name AS service, c.purl, f.ref_id, \
                f.severity, f.status, f.opened_at, f.resolved_at, f.details, \
                CASE WHEN $15 THEN c.version END AS component_version{epss_cols} \
         FROM findings f \
         LEFT JOIN services s ON s.id = f.service_id \
         LEFT JOIN components c ON c.id = f.component_id \
         {joins} {epss_join} \
         WHERE f.status = CASE WHEN $14::text = 'resolved' THEN 'resolved' WHEN $14::text IS NOT NULL THEN 'open' ELSE $1 END \
           AND ($13::text[] IS NULL OR f.realm = ANY($13)) \
           {view_filter} \
           AND ($2::text IS NULL OR f.realm = $2) \
           AND ($3::text IS NULL OR f.kind = $3) \
           AND f.severity = ANY($4) \
           AND ($7 OR f.realm = ANY($8)) \
           AND ($9::text IS NULL OR f.severity = $9) \
           AND ($10::text IS NULL OR s.name = $10) \
           {search_filter} \
           AND ($12::bool IS NULL OR (f.details->'advice' IS NOT NULL AND f.details->'advice' <> 'null'::jsonb) = $12) \
         ORDER BY {sort} {direction} NULLS LAST, {secondary}f.id DESC \
         LIMIT $5 OFFSET $6"
    );
    let mut rows: Vec<FindingRow> = sqlx::query_as(sqlx::AssertSqlSafe(sql.as_str()))
        .bind(status)
        .bind(realm)
        .bind(kind)
        .bind(&severities)
        .bind(limit)
        .bind(offset)
        .bind(authed.kind == "key")
        .bind(authed.readable_realms(&state.cfg.realms))
        .bind(severity)
        .bind(given(&q.service))
        .bind(given(&q.search))
        .bind(q.has_fix)
        .bind(selected)
        .bind(view_status)
        .bind(q.ui.unwrap_or(false))
        .fetch_all(&state.pool)
        .await?;
    if q.ui.unwrap_or(false) {
        for row in &mut rows {
            row.component_name = row.purl.as_deref().and_then(|purl| {
                purl.parse::<packageurl::PackageUrl>().ok().map(|package| {
                    match package.namespace() {
                        Some(namespace) => format!("{namespace}/{}", package.name()),
                        None => package.name().to_owned(),
                    }
                })
            });
        }
    }
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct FindingDetailQuery {
    affected_offset: Option<String>,
    oaths_offset: Option<String>,
}

#[derive(FromRow)]
struct FindingDetailRow {
    realm: String,
    service: Option<String>,
    purl: Option<String>,
    version: Option<String>,
    name_key: Option<String>,
    summary: Option<String>,
    fixed: Option<serde_json::Value>,
    scores: Option<serde_json::Value>,
    aliases: Option<Vec<String>>,
    epss: Option<f32>,
    epss_percentile: Option<f32>,
}

async fn finding_detail_handler(
    State(state): State<AppState>,
    authed: Principal,
    UrlPath(id): UrlPath<i64>,
    Query(q): Query<FindingDetailQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    authed.require_read()?;
    let affected_offset = parse_offset(&q.affected_offset)?;
    let oaths_offset = parse_offset(&q.oaths_offset)?;
    let row: Option<FindingDetailRow> = sqlx::query_as(
        "SELECT f.realm, s.name AS service, c.purl, c.version, c.name_key, a.summary, a.fixed, a.scores, a.aliases, e.score AS epss, e.percentile AS epss_percentile FROM findings f LEFT JOIN services s ON s.id=f.service_id LEFT JOIN components c ON c.id=f.component_id LEFT JOIN advisories a ON a.id=f.ref_id LEFT JOIN epss e ON e.cve_id=COALESCE(a.cve_id, f.ref_id) WHERE f.id=$1 AND ($2 OR f.realm = ANY($3))"
    ).bind(id).bind(authed.kind == "key").bind(authed.readable_realms(&state.cfg.realms)).fetch_optional(&state.pool).await?;
    let FindingDetailRow {
        realm,
        service,
        purl,
        version,
        name_key,
        summary,
        fixed,
        scores,
        aliases,
        epss,
        epss_percentile,
    } = row.ok_or(ApiError::NotFound)?;
    let ref_id: Option<String> = sqlx::query_scalar("SELECT ref_id FROM findings WHERE id=$1")
        .bind(id)
        .fetch_one(&state.pool)
        .await?;
    let affected: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as("SELECT DISTINCT s.name, sc.via_image_digest, i.image_ref FROM service_components sc JOIN services s ON s.id=sc.service_id JOIN components c ON c.id=sc.component_id LEFT JOIN image_sboms i ON i.digest=sc.via_image_digest WHERE s.realm=$1 AND c.purl=$2 ORDER BY s.name, sc.via_image_digest, i.image_ref LIMIT 25 OFFSET $3")
        .bind(&realm).bind(&purl).bind(affected_offset).fetch_all(&state.pool).await?;
    let history: Vec<oath::Oath> = sqlx::query_as("SELECT id, advisory_id, name_key, service_name, realm, kind, reason, version_at_creation, expires_at, review_at, created_by, created_at, status FROM oaths WHERE (advisory_id=$1 OR advisory_id IN (SELECT unnest(aliases) FROM advisories WHERE id=$1) OR $1 IN (SELECT unnest(a.aliases) FROM advisories a WHERE a.id=oaths.advisory_id)) AND name_key=$2 AND service_name=$3 AND (realm=$4 OR realm IS NULL) ORDER BY created_at DESC, id DESC LIMIT 25 OFFSET $5")
        .bind(&ref_id).bind(&name_key).bind(&service).bind(&realm).bind(oaths_offset).fetch_all(&state.pool).await?;
    Ok(Json(
        serde_json::json!({"summary": summary, "aliases": aliases.unwrap_or_default(), "scores": scores, "epss": epss, "epss_percentile": epss_percentile, "fixed": fixed, "name_key": name_key, "version": version, "purl": purl, "affected": affected.into_iter().map(|(service,digest,image)| serde_json::json!({"service":service,"digest":digest,"image":image})).collect::<Vec<_>>(), "oaths": history}),
    ))
}

async fn services_handler(
    State(state): State<AppState>,
    authed: Principal,
    Query(q): Query<RealmQuery>,
) -> Result<Json<Vec<ServiceRow>>, ApiError> {
    authed.require_read()?;
    let realm = given(&q.realm);
    check_realm(&state.cfg, realm)?;
    let rows: Vec<ServiceRow> = sqlx::query_as(
        "SELECT s.id, s.realm, s.name, count(DISTINCT sc.component_id) AS components \
         FROM services s LEFT JOIN service_components sc ON sc.service_id = s.id \
         WHERE ($1::text IS NULL OR s.realm = $1) AND ($2 OR s.realm = ANY($3)) \
         GROUP BY s.id ORDER BY s.realm, s.name, s.id LIMIT $4 OFFSET $5",
    )
    .bind(realm)
    .bind(authed.kind == "key")
    .bind(authed.readable_realms(&state.cfg.realms))
    .bind(match given(&q.limit) {
        Some(_) => Some(parse_limit(&q.limit)?),
        None => None,
    })
    .bind(parse_offset(&q.offset)?)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(rows))
}

async fn components_handler(
    State(state): State<AppState>,
    authed: Principal,
    UrlPath(id): UrlPath<i64>,
) -> Result<Json<Vec<ComponentRow>>, ApiError> {
    authed.require_read()?;
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT id FROM services WHERE id = $1 AND ($2 OR realm = ANY($3))")
            .bind(id)
            .bind(authed.kind == "key")
            .bind(authed.readable_realms(&state.cfg.realms))
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
    authed: Principal,
    Query(q): Query<ReleasesQuery>,
) -> Result<Json<Vec<ReleaseRow>>, ApiError> {
    authed.require_read()?;
    // Watch targets are global, so any grant permits reading releases.
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
         LIMIT $3 OFFSET $4",
    )
    .bind(given(&q.target))
    .bind(since)
    .bind(limit)
    .bind(parse_offset(&q.offset)?)
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
            serde_saphyr::from_str("realms: [prod, dev]").unwrap();
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
    async fn session_read_access_is_realm_scoped(pool: PgPool) {
        use sha2::{Digest, Sha256};
        seed_finding(&pool, "a", "one", "finding-a", "high").await;
        seed_finding(&pool, "b", "two", "finding-b", "high").await;
        let service_b: i64 = sqlx::query_scalar("SELECT id FROM services WHERE realm='b'")
            .fetch_one(&pool)
            .await
            .unwrap();
        for realm in [Some("a"), Some("b"), None] {
            sqlx::query("INSERT INTO oaths(advisory_id,name_key,service_name,realm,kind,reason,version_at_creation,created_by) VALUES ('CVE-test','pkg','one',$1,'ignore','test','1','alice')")
                .bind(realm).execute(&pool).await.unwrap();
        }
        sqlx::query("INSERT INTO releases(target,version) VALUES ('global','1')")
            .execute(&pool)
            .await
            .unwrap();
        let user: i64 = sqlx::query_scalar(
            "INSERT INTO users(username,password_hash) VALUES ('alice','test') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO sessions(id_hash,user_id,csrf_token,expires_at) VALUES ($1,$2,'csrf',now()+interval '1 day')")
            .bind(Sha256::digest(b"test-session").to_vec()).bind(user).execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO user_grants(user_id,role,realm) VALUES ($1,'viewer','a')")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let cfg = HeimdallConfig::from_yaml(
            "realms: [a, b]\nauth: {public_url: 'http://localhost:8080'}",
        )
        .unwrap();
        let app = router(AppState::with_grant_cache_ttl(
            pool.clone(),
            Arc::new(cfg),
            reqwest::Client::new(),
            Duration::ZERO,
        ));
        let get_session = |path: String| {
            let app = app.clone();
            async move {
                let response = app
                    .oneshot(
                        Request::builder()
                            .uri(path)
                            .header("cookie", "heimdall_session=test-session")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                let status = response.status();
                let body = response.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                )
            }
        };
        for (path, count) in [
            ("/api/v1/findings", 1),
            ("/api/v1/services", 1),
            ("/api/v1/realms", 1),
            ("/api/v1/oaths", 2),
            ("/api/v1/releases", 1),
        ] {
            let (status, body) = get_session(path.into()).await;
            assert_eq!(status, StatusCode::OK, "{path}: {body}");
            assert_eq!(body.as_array().unwrap().len(), count, "{path}: {body}");
            if path != "/api/v1/releases" {
                assert!(
                    !body.to_string().contains("finding-b") && !body.to_string().contains("\"b\""),
                    "{path}: {body}"
                );
            }
        }
        let (status, overview) = get_session("/api/v1/status".into()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(overview["severity"].as_array().unwrap().len(), 5);
        assert_eq!(overview["severity"][0]["realm"], "a");
        assert_eq!(overview["services"][0]["risk"], 3);
        let (_, filtered) = get_session("/api/v1/status?realms=b".into()).await;
        assert!(filtered["severity"].as_array().unwrap().is_empty());
        assert!(filtered["services"].as_array().unwrap().is_empty());
        for path in [
            "/api/v1/ui/services?realms=b",
            "/api/v1/ui/oaths?realms=b",
            "/api/v1/ui/releases?realms=b",
        ] {
            let (status, rows) = get_session(path.into()).await;
            assert_eq!(status, StatusCode::OK, "{path}: {rows}");
            assert!(rows.as_array().unwrap().is_empty(), "{path}: {rows}");
        }
        assert_eq!(
            get_session(format!("/api/v1/ui/services/{service_b}/components"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_session(format!("/api/v1/services/{service_b}/components"))
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            get_session("/api/v1/findings?realm=b".into())
                .await
                .1
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let finding_b: i64 = sqlx::query_scalar("SELECT id FROM findings WHERE realm='b'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            get_session(format!("/api/v1/findings/{finding_b}")).await.0,
            StatusCode::NOT_FOUND
        );
        assert!(
            get_session("/api/v1/findings?realms=b&view_status=open".into())
                .await
                .1
                .as_array()
                .unwrap()
                .is_empty()
        );
        sqlx::query("UPDATE user_grants SET realm='*' WHERE user_id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        for (path, count) in [
            ("/api/v1/findings", 2),
            ("/api/v1/services", 2),
            ("/api/v1/realms", 2),
            ("/api/v1/oaths", 3),
        ] {
            let (status, body) = get_session(path.into()).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_array().unwrap().len(), count, "{path}: {body}");
        }
        assert_eq!(
            get_session(format!("/api/v1/services/{service_b}/components"))
                .await
                .0,
            StatusCode::OK
        );
        sqlx::query("DELETE FROM user_grants WHERE user_id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        for path in [
            "/api/v1/findings",
            "/api/v1/services",
            "/api/v1/realms",
            "/api/v1/oaths",
            "/api/v1/releases",
            "/api/v1/status",
            &format!("/api/v1/services/{service_b}/components"),
        ] {
            let (status, body) = get_session(path.into()).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert_eq!(body, serde_json::json!({"error":"no_access"}));
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn data_page_projections_page_filter_and_sort(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "a", "critical").await;
        seed_finding(&pool, "prod", "api", "b", "high").await;
        seed_finding(&pool, "dev", "worker", "c", "low").await;
        let id: i64 = sqlx::query_scalar("SELECT id FROM services WHERE name='api'")
            .fetch_one(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO components(purl,name_key,ecosystem,version) VALUES ('pkg:generic/test@1','pkg:generic/test','generic','1')").execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO image_sboms(digest,image_ref) VALUES ('sha256:abc','example/image:1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO service_components(service_id,component_id,source,via_image_digest) SELECT $1,id,'cluster','sha256:abc' FROM components").bind(id).execute(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO releases(target,version,notes_class) VALUES ('widget','2','gave_up')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO findings(key,kind,realm,ref_id,severity,details) VALUES ('rel','majorrelease','prod','2','high','{\"target\":\"widget\",\"version\":\"2\"}'),('eol','eol','dev','1','high','{\"target\":\"widget\"}')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oaths(advisory_id,name_key,service_name,realm,kind,reason,version_at_creation,created_by,expires_at,status) VALUES ('CVE-1','pkg','api','prod','snooze','reason','1','alice',now()+interval '2 days','active'),('CVE-2','pkg','api','prod','snooze','reason','1','alice',now()-interval '2 days','active'),('CVE-3','pkg','api','dev','snooze','reason','1','alice',now()+interval '2 days','active')").execute(&pool).await.unwrap();
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = router(state(pool));
        let request = |path: String| {
            let app = &app;
            let key = &key;
            async move {
                let (status, body) = get(app, &path, Some(key)).await;
                assert_eq!(status, StatusCode::OK, "{path}: {body}");
                serde_json::from_str::<serde_json::Value>(&body).unwrap()
            }
        };
        let services =
            request("/api/v1/ui/services?realms=prod&limit=1&sort=critical&order=desc".into())
                .await;
        assert_eq!(services[0]["critical"], 1);
        assert_eq!(services[0]["high"], 1);
        assert!(
            request("/api/v1/ui/services?realms=prod&limit=1&offset=1".into())
                .await
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            request(format!("/api/v1/ui/services/{id}/info")).await[0]["name"],
            "api"
        );
        assert_eq!(
            request(format!("/api/v1/ui/services/{id}/components?sort=purl")).await[0]["source"],
            "cluster"
        );
        assert_eq!(
            request(format!("/api/v1/ui/services/{id}/images?sort=image")).await[0]["digest"],
            "sha256:abc"
        );
        assert_eq!(
            request(format!(
                "/api/v1/ui/services/{id}/findings?sort=severity&limit=1"
            ))
            .await[0]["severity"],
            "critical"
        );
        let releases = request("/api/v1/ui/releases?realms=prod&kind=majorrelease".into()).await;
        assert_eq!(releases[0]["notes_class"], "gave_up");
        assert!(request("/api/v1/ui/releases?realms=prod&kind=eol".into())
            .await
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            request("/api/v1/ui/oaths?realms=prod&tab=expiring".into())
                .await
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            request("/api/v1/ui/oaths?realms=prod&tab=past".into()).await[0]["advisory_id"],
            "CVE-2"
        );
        assert_eq!(
            get(
                &app,
                "/api/v1/ui/oaths?sort=invalid%3BSELECT%201",
                Some(&key)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get(&app, "/api/v1/ui/services", None).await.0,
            StatusCode::UNAUTHORIZED
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn overview_counts_ranks_and_exposes_recorded_sync(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "crit", "critical").await;
        seed_finding(&pool, "prod", "api", "high", "high").await;
        seed_finding(&pool, "prod", "worker", "medium", "medium").await;
        sqlx::query(
            "UPDATE findings SET details='{\"advice\":{\"recommended\":\"2\"}}' WHERE key='crit'",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO kv(key,value) VALUES ('sync|nvd','2026-11-15T00:00:00Z')")
            .execute(&pool)
            .await
            .unwrap();
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = router(state(pool));
        let (status, body) = get(&app, "/api/v1/status?realms=prod", Some(&key)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let value: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(value["fix_available"], 1);
        assert_eq!(value["services"][0]["service"], "api");
        assert_eq!(value["services"][0]["risk"], 13);
        assert_eq!(value["sync"]["nvd"], "2026-11-15T00:00:00Z");
        assert!(value["sync"]["osv"].is_null());
        assert_eq!(
            get(&app, "/api/v1/status", None).await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            get(&app, "/api/v1/status?realms=invalid", Some(&key))
                .await
                .0,
            StatusCode::BAD_REQUEST
        );
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
    async fn findings_pages_keep_response_shape_and_order(pool: PgPool) {
        for key in ["vuln|a", "vuln|b", "vuln|c"] {
            seed_finding(&pool, "prod", "api", key, "high").await;
        }
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = router(state(pool));
        let (_, first) = get(&app, "/api/v1/findings?limit=2", Some(&key)).await;
        let (_, equivalent) = get(&app, "/api/v1/findings?limit=2&offset=0", Some(&key)).await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&first).unwrap(),
            serde_json::from_str::<serde_json::Value>(&equivalent).unwrap()
        );
        let (_, second) = get(&app, "/api/v1/findings?limit=2&offset=2", Some(&key)).await;
        let first: Vec<FindingRow> = serde_json::from_str(&first).unwrap();
        let second: Vec<FindingRow> = serde_json::from_str(&second).unwrap();
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 1);
        assert!(first.iter().all(|row| row.id != second[0].id));
        for invalid in ["-1", "abc", "9223372036854775808"] {
            let (status, _) = get(
                &app,
                &format!("/api/v1/findings?offset={invalid}"),
                Some(&key),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn findings_ui_package_and_severity_order_preserve_legacy_shape(pool: PgPool) {
        for (name, severity) in [
            ("old-critical", "critical"),
            ("new-critical", "critical"),
            ("new-high", "high"),
        ] {
            seed_finding(&pool, "prod", "api", name, severity).await;
        }
        sqlx::query("INSERT INTO components (purl,name_key,ecosystem,version) VALUES ('pkg:pypi/django@3.2.0','pkg:pypi/django','pypi','3.2.0')").execute(&pool).await.unwrap();
        sqlx::query("UPDATE findings SET component_id=(SELECT id FROM components LIMIT 1), opened_at=CASE key WHEN 'old-critical' THEN '2024-01-01'::timestamptz WHEN 'new-critical' THEN '2025-01-01'::timestamptz ELSE '2026-01-01'::timestamptz END").execute(&pool).await.unwrap();
        let key = create_key(&pool, &[], "reader", Scope::Read).await.unwrap();
        let app = router(state(pool));
        for path in [
            "/api/v1/findings",
            "/api/v1/findings?offset=0&sort=severity",
        ] {
            let (status, body) = get(&app, path, Some(&key)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
            let mut fields: Vec<_> = rows[0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            fields.sort_unstable();
            assert_eq!(
                fields,
                vec![
                    "details",
                    "id",
                    "key",
                    "kind",
                    "opened_at",
                    "purl",
                    "realm",
                    "ref_id",
                    "resolved_at",
                    "service",
                    "severity",
                    "status"
                ]
            );
        }
        let (status, body) = get(
            &app,
            "/api/v1/findings?ui=true&sort=severity&order=desc",
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(
            rows.iter()
                .map(|row| row["key"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["new-critical", "old-critical", "new-high"]
        );
        assert_eq!(rows[0]["component_name"], "django");
        assert_eq!(rows[0]["component_version"], "3.2.0");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn findings_carry_epss_on_the_ui_path_and_sort_by_it(pool: PgPool) {
        // ref_id = key: one via an advisory's CVE, one a bare CVE, one unscored.
        for key in ["GHSA-aaaa", "CVE-2024-0002", "GHSA-none"] {
            seed_finding(&pool, "prod", "api", key, "high").await;
        }
        sqlx::query("INSERT INTO advisories (id, severity, source, cve_id) VALUES ('GHSA-aaaa','high','osv','CVE-2024-0001')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO epss (cve_id, score, percentile, scored_on) VALUES ('CVE-2024-0001', 0.5, 0.97, '2026-11-22'), ('CVE-2024-0002', 0.01, 0.4, '2026-11-22')").execute(&pool).await.unwrap();
        let key = create_key(&pool, &[], "reader", Scope::Read).await.unwrap();
        let app = router(state(pool));

        let (status, body) = get(
            &app,
            "/api/v1/findings?ui=true&sort=epss&order=desc",
            Some(&key),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        let got: Vec<_> = rows
            .iter()
            .map(|r| (r["key"].as_str().unwrap(), r["epss"].as_f64()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("GHSA-aaaa", Some(0.5)),
                ("CVE-2024-0002", Some(0.01)),
                ("GHSA-none", None)
            ]
        );
        assert_eq!(rows[0]["epss_percentile"].as_f64(), Some(0.97));

        // The API-key list without UI params keeps its old shape.
        let (_, body) = get(&app, "/api/v1/findings", Some(&key)).await;
        assert!(!body.contains("epss"), "{body}");

        let id = rows[0]["id"].as_i64().unwrap();
        let (status, body) = get(&app, &format!("/api/v1/findings/{id}"), Some(&key)).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(detail["epss"].as_f64(), Some(0.5));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn findings_filters_and_sort_are_applied_before_paging(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "vuln|a", "high").await;
        seed_finding(&pool, "prod", "api", "vuln|b", "critical").await;
        seed_finding(&pool, "prod", "worker", "vuln|c", "low").await;
        sqlx::query("UPDATE findings SET ref_id = 'CVE-2026-1234', details = '{\"advice\":{\"recommended\":\"2.0\"}}' WHERE key = 'vuln|b'")
            .execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO advisories (id, aliases, severity, source) VALUES ('CVE-2026-1234', ARRAY['GHSA-test'], 'critical', 'osv')")
            .execute(&pool).await.unwrap();
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = router(state(pool));
        for path in [
            "/api/v1/findings?severity=critical&service=api&search=2026&has_fix=true",
            "/api/v1/findings?search=GHSA-test",
            "/api/v1/findings?sort=severity&order=desc&limit=1",
        ] {
            let (status, body) = get(&app, path, Some(&key)).await;
            assert_eq!(status, StatusCode::OK, "{body}");
            let rows: Vec<FindingRow> = serde_json::from_str(&body).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].key, "vuln|b");
        }
        for path in [
            "/api/v1/findings?sort=bogus",
            "/api/v1/findings?sort=severity%3BSELECT%201",
            "/api/v1/findings?order=bogus",
        ] {
            assert_eq!(get(&app, path, Some(&key)).await.0, StatusCode::BAD_REQUEST);
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn finding_detail_and_oath_status_filters(pool: PgPool) {
        seed_finding(&pool, "prod", "api", "one", "high").await;
        sqlx::query("INSERT INTO components (purl,name_key,ecosystem,version) VALUES ('pkg:generic/foo@1','pkg:generic/foo','generic','1')").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO advisories (id,aliases,severity,summary,source,scores,fixed) VALUES ('GHSA-test',ARRAY['CVE-2026-1234'],'high','Example','osv','{\"osv\":7.5}','{\"pkg:generic/foo\":[\"2\"]}')").execute(&pool).await.unwrap();
        sqlx::query("UPDATE findings SET ref_id='GHSA-test', component_id=(SELECT id FROM components LIMIT 1) WHERE key='one'").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO service_components (service_id,component_id,source) SELECT s.id,c.id,'git' FROM services s,components c").execute(&pool).await.unwrap();
        sqlx::query("INSERT INTO oaths(advisory_id,name_key,service_name,realm,kind,reason,version_at_creation,created_by,expires_at) VALUES ('CVE-2026-1234','pkg:generic/foo','api','prod','snooze','later','1','alice',now()+interval '1 day')").execute(&pool).await.unwrap();
        let id: i64 = sqlx::query_scalar("SELECT id FROM findings WHERE key='one'")
            .fetch_one(&pool)
            .await
            .unwrap();
        let key = create_key(&pool, &[], "reader", Scope::Read).await.unwrap();
        let app = router(state(pool));
        for (status, count) in [("snoozed", 1), ("open", 0), ("ignored", 0), ("resolved", 0)] {
            let (code, body) = get(
                &app,
                &format!("/api/v1/findings?realms=prod&view_status={status}"),
                Some(&key),
            )
            .await;
            assert_eq!(code, StatusCode::OK, "{body}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body)
                    .unwrap()
                    .as_array()
                    .unwrap()
                    .len(),
                count
            );
        }
        let (code, body) = get(&app, &format!("/api/v1/findings/{id}"), Some(&key)).await;
        assert_eq!(code, StatusCode::OK, "{body}");
        let detail: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(detail["summary"], "Example");
        assert_eq!(detail["fixed"]["pkg:generic/foo"][0], "2");
        assert_eq!(detail["affected"][0]["service"], "api");
        assert_eq!(detail["oaths"][0]["reason"], "later");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn services_and_releases_can_be_paged(pool: PgPool) {
        for name in ["a", "b", "c"] {
            sqlx::query("INSERT INTO services (realm,name) VALUES ('prod',$1)")
                .bind(name)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO releases (target,version) VALUES ('test',$1)")
                .bind(name)
                .execute(&pool)
                .await
                .unwrap();
        }
        let key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = router(state(pool));
        for path in ["/api/v1/services", "/api/v1/releases"] {
            let (status, first) = get(&app, &format!("{path}?limit=2"), Some(&key)).await;
            assert_eq!(status, StatusCode::OK, "{first}");
            let (status, second) = get(&app, &format!("{path}?limit=2&offset=2"), Some(&key)).await;
            assert_eq!(status, StatusCode::OK, "{second}");
            let first: Vec<serde_json::Value> = serde_json::from_str(&first).unwrap();
            let second: Vec<serde_json::Value> = serde_json::from_str(&second).unwrap();
            assert_eq!((first.len(), second.len()), (2, 1));
            assert!(first.iter().all(|row| row["id"] != second[0]["id"]));
        }
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

#[cfg(test)]
mod ui_tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn fallback_serves_html_with_security_headers_and_preserves_api_404() {
        let app = Router::new().fallback(ui_fallback);
        for path in ["/", "/findings"] {
            let response = app
                .clone()
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "text/html");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-cache");
            assert_eq!(response.headers()[header::CONTENT_SECURITY_POLICY], "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
            assert_eq!(
                response.headers()[header::X_CONTENT_TYPE_OPTIONS],
                "nosniff"
            );
            assert_eq!(response.headers()[header::REFERRER_POLICY], "same-origin");
            assert!(!response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .is_empty());
        }
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/unknown")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    }

    #[tokio::test]
    async fn embedded_assets_have_immutable_cache_headers() {
        if let Some(name) = UiAssets::iter().find(|name| name.starts_with("assets/")) {
            let response = ui_fallback(Method::GET, format!("/{name}").parse().unwrap()).await;
            assert_eq!(
                response.headers()[header::CACHE_CONTROL],
                "public, max-age=31536000, immutable"
            );
        } else {
            let html = UiAssets::get("index.html").unwrap();
            assert!(std::str::from_utf8(&html.data)
                .unwrap()
                .contains("UI not built; run npm run build in web/"));
        }
    }
}
