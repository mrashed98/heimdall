//! Scoped API keys. Keys are random, so they are stored as plain SHA-256
//! and looked up by hash (see docs/adr/0004-sha256-api-keys.md).

use anyhow::{bail, Context};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;

use crate::error::ApiError;
use crate::AppState;

/// The one name that may hold Admin without being listed in `cfg.admins`.
const BOOTSTRAP: &str = "bootstrap";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    Ingest,
    Read,
    Admin,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Ingest => "ingest",
            Scope::Read => "read",
            Scope::Admin => "admin",
        }
    }

    /// Admin satisfies everything; Read and Ingest only satisfy themselves.
    fn satisfies(self, needed: Scope) -> bool {
        self == Scope::Admin || self == needed
    }
}

impl std::str::FromStr for Scope {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Scope> {
        match s {
            "ingest" => Ok(Scope::Ingest),
            "read" => Ok(Scope::Read),
            "admin" => Ok(Scope::Admin),
            other => bail!("unknown scope {other:?} (use ingest, read or admin)"),
        }
    }
}

/// The caller, resolved from the `Authorization: Bearer` header.
#[derive(Debug, Clone)]
pub struct Authed {
    pub name: String,
    pub scope: Scope,
}

/// Fail with 403 unless the caller's scope covers `needed`.
pub fn require(authed: &Authed, needed: Scope) -> Result<(), ApiError> {
    if authed.scope.satisfies(needed) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn hash(key: &str) -> Vec<u8> {
    Sha256::digest(key.as_bytes()).to_vec()
}

/// Used when a key is presented: `bootstrap` only exists via `ensure_bootstrap`
/// (create paths reject that name), so exempting it here is safe.
fn admin_allowed(admins: &[String], name: &str) -> bool {
    name == BOOTSTRAP || admins.iter().any(|a| a == name)
}

/// Shared key-format check: `hd_` + 43 base64url chars (32 random bytes).
pub fn is_valid_key_format(key: &str) -> bool {
    match key.strip_prefix("hd_") {
        Some(rest) => {
            rest.len() == 43
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        }
        None => false,
    }
}

/// Names are `[A-Za-z0-9._-]{1,64}` and `bootstrap` is reserved.
fn check_name(name: &str) -> Result<(), String> {
    if name == BOOTSTRAP {
        return Err("reserved name".into());
    }
    let ok = (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err("name must match [A-Za-z0-9._-]{1,64}".into())
    }
}

/// Create a key and return its plaintext (shown once; only the hash is stored).
pub async fn create_key(
    pool: &PgPool,
    admins: &[String],
    name: &str,
    scope: Scope,
) -> anyhow::Result<String> {
    if let Err(m) = check_name(name) {
        bail!("invalid key name {name:?}: {m}");
    }
    if scope == Scope::Admin && !admins.iter().any(|a| a == name) {
        bail!("{name:?} is not listed in `admins`, so it cannot hold an admin key");
    }
    let mut bytes = [0u8; 32];
    // Thread-local CSPRNG seeded from the OS (rand >= 0.9 API).
    rand::fill(&mut bytes);
    let key = format!("hd_{}", URL_SAFE_NO_PAD.encode(bytes));
    sqlx::query("INSERT INTO api_keys (name, sha256, scope) VALUES ($1, $2, $3)")
        .bind(name)
        .bind(hash(&key))
        .bind(scope.as_str())
        .execute(pool)
        .await
        .with_context(|| format!("storing key {name:?} (name already in use?)"))?;
    Ok(key)
}

/// Make `key` the admin key named `bootstrap`; a changed key rotates it.
/// The format is enforced because a fast hash is only safe for random keys.
pub async fn ensure_bootstrap(pool: &PgPool, key: &str) -> anyhow::Result<()> {
    if !is_valid_key_format(key) {
        bail!("bootstrap key must be `hd_` followed by 43 base64url characters");
    }
    sqlx::query(
        "INSERT INTO api_keys (name, sha256, scope) VALUES ($1, $2, 'admin') \
         ON CONFLICT (name) DO UPDATE SET sha256 = EXCLUDED.sha256, scope = 'admin'",
    )
    .bind(BOOTSTRAP)
    .bind(hash(key))
    .execute(pool)
    .await
    .context("storing bootstrap key")?;
    Ok(())
}

/// Apply `HEIMDALL_BOOTSTRAP_ADMIN_KEY` (its value, None when unset) at
/// startup. Set: the `bootstrap` admin key is created or rotated. Unset or
/// empty: the `bootstrap` key is deleted, so removing the variable really
/// revokes the key instead of leaving it valid in the database.
pub async fn sync_bootstrap(pool: &PgPool, key: Option<&str>) -> anyhow::Result<()> {
    if let Some(k) = key.filter(|k| !k.is_empty()) {
        return ensure_bootstrap(pool, k).await;
    }
    let deleted = sqlx::query("DELETE FROM api_keys WHERE name = $1")
        .bind(BOOTSTRAP)
        .execute(pool)
        .await
        .context("removing the bootstrap key")?
        .rows_affected();
    if deleted > 0 {
        tracing::info!("HEIMDALL_BOOTSTRAP_ADMIN_KEY is not set; removed the bootstrap key");
    } else {
        tracing::info!("HEIMDALL_BOOTSTRAP_ADMIN_KEY is not set; no bootstrap key");
    }
    Ok(())
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if !parts.headers.contains_key("authorization") {
            let principal = crate::local_auth::Principal::from_request_parts(parts, state).await?;
            let scope = if principal
                .grants
                .iter()
                .any(|g| g.role == "admin" && g.realm == "*")
                && state.cfg.admins.contains(&principal.name)
            {
                Scope::Admin
            } else if principal
                .grants
                .iter()
                .any(|g| (g.role == "viewer" || g.role == "editor") && g.realm == "*")
            {
                Scope::Read
            } else {
                return Err(ApiError::Forbidden);
            };
            return Ok(Authed {
                name: principal.name,
                scope,
            });
        }
        authenticate_key(parts, state).await
    }
}

pub(crate) async fn authenticate_key(parts: &Parts, state: &AppState) -> Result<Authed, ApiError> {
    let key = parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let row: Option<(String, String)> =
        sqlx::query_as("SELECT name, scope FROM api_keys WHERE sha256 = $1")
            .bind(hash(key))
            .fetch_optional(&state.pool)
            .await?;
    let (name, scope) = row.ok_or(ApiError::Unauthorized)?;
    let scope = scope.parse::<Scope>()?;
    // Checked on every request so removing a name from `admins` takes
    // effect without revoking its key.
    if scope == Scope::Admin && !admin_allowed(&state.cfg.admins, &name) {
        return Err(ApiError::Forbidden);
    }
    Ok(Authed { name, scope })
}

#[derive(Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub scope: Scope,
}

#[derive(Serialize, Deserialize)]
pub struct CreateKeyResponse {
    pub name: String,
    pub scope: Scope,
    pub key: String,
}

/// Listing never includes the hash or the key.
#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct KeyInfo {
    pub name: String,
    pub scope: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Key management routes; the server merges these into its router.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/keys", get(list_keys).post(create_key_handler))
        .route("/api/v1/keys/{name}", delete(revoke_key))
}

async fn create_key_handler(
    State(state): State<AppState>,
    authed: Authed,
    Json(req): Json<CreateKeyRequest>,
) -> Result<Json<CreateKeyResponse>, ApiError> {
    require(&authed, Scope::Admin)?;
    check_name(&req.name).map_err(ApiError::BadRequest)?;
    if req.scope == Scope::Admin && !state.cfg.admins.contains(&req.name) {
        return Err(ApiError::BadRequest(format!(
            "{:?} is not listed in `admins`",
            req.name
        )));
    }
    let taken: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM api_keys WHERE name = $1)")
        .bind(&req.name)
        .fetch_one(&state.pool)
        .await?;
    if taken {
        return Err(ApiError::BadRequest(format!(
            "a key named {:?} already exists",
            req.name
        )));
    }
    let key = create_key(&state.pool, &state.cfg.admins, &req.name, req.scope).await?;
    Ok(Json(CreateKeyResponse {
        name: req.name,
        scope: req.scope,
        key,
    }))
}

async fn list_keys(
    State(state): State<AppState>,
    authed: Authed,
) -> Result<Json<Vec<KeyInfo>>, ApiError> {
    require(&authed, Scope::Admin)?;
    let keys = sqlx::query_as::<_, KeyInfo>(
        "SELECT name, scope, created_at FROM api_keys ORDER BY created_at, name",
    )
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(keys))
}

async fn revoke_key(
    State(state): State<AppState>,
    authed: Authed,
    Path(name): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    require(&authed, Scope::Admin)?;
    let done = sqlx::query("DELETE FROM api_keys WHERE name = $1")
        .bind(&name)
        .execute(&state.pool)
        .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    Ok(Json(serde_json::json!({ "revoked": name })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;
    use tower::ServiceExt;

    const BOOT: &str = "hd_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const BOOT2: &str = "hd_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    fn state(pool: PgPool, admins: &[&str]) -> AppState {
        let mut cfg: crate::config::HeimdallConfig =
            serde_saphyr::from_str("realms: [prod]").unwrap();
        cfg.admins = admins.iter().map(|s| s.to_string()).collect();
        AppState::new(pool, Arc::new(cfg), reqwest::Client::new())
    }

    fn app(state: AppState) -> Router {
        async fn guarded(a: Authed, needed: Scope) -> Result<&'static str, ApiError> {
            require(&a, needed)?;
            Ok("ok")
        }
        Router::new()
            .route(
                "/ingest",
                get(|a: Authed| async move { guarded(a, Scope::Ingest).await }),
            )
            .route(
                "/read",
                get(|a: Authed| async move { guarded(a, Scope::Read).await }),
            )
            .route(
                "/admin",
                get(|a: Authed| async move { guarded(a, Scope::Admin).await }),
            )
            .with_state(state)
    }

    async fn status(app: &Router, path: &str, key: Option<&str>) -> StatusCode {
        let mut req = Request::builder().uri(path);
        if let Some(k) = key {
            req = req.header("authorization", format!("Bearer {k}"));
        }
        app.clone()
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_key_roundtrip(pool: PgPool) {
        let key = create_key(&pool, &[], "ci", Scope::Ingest).await.unwrap();
        assert!(is_valid_key_format(&key));
        assert!(!is_valid_key_format("hd_short"));
        let read_key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = app(state(pool, &[]));
        assert_eq!(status(&app, "/ingest", Some(&key)).await, StatusCode::OK);
        assert_eq!(
            status(&app, "/ingest", None).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, "/ingest", Some("hd_wrong")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status(&app, "/ingest", Some(&read_key)).await,
            StatusCode::FORBIDDEN
        );
        // Read and Ingest do not satisfy each other.
        assert_eq!(
            status(&app, "/read", Some(&key)).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(status(&app, "/read", Some(&read_key)).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn admin_includes_ingest_and_read(pool: PgPool) {
        let key = create_key(&pool, &["mahmoud".into()], "mahmoud", Scope::Admin)
            .await
            .unwrap();
        let app = app(state(pool, &["mahmoud"]));
        for path in ["/ingest", "/read", "/admin"] {
            assert_eq!(
                status(&app, path, Some(&key)).await,
                StatusCode::OK,
                "{path}"
            );
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn bootstrap_idempotent(pool: PgPool) {
        ensure_bootstrap(&pool, BOOT).await.unwrap();
        ensure_bootstrap(&pool, BOOT).await.unwrap();
        let n: i64 = sqlx::query_scalar("select count(*) from api_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Works as an admin even though `bootstrap` is not in cfg.admins.
        let app = app(state(pool, &[]));
        assert_eq!(status(&app, "/admin", Some(BOOT)).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn admin_key_only_for_listed_admins(pool: PgPool) {
        let admins = vec!["mahmoud".to_string()];
        assert!(create_key(&pool, &admins, "eve", Scope::Admin)
            .await
            .is_err());
        assert!(create_key(&pool, &admins, "mahmoud", Scope::Admin)
            .await
            .is_ok());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn delisted_admin_key_rejected(pool: PgPool) {
        let key = create_key(&pool, &["mahmoud".into()], "mahmoud", Scope::Admin)
            .await
            .unwrap();
        let app = app(state(pool, &[]));
        assert_eq!(
            status(&app, "/admin", Some(&key)).await,
            StatusCode::FORBIDDEN
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn key_routes_create_list_revoke(pool: PgPool) {
        use http_body_util::BodyExt;
        ensure_bootstrap(&pool, BOOT).await.unwrap();
        let read_key = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        let app = routes().with_state(state(pool, &[]));
        let call = |method: &str, uri: &str, key: &str, body: Option<&str>| {
            let req = Request::builder()
                .method(method)
                .uri(uri)
                .header("authorization", format!("Bearer {key}"))
                .header("content-type", "application/json")
                .body(Body::from(body.unwrap_or("").to_string()))
                .unwrap();
            let app = app.clone();
            async move {
                let resp = app.oneshot(req).await.unwrap();
                let status = resp.status();
                let bytes = resp.into_body().collect().await.unwrap().to_bytes();
                (status, String::from_utf8(bytes.to_vec()).unwrap())
            }
        };
        let new = r#"{"name":"ci","scope":"ingest"}"#;
        assert_eq!(
            call("POST", "/api/v1/keys", &read_key, Some(new)).await.0,
            StatusCode::FORBIDDEN
        );
        let (st, body) = call("POST", "/api/v1/keys", BOOT, Some(new)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.contains("\"key\":\"hd_"));
        // Duplicate name and unlisted admin are 400s.
        let (st, _) = call("POST", "/api/v1/keys", BOOT, Some(new)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let eve = r#"{"name":"eve","scope":"admin"}"#;
        let (st, _) = call("POST", "/api/v1/keys", BOOT, Some(eve)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, list) = call("GET", "/api/v1/keys", BOOT, None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(list.contains("\"ci\"") && !list.contains("sha256"));
        assert_eq!(
            call("DELETE", "/api/v1/keys/ci", BOOT, None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call("DELETE", "/api/v1/keys/ci", BOOT, None).await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn bootstrap_rotation_and_format(pool: PgPool) {
        assert!(ensure_bootstrap(&pool, "hd_short").await.is_err());
        ensure_bootstrap(&pool, BOOT).await.unwrap();
        ensure_bootstrap(&pool, BOOT2).await.unwrap();
        let app = app(state(pool, &[]));
        assert_eq!(
            status(&app, "/admin", Some(BOOT)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(status(&app, "/admin", Some(BOOT2)).await, StatusCode::OK);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn bootstrap_key_removed_when_env_unset(pool: PgPool) {
        sync_bootstrap(&pool, Some(BOOT)).await.unwrap();
        let other = create_key(&pool, &[], "viewer", Scope::Read).await.unwrap();
        // HEIMDALL_BOOTSTRAP_ADMIN_KEY removed (unset or empty) on restart.
        for unset in [None, Some("")] {
            sync_bootstrap(&pool, unset).await.unwrap();
            let app = app(state(pool.clone(), &[]));
            assert_eq!(
                status(&app, "/admin", Some(BOOT)).await,
                StatusCode::UNAUTHORIZED,
                "{unset:?}"
            );
        }
        // Other keys are untouched.
        let app = app(state(pool, &[]));
        assert_ne!(
            status(&app, "/admin", Some(&other)).await,
            StatusCode::UNAUTHORIZED
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn reserved_and_invalid_names_rejected(pool: PgPool) {
        let admins = vec!["bootstrap".to_string()];
        assert!(create_key(&pool, &admins, "bootstrap", Scope::Admin)
            .await
            .is_err());
        assert!(create_key(&pool, &[], "bootstrap", Scope::Read)
            .await
            .is_err());
        assert!(create_key(&pool, &[], "ci?x", Scope::Read).await.is_err());
        ensure_bootstrap(&pool, BOOT).await.unwrap();
        let app = routes().with_state(state(pool, &["mahmoud"]));
        for body in [
            r#"{"name":"bootstrap","scope":"admin"}"#,
            r#"{"name":"ci?x","scope":"read"}"#,
        ] {
            let req = Request::builder()
                .method("POST")
                .uri("/api/v1/keys")
                .header("authorization", format!("Bearer {BOOT}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{body}");
        }
    }
}
