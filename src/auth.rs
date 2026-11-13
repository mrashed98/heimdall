//! Scoped API keys. Keys are random, so they are stored as plain SHA-256
//! and looked up by hash (see docs/adr/0004-sha256-api-keys.md).

use anyhow::{bail, Context};
use axum::extract::{FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::routing::{delete, get};
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
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

fn admin_allowed(admins: &[String], name: &str) -> bool {
    name == BOOTSTRAP || admins.iter().any(|a| a == name)
}

/// Create a key and return its plaintext (shown once; only the hash is stored).
pub async fn create_key(
    pool: &PgPool,
    admins: &[String],
    name: &str,
    scope: Scope,
) -> anyhow::Result<String> {
    if scope == Scope::Admin && !admin_allowed(admins, name) {
        bail!("{name:?} is not listed in `admins`, so it cannot hold an admin key");
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
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

/// Make `key` an admin key named `bootstrap`, unless it is already stored.
pub async fn ensure_bootstrap(pool: &PgPool, key: &str) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO api_keys (name, sha256, scope) VALUES ($1, $2, 'admin') \
         ON CONFLICT DO NOTHING",
    )
    .bind(BOOTSTRAP)
    .bind(hash(key))
    .execute(pool)
    .await
    .context("storing bootstrap key")?;
    Ok(())
}

impl FromRequestParts<AppState> for Authed {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
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
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }
    if req.scope == Scope::Admin && !admin_allowed(&state.cfg.admins, &req.name) {
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

    fn state(pool: PgPool, admins: &[&str]) -> AppState {
        let mut cfg: crate::config::HeimdallConfig =
            serde_yaml::from_str("realms: [prod]").unwrap();
        cfg.admins = admins.iter().map(|s| s.to_string()).collect();
        AppState {
            pool,
            cfg: Arc::new(cfg),
            http: reqwest::Client::new(),
        }
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
        assert!(key.starts_with("hd_"));
        assert_eq!(key.len(), 46);
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
        ensure_bootstrap(&pool, "hd_bootstrapsecret").await.unwrap();
        ensure_bootstrap(&pool, "hd_bootstrapsecret").await.unwrap();
        let n: i64 = sqlx::query_scalar("select count(*) from api_keys")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        // Works as an admin even though `bootstrap` is not in cfg.admins.
        let app = app(state(pool, &[]));
        assert_eq!(
            status(&app, "/admin", Some("hd_bootstrapsecret")).await,
            StatusCode::OK
        );
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
        ensure_bootstrap(&pool, "hd_boot").await.unwrap();
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
        let (st, body) = call("POST", "/api/v1/keys", "hd_boot", Some(new)).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.contains("\"key\":\"hd_"));
        // Duplicate name and unlisted admin are 400s.
        let (st, _) = call("POST", "/api/v1/keys", "hd_boot", Some(new)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let eve = r#"{"name":"eve","scope":"admin"}"#;
        let (st, _) = call("POST", "/api/v1/keys", "hd_boot", Some(eve)).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, list) = call("GET", "/api/v1/keys", "hd_boot", None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(list.contains("\"ci\"") && !list.contains("sha256"));
        assert_eq!(
            call("DELETE", "/api/v1/keys/ci", "hd_boot", None).await.0,
            StatusCode::OK
        );
        assert_eq!(
            call("DELETE", "/api/v1/keys/ci", "hd_boot", None).await.0,
            StatusCode::NOT_FOUND
        );
    }
}
