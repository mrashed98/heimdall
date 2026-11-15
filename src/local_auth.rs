//! Local identities and browser sessions.
use crate::{
    auth::{authenticate_key, Scope},
    error::ApiError,
    AppState,
};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{FromRequestParts, State},
    http::{request::Parts, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq;

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
fn hash(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}
pub fn password_hash(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|p| p.to_string())
        .map_err(|e| anyhow::anyhow!(e.to_string()))
}
pub async fn create_user(
    pool: &PgPool,
    admins: &[String],
    name: &str,
    password: &str,
    role: Option<&str>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "invalid username"
    );
    anyhow::ensure!(!password.is_empty(), "password cannot be empty");
    if let Some(r) = role {
        anyhow::ensure!(["viewer", "editor", "admin"].contains(&r), "invalid role");
        anyhow::ensure!(
            r != "admin" || admins.iter().any(|a| a == name),
            "admin must be listed in config admins"
        );
    }
    let hash = password_hash(password)?;
    let mut tx = pool.begin().await?;
    let id: i64 =
        sqlx::query_scalar("INSERT INTO users(username,password_hash) VALUES ($1,$2) RETURNING id")
            .bind(name)
            .bind(hash)
            .fetch_one(&mut *tx)
            .await?;
    if let Some(r) = role {
        sqlx::query("INSERT INTO user_grants(user_id,role,realm) VALUES ($1,$2,'*')")
            .bind(id)
            .bind(r)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("INSERT INTO audit_log(action,username) VALUES ('user_created',$1)")
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
pub async fn set_password(pool: &PgPool, name: &str, password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!password.is_empty(), "password cannot be empty");
    let hash = password_hash(password)?;
    let mut tx = pool.begin().await?;
    let id: i64 =
        sqlx::query_scalar("UPDATE users SET password_hash=$2 WHERE username=$1 RETURNING id")
            .bind(name)
            .bind(hash)
            .fetch_one(&mut *tx)
            .await?;
    sqlx::query("DELETE FROM sessions WHERE user_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}
#[derive(Clone, Debug, Serialize, sqlx::FromRow)]
pub struct Grant {
    pub role: String,
    pub realm: String,
}
#[derive(Clone, Debug)]
pub struct Principal {
    pub kind: &'static str,
    pub name: String,
    pub grants: Vec<Grant>,
    pub csrf_token: Option<String>,
    pub(crate) session_hash: Option<Vec<u8>>,
    pub scope: Option<Scope>,
}
impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        if parts.headers.contains_key("authorization") {
            let key = authenticate_key(parts, state).await?;
            return Ok(Self {
                kind: "key",
                name: key.name,
                grants: match key.scope {
                    Scope::Read => vec![Grant {
                        role: "viewer".into(),
                        realm: "*".into(),
                    }],
                    Scope::Admin => vec![Grant {
                        role: "admin".into(),
                        realm: "*".into(),
                    }],
                    Scope::Ingest => vec![],
                },
                csrf_token: None,
                session_hash: None,
                scope: Some(key.scope),
            });
        }
        let cfg = state.cfg.auth.as_ref().ok_or(ApiError::Unauthorized)?;
        let cookie = parts
            .headers
            .get("cookie")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| {
                v.split(';')
                    .map(str::trim)
                    .find_map(|v| v.strip_prefix("heimdall_session="))
            })
            .ok_or(ApiError::Unauthorized)?;
        let id = hash(cookie);
        let row: Option<(i64, String, String)> = sqlx::query_as("UPDATE sessions s SET last_seen_at=now() FROM users u WHERE s.id_hash=$1 AND s.user_id=u.id AND NOT u.disabled AND s.expires_at>now() AND s.last_seen_at > now() - ($2 * interval '1 hour') RETURNING u.id,u.username,s.csrf_token")
            .bind(&id).bind(i64::from(cfg.session.idle_hours)).fetch_optional(&state.pool).await?;
        let (user_id, name, csrf) = row.ok_or(ApiError::Unauthorized)?;
        if matches!(
            parts.method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            let provided = parts
                .headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !bool::from(csrf.as_bytes().ct_eq(provided.as_bytes())) {
                return Err(ApiError::Forbidden);
            }
        }
        let grants = sqlx::query_as::<_, Grant>(
            "SELECT role, realm FROM user_grants WHERE user_id=$1 ORDER BY role,realm",
        )
        .bind(user_id)
        .fetch_all(&state.pool)
        .await?;
        Ok(Self {
            kind: "user",
            name,
            grants,
            csrf_token: Some(csrf),
            session_hash: Some(id),
            scope: None,
        })
    }
}
#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/login", get(methods))
        .route("/auth/local", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}
async fn methods(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"local":state.cfg.auth.as_ref().is_some_and(|a| a.local.enabled),"oidc":false}),
    )
}
fn ip(parts: &axum::extract::ConnectInfo<std::net::SocketAddr>) -> String {
    parts.0.ip().to_string()
}
async fn login(
    State(state): State<AppState>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Json(req): Json<Login>,
) -> Result<Response, ApiError> {
    let cfg = state
        .cfg
        .auth
        .as_ref()
        .filter(|a| a.local.enabled)
        .ok_or(ApiError::Unauthorized)?;
    let address = peer
        .as_ref()
        .map(|v| ip(&v.0))
        .unwrap_or_else(|| "unknown".into());
    // Serialize checks and inserts for both dimensions, preventing concurrent bypasses.
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("login-ip:{address}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("login-user:{}", req.username))
        .execute(&mut *tx)
        .await?;
    let failures: (i64,i64) = sqlx::query_as("SELECT count(*) FILTER (WHERE username=$1), count(*) FILTER (WHERE ip=$2) FROM login_failures WHERE occurred_at > now()-interval '15 minutes'").bind(&req.username).bind(&address).fetch_one(&mut *tx).await?;
    let user: Option<(i64, Option<String>, bool)> =
        sqlx::query_as("SELECT id,password_hash,disabled FROM users WHERE username=$1")
            .bind(&req.username)
            .fetch_optional(&mut *tx)
            .await?;
    // Always perform a password verification, even when the account is absent.
    const DUMMY: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHRzb21lc2FsdA$RMqS6ZUJXUbFDSJ6E1ZMsypGWkVA+RW6tpfnjkXFHnU";
    let encoded = user.as_ref().and_then(|u| u.1.as_deref()).unwrap_or(DUMMY);
    let valid = PasswordHash::new(encoded).ok().is_some_and(|p| {
        Argon2::default()
            .verify_password(req.password.as_bytes(), &p)
            .is_ok()
    });
    if !valid || user.as_ref().is_none_or(|u| u.2) || failures.0 >= 5 || failures.1 >= 5 {
        sqlx::query("INSERT INTO login_failures(username,ip) VALUES ($1,$2)")
            .bind(&req.username)
            .bind(&address)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO audit_log(action,method,username,ip) VALUES ('login_failure','local',$1,$2)").bind(&req.username).bind(&address).execute(&mut *tx).await?;
        tx.commit().await?;
        return Err(ApiError::Unauthorized);
    }
    let id = user.unwrap().0;
    let token = random_token();
    let csrf = random_token();
    sqlx::query("INSERT INTO sessions(id_hash,user_id,csrf_token,expires_at) VALUES ($1,$2,$3,now()+($4 * interval '1 day'))").bind(hash(&token)).bind(id).bind(csrf).bind(i64::from(cfg.session.absolute_days)).execute(&mut *tx).await?;
    sqlx::query("UPDATE users SET last_login_at=now() WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO audit_log(action,method,username,ip) VALUES ('login_success','local',$1,$2)",
    )
    .bind(&req.username)
    .bind(&address)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let secure = if cfg.public_url.starts_with("http://localhost") {
        ""
    } else {
        "; Secure"
    };
    let cookie = format!("heimdall_session={token}; HttpOnly; SameSite=Lax; Path=/{secure}");
    let mut response = StatusCode::NO_CONTENT.into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&cookie).map_err(|e| ApiError::Internal(e.into()))?,
    );
    Ok(response)
}
async fn me(p: Principal) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"kind":p.kind,"name":p.name,"grants":p.grants,"csrf_token":p.csrf_token}),
    )
}
async fn logout(
    State(state): State<AppState>,
    p: Principal,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
) -> Result<Response, ApiError> {
    if let Some(id) = p.session_hash {
        let mut tx = state.pool.begin().await?;
        sqlx::query("DELETE FROM sessions WHERE id_hash=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log(action,method,username,ip) VALUES ('logout','local',$1,$2)",
        )
        .bind(p.name)
        .bind(peer.as_ref().map(|v| ip(&v.0)))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "set-cookie",
        HeaderValue::from_static("heimdall_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/"),
    );
    Ok((headers, StatusCode::NO_CONTENT).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app(pool: PgPool) -> Router {
        let cfg = crate::config::HeimdallConfig::from_yaml("realms: [prod]\nauth:\n  public_url: http://localhost:8080\n  local: { enabled: true }\n").unwrap();
        crate::server::router(AppState::new(pool, Arc::new(cfg), reqwest::Client::new()))
    }
    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        cookie: Option<&str>,
        csrf: Option<&str>,
        body: &str,
    ) -> (StatusCode, HeaderMap, String) {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        if let Some(c) = csrf {
            req = req.header("x-csrf-token", c);
        }
        let res = app
            .clone()
            .oneshot(req.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (status, headers, String::from_utf8(bytes.to_vec()).unwrap())
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn login_csrf_logout_and_expiry(pool: PgPool) {
        create_user(&pool, &[], "alice", "correct", Some("viewer"))
            .await
            .unwrap();
        let app = app(pool.clone());
        let (st, headers, _) = call(
            &app,
            "POST",
            "/auth/local",
            None,
            None,
            r#"{"username":"alice","password":"correct"}"#,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let cookie = headers["set-cookie"].to_str().unwrap();
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("SameSite=Lax")
                && !cookie.contains("Secure")
        );
        let cookie = cookie.split(';').next().unwrap();
        let (st, _, body) = call(&app, "GET", "/auth/me", Some(cookie), None, "").await;
        assert_eq!(st, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["name"], "alice");
        assert_eq!(json["grants"][0]["role"], "viewer");
        let csrf = json["csrf_token"].as_str().unwrap();
        assert_eq!(
            call(&app, "POST", "/auth/logout", Some(cookie), None, "")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "POST", "/auth/logout", Some(cookie), Some(csrf), "")
                .await
                .0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            call(&app, "GET", "/auth/me", Some(cookie), None, "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let audit: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM audit_log WHERE action IN ('login_success','logout')",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(audit, 2);
        let (_, h, _) = call(
            &app,
            "POST",
            "/auth/local",
            None,
            None,
            r#"{"username":"alice","password":"correct"}"#,
        )
        .await;
        let cookie = h["set-cookie"].to_str().unwrap().split(';').next().unwrap();
        sqlx::query("UPDATE sessions SET last_seen_at=now()-interval '13 hours'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            call(&app, "GET", "/auth/me", Some(cookie), None, "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn throttles_and_admin_creation_checks(pool: PgPool) {
        assert!(create_user(&pool, &[], "alice", "correct", Some("admin"))
            .await
            .is_err());
        create_user(&pool, &[], "alice", "correct", None)
            .await
            .unwrap();
        let app = app(pool.clone());
        for _ in 0..5 {
            assert_eq!(
                call(
                    &app,
                    "POST",
                    "/auth/local",
                    None,
                    None,
                    r#"{"username":"alice","password":"bad"}"#
                )
                .await
                .0,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            call(
                &app,
                "POST",
                "/auth/local",
                None,
                None,
                r#"{"username":"alice","password":"correct"}"#
            )
            .await
            .0,
            StatusCode::UNAUTHORIZED
        );
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE action='login_failure'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 6);
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn sessions_follow_user_changes_and_retention(pool: PgPool) {
        create_user(&pool, &[], "alice", "correct", Some("viewer"))
            .await
            .unwrap();
        let app = app(pool.clone());
        let login = async || {
            let (status, headers, _) = call(
                &app,
                "POST",
                "/auth/local",
                None,
                None,
                r#"{"username":"alice","password":"correct"}"#,
            )
            .await;
            assert_eq!(status, StatusCode::NO_CONTENT);
            headers["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap()
                .to_owned()
        };
        let cookie = login().await;
        let raw = cookie.split_once('=').unwrap().1;
        let stored: Vec<u8> = sqlx::query_scalar("SELECT id_hash FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(stored, hash(raw));
        sqlx::query("DELETE FROM user_grants")
            .execute(&pool)
            .await
            .unwrap();
        let (_, _, body) = call(&app, "GET", "/auth/me", Some(&cookie), None, "").await;
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&body).unwrap()["grants"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            call(&app, "GET", "/api/v1/findings", Some(&cookie), None, "")
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        sqlx::query("UPDATE users SET disabled=true")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            call(&app, "GET", "/auth/me", Some(&cookie), None, "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        sqlx::query("UPDATE users SET disabled=false")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE sessions SET expires_at=now()-interval '1 second'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            call(&app, "GET", "/auth/me", Some(&cookie), None, "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
        let cfg = crate::config::HeimdallConfig::from_yaml("realms: [prod]").unwrap();
        sqlx::query("INSERT INTO login_failures(username,ip,occurred_at) VALUES ('old','ip',now()-interval '16 minutes'),('new','ip',now())").execute(&pool).await.unwrap();
        crate::retention::cleanup(&pool, &cfg, chrono::Utc::now())
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM login_failures")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let cookie = login().await;
        set_password(&pool, "alice", "new password").await.unwrap();
        assert_eq!(
            call(&app, "GET", "/auth/me", Some(&cookie), None, "")
                .await
                .0,
            StatusCode::UNAUTHORIZED
        );
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn bearer_mutations_do_not_require_csrf(pool: PgPool) {
        let key = crate::auth::create_key(&pool, &["admin".into()], "admin", Scope::Admin)
            .await
            .unwrap();
        let mut cfg = crate::config::HeimdallConfig::from_yaml("realms: [prod]").unwrap();
        cfg.admins.push("admin".into());
        let app = crate::server::router(AppState::new(pool, Arc::new(cfg), reqwest::Client::new()));
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/keys")
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"name":"other","scope":"read"}"#))
            .unwrap();
        assert_eq!(app.oneshot(request).await.unwrap().status(), StatusCode::OK);
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn ip_throttle_and_secure_cookie(pool: PgPool) {
        create_user(&pool, &[], "alice", "correct", None)
            .await
            .unwrap();
        for i in 0..5 {
            sqlx::query("INSERT INTO login_failures(username,ip) VALUES ($1,'192.0.2.1')")
                .bind(format!("unknown{i}"))
                .execute(&pool)
                .await
                .unwrap();
        }
        let cfg = crate::config::HeimdallConfig::from_yaml(
            "realms: [prod]\nauth: {public_url: 'https://example.com', local: {enabled: true}}",
        )
        .unwrap();
        let app = crate::server::router(AppState::new(pool, Arc::new(cfg), reqwest::Client::new()));
        let request = |address: &str| {
            Request::builder()
                .method("POST")
                .uri("/auth/local")
                .header("content-type", "application/json")
                .extension(axum::extract::ConnectInfo(
                    address.parse::<std::net::SocketAddr>().unwrap(),
                ))
                .body(Body::from(r#"{"username":"alice","password":"correct"}"#))
                .unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(request("192.0.2.1:1234"))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let response = app.oneshot(request("192.0.2.2:1234")).await.unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("; Secure"));
    }
}
