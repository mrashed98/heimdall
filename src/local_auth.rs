//! Local identities and browser sessions.
use crate::config::{HeimdallConfig, Role};
use crate::{
    auth::{authenticate_key, Scope},
    error::ApiError,
    AppState,
};
use argon2::{
    password_hash::{phc::PasswordHash, PasswordHasher, PasswordVerifier},
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
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

pub(crate) fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}
pub(crate) fn hash(s: &str) -> Vec<u8> {
    Sha256::digest(s.as_bytes()).to_vec()
}
pub fn password_hash(password: &str) -> anyhow::Result<String> {
    Argon2::default()
        .hash_password_with_salt(password.as_bytes(), &rand::random::<[u8; 16]>())
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
    let id: i64 = sqlx::query_scalar(
        "UPDATE users SET password_hash=$2 WHERE username=$1 AND kind='local' RETURNING id",
    )
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, sqlx::FromRow)]
pub struct Grant {
    pub role: String,
    pub realm: String,
}
#[derive(Clone, Debug)]
pub struct Principal {
    pub kind: &'static str,
    pub name: String,
    pub grants: Vec<Grant>,
    pub groups: Vec<String>,
    pub csrf_token: Option<String>,
    pub scope: Option<Scope>,
    pub admin_allowed: bool,
}
type SessionRow = (
    i64,
    String,
    String,
    Vec<String>,
    Option<String>,
    String,
    Option<String>,
    bool,
    Option<chrono::DateTime<chrono::Utc>>,
);
type CacheEntries = HashMap<i64, (Instant, Option<Vec<Grant>>)>;
pub struct GrantCache {
    ttl: Duration,
    entries: Mutex<CacheEntries>,
}
impl GrantCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }
    pub fn invalidate(&self, user_id: i64) {
        self.entries
            .lock()
            .unwrap()
            .insert(user_id, (Instant::now(), None));
    }
    async fn get(&self, pool: &PgPool, user_id: i64) -> Result<Vec<Grant>, sqlx::Error> {
        if let Some((at, grants)) = self.entries.lock().unwrap().get(&user_id) {
            if at.elapsed() < self.ttl && grants.is_some() {
                return Ok(grants.clone().unwrap());
            }
        }
        let fetched_at = Instant::now();
        let grants = sqlx::query_as::<_, Grant>(
            "SELECT role, realm FROM user_grants WHERE user_id=$1 ORDER BY role,realm",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        let mut entries = self.entries.lock().unwrap();
        if entries
            .get(&user_id)
            .is_none_or(|(at, _)| *at <= fetched_at)
        {
            entries.insert(user_id, (fetched_at, Some(grants.clone())));
        }
        Ok(grants)
    }
}
impl Principal {
    pub fn can(&self, role: &str, realm: &str) -> bool {
        fn rank(role: &str) -> u8 {
            match role {
                "viewer" => 1,
                "editor" => 2,
                "admin" => 3,
                _ => 0,
            }
        }
        let needed = rank(role);
        needed > 0
            && self.grants.iter().any(|g| {
                g.role == "admin"
                    || ((g.realm == "*" || g.realm == realm) && rank(&g.role) >= needed)
            })
    }
    pub fn readable_realms(&self, all: &[String]) -> Vec<String> {
        all.iter()
            .filter(|r| self.can("viewer", r))
            .cloned()
            .collect()
    }
    pub fn require_read(&self) -> Result<(), ApiError> {
        if self.grants.is_empty() {
            if self.kind == "key" {
                Err(ApiError::Forbidden)
            } else {
                Err(ApiError::NoAccess)
            }
        } else {
            Ok(())
        }
    }
    fn add_config_grants(&mut self, cfg: &HeimdallConfig) {
        if let Some(oidc) = cfg.auth.as_ref().and_then(|a| a.oidc.as_ref()) {
            let mut add = |role: Role, realms: &[String]| {
                if role == Role::Admin && !self.admin_allowed {
                    return;
                }
                let role = match role {
                    Role::Viewer => "viewer",
                    Role::Editor => "editor",
                    Role::Admin => "admin",
                };
                for realm in realms {
                    let grant = Grant {
                        role: role.into(),
                        realm: realm.clone(),
                    };
                    if !self.grants.contains(&grant) {
                        self.grants.push(grant);
                    }
                }
            };
            for mapping in &oidc.role_mappings {
                if self.groups.contains(&mapping.group) {
                    add(mapping.role, &mapping.realms);
                }
            }
            if let Some(default) = &oidc.default_role {
                add(default.role, &default.realms);
            }
        }
    }
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
                groups: vec![],
                csrf_token: None,
                scope: Some(key.scope),
                admin_allowed: true,
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
        let row: Option<SessionRow> = sqlx::query_as("UPDATE sessions s SET last_seen_at=now() FROM users u WHERE s.id_hash=$1 AND s.user_id=u.id AND NOT u.disabled AND s.expires_at>now() AND s.last_seen_at > now() - ($2 * interval '1 hour') RETURNING u.id,u.username,s.csrf_token,s.groups,u.email,u.kind,u.preferred_username,u.email_verified,s.groups_refreshed_at")
            .bind(&id).bind(i64::from(cfg.session.idle_hours)).fetch_optional(&state.pool).await?;
        let (user_id, name, csrf, groups, email, user_kind, preferred, email_verified, refreshed) =
            row.ok_or(ApiError::Unauthorized)?;
        let admin_allowed = if user_kind == "oidc" {
            let oidc = cfg.oidc.as_ref().ok_or(ApiError::Reauth)?;
            if refreshed.is_none_or(|at| {
                at < state.clock.now()
                    - chrono::Duration::minutes(i64::from(oidc.groups_max_age_minutes))
            }) {
                return Err(ApiError::Reauth);
            }
            (oidc.admin_match_username
                && preferred
                    .as_ref()
                    .is_some_and(|n| state.cfg.admins.contains(n)))
                || (email_verified && email.as_ref().is_some_and(|e| state.cfg.admins.contains(e)))
        } else {
            state.cfg.admins.contains(&name)
        };
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
        let mut grants = state.grants_cache.get(&state.pool, user_id).await?;
        if !admin_allowed {
            grants.retain(|g| g.role != "admin");
        }
        let mut principal = Self {
            kind: "user",
            name,
            grants,
            groups,
            csrf_token: Some(csrf),
            scope: None,
            admin_allowed,
        };
        if user_kind == "oidc" {
            principal.add_config_grants(&state.cfg);
        }

        Ok(principal)
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
        serde_json::json!({"local":state.cfg.auth.as_ref().is_some_and(|a| a.local.enabled),"oidc":state.cfg.auth.as_ref().and_then(|a| a.oidc.as_ref()).map(|_| "OpenID Connect")}),
    )
}
fn ip(parts: &axum::extract::ConnectInfo<std::net::SocketAddr>) -> String {
    parts.0.ip().to_string()
}
pub(crate) fn client_ip(
    peer: Option<&axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: &HeaderMap,
    proxies: &[String],
) -> String {
    let Some(mut address) = peer.map(|p| p.0.ip()) else {
        return "unknown".into();
    };
    let trusted = |ip: std::net::IpAddr| {
        proxies
            .iter()
            .any(|c| c.parse::<ipnet::IpNet>().is_ok_and(|n| n.contains(&ip)))
    };
    if trusted(address) {
        let values: Vec<_> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .collect();
        for value in values.into_iter().rev() {
            if !trusted(address) {
                break;
            }
            let value = value.trim();
            let parsed = value
                .parse::<std::net::IpAddr>()
                .or_else(|_| {
                    value
                        .parse::<std::net::SocketAddr>()
                        .map(|socket| socket.ip())
                })
                .or_else(|_| {
                    value
                        .strip_prefix('[')
                        .and_then(|v| v.strip_suffix(']'))
                        .unwrap_or("")
                        .parse()
                });
            match parsed {
                Ok(ip) => address = ip,
                Err(_) => break,
            }
        }
    }
    address.to_string()
}
async fn login(
    State(state): State<AppState>,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    headers: HeaderMap,
    Json(req): Json<Login>,
) -> Result<Response, ApiError> {
    let cfg = state
        .cfg
        .auth
        .as_ref()
        .filter(|a| a.local.enabled)
        .ok_or(ApiError::Unauthorized)?;
    if req.username.chars().count() > 128 {
        return Err(ApiError::BadRequest("username_too_long".into()));
    }
    let address = client_ip(peer.as_ref().map(|v| &v.0), &headers, &cfg.trusted_proxies);
    // Serialize checks and inserts for both dimensions, preventing concurrent bypasses.
    let mut tx = state.pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("login-ip:{address}"))
        .execute(&mut *tx)
        .await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
        .bind(format!("login-user-ip:{}:{address}", req.username))
        .execute(&mut *tx)
        .await?;
    let failures: (i64,i64) = sqlx::query_as("SELECT count(*) FILTER (WHERE username=$1 AND ip=$2), count(*) FILTER (WHERE ip=$2) FROM login_failures WHERE occurred_at > now()-interval '15 minutes'").bind(&req.username).bind(&address).fetch_one(&mut *tx).await?;
    if failures.0 >= 5 || failures.1 >= 20 {
        return Err(ApiError::Unauthorized);
    }
    let user: Option<(i64, Option<String>, bool)> = sqlx::query_as(
        "SELECT id,password_hash,disabled FROM users WHERE username=$1 AND kind='local'",
    )
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
    if !valid || user.as_ref().is_none_or(|u| u.2) {
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
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    request: axum::extract::Request,
) -> Result<Response, ApiError> {
    let (mut parts, _) = request.into_parts();
    if parts.headers.contains_key("authorization") {
        // Preserve bearer-key authentication and its existing logout response.
        Principal::from_request_parts(&mut parts, &state).await?;
    } else {
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
        let mut tx = state.pool.begin().await?;
        let row: Option<(String, String)> = sqlx::query_as("SELECT u.username,s.csrf_token FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id_hash=$1 FOR UPDATE OF s")
            .bind(&id).fetch_optional(&mut *tx).await?;
        let (name, csrf) = row.ok_or(ApiError::Unauthorized)?;
        let provided = parts
            .headers
            .get("x-csrf-token")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !bool::from(csrf.as_bytes().ct_eq(provided.as_bytes())) {
            return Err(ApiError::Forbidden);
        }
        sqlx::query("DELETE FROM sessions WHERE id_hash=$1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO audit_log(action,method,username,ip) VALUES ('logout','local',$1,$2)",
        )
        .bind(name)
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
// Exception: these tests compare against database now() defaults, so they
// read the real clock. Tests only; production code here uses AppState.clock.
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;

    /// Hashes stored by argon2 0.5 (v0.3.x) must keep verifying after the upgrade.
    #[test]
    fn hashes_from_argon2_0_5_still_verify_and_new_ones_round_trip() {
        let verify = |encoded: &str, pw: &str| {
            Argon2::default()
                .verify_password(pw.as_bytes(), &PasswordHash::new(encoded).unwrap())
                .is_ok()
        };
        let old = "$argon2id$v=19$m=19456,t=2,p=1$3I6c3oZmvRItvyOx9kxwEg$HM+iocPgv1tbsWlqWUVwiQGkBQU4IiFRMGST6MmA02g";
        assert!(verify(old, "correct horse"));
        assert!(!verify(old, "wrong horse"));
        let new = password_hash("correct horse").unwrap();
        assert!(new.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"), "{new}");
        assert!(verify(&new, "correct horse"));
        assert_ne!(
            new,
            password_hash("correct horse").unwrap(),
            "salt must be random"
        );
    }
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    fn app(pool: PgPool) -> Router {
        let cfg = crate::config::HeimdallConfig::from_yaml("realms: [prod]\nauth:\n  public_url: http://localhost:8080\n  local: { enabled: true }\n").unwrap();
        crate::server::router(AppState::with_grant_cache_ttl(
            pool,
            Arc::new(cfg),
            reqwest::Client::new(),
            Duration::ZERO,
        ))
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
    #[test]
    fn forwarded_for_requires_trusted_peer_and_walks_right() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.1, 203.0.113.4, 10.0.0.2".parse().unwrap(),
        );
        let peer = axum::extract::ConnectInfo("10.0.0.1:1234".parse().unwrap());
        assert_eq!(client_ip(Some(&peer), &headers, &[]), "10.0.0.1");
        assert_eq!(
            client_ip(Some(&peer), &headers, &["10.0.0.0/8".into()]),
            "203.0.113.4"
        );
    }
    #[test]
    fn forwarded_for_accepts_ports_and_bracketed_ipv6() {
        let peer = axum::extract::ConnectInfo("10.0.0.1:1234".parse().unwrap());
        let mut headers = HeaderMap::new();
        for (value, expected) in [
            ("1.2.3.4:5678", "1.2.3.4"),
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("[2001:db8::1]", "2001:db8::1"),
            ("1.2.3.4:5678, 10.0.0.2:80", "1.2.3.4"),
            ("1.2.3.4, invalid", "10.0.0.1"),
        ] {
            headers.insert("x-forwarded-for", value.parse().unwrap());
            assert_eq!(
                client_ip(Some(&peer), &headers, &["10.0.0.0/8".into()]),
                expected
            );
        }
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn stale_oidc_session_can_logout_only_with_csrf(pool: PgPool) {
        let cfg = crate::config::HeimdallConfig::from_yaml("realms: [prod]\nauth:\n  public_url: http://localhost\n  oidc: {issuer: 'https://example.com', client_id: x, client_secret_env: SECRET}\n").unwrap();
        let id: i64 = sqlx::query_scalar("INSERT INTO users(kind,username,oidc_issuer,oidc_subject) VALUES ('oidc','alice','issuer','sub') RETURNING id").fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO sessions(id_hash,user_id,csrf_token,groups_refreshed_at,expires_at) VALUES ($1,$2,'secret',now()-interval '2 hours',now()+interval '1 day')").bind(hash("token")).bind(id).execute(&pool).await.unwrap();
        let app = crate::server::router(AppState::new(
            pool.clone(),
            Arc::new(cfg),
            reqwest::Client::new(),
        ));
        let cookie = Some("heimdall_session=token");
        assert_eq!(
            call(&app, "GET", "/auth/me", cookie, None, "").await.0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            call(&app, "POST", "/auth/logout", cookie, None, "").await.0,
            StatusCode::FORBIDDEN
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let (status, headers, _) =
            call(&app, "POST", "/auth/logout", cookie, Some("secret"), "").await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(headers["set-cookie"]
            .to_str()
            .unwrap()
            .contains("heimdall_session=; Max-Age=0"));
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn oidc_freshness_and_admin_claims(pool: PgPool) {
        let yaml = "realms: [prod]\nadmins: [alice, alice@example.com]\nauth:\n  public_url: http://localhost\n  oidc: {issuer: 'https://example.com', client_id: x, client_secret_env: SECRET}\n";
        let mut cfg = crate::config::HeimdallConfig::from_yaml(yaml).unwrap();
        let id: i64 = sqlx::query_scalar("INSERT INTO users(kind,username,oidc_issuer,oidc_subject,email,preferred_username) VALUES ('oidc','alice','issuer','sub','alice@example.com','alice') RETURNING id").fetch_one(&pool).await.unwrap();
        sqlx::query("INSERT INTO user_grants VALUES ($1,'admin','*')")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions(id_hash,user_id,csrf_token,groups_refreshed_at,expires_at) VALUES ($1,$2,'x',now(),now()+interval '1 day')").bind(hash("token")).bind(id).execute(&pool).await.unwrap();
        let make = |cfg: crate::config::HeimdallConfig| {
            crate::server::router(AppState::with_grant_cache_ttl(
                pool.clone(),
                Arc::new(cfg),
                reqwest::Client::new(),
                Duration::ZERO,
            ))
        };
        let (_, _, body) = call(
            &make(cfg.clone()),
            "GET",
            "/auth/me",
            Some("heimdall_session=token"),
            None,
            "",
        )
        .await;
        assert!(!body.contains("admin"));
        cfg.auth
            .as_mut()
            .unwrap()
            .oidc
            .as_mut()
            .unwrap()
            .admin_match_username = true;
        let (_, _, body) = call(
            &make(cfg.clone()),
            "GET",
            "/auth/me",
            Some("heimdall_session=token"),
            None,
            "",
        )
        .await;
        assert!(body.contains("admin"));
        cfg.auth
            .as_mut()
            .unwrap()
            .oidc
            .as_mut()
            .unwrap()
            .admin_match_username = false;
        sqlx::query("UPDATE users SET email_verified=true WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let (_, _, body) = call(
            &make(cfg.clone()),
            "GET",
            "/auth/me",
            Some("heimdall_session=token"),
            None,
            "",
        )
        .await;
        assert!(body.contains("admin"));
        sqlx::query("UPDATE sessions SET groups_refreshed_at=now()-interval '61 minutes'")
            .execute(&pool)
            .await
            .unwrap();
        let (status, _, body) = call(
            &make(cfg),
            "GET",
            "/auth/me",
            Some("heimdall_session=token"),
            None,
            "",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, r#"{"error":"reauth"}"#);
    }
    #[sqlx::test(migrations = "./migrations")]
    async fn long_username_is_rejected_without_audit(pool: PgPool) {
        let app = app(pool.clone());
        let body = serde_json::json!({"username":"a".repeat(129),"password":"x"}).to_string();
        assert_eq!(
            call(&app, "POST", "/auth/local", None, None, &body).await.0,
            StatusCode::BAD_REQUEST
        );
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0);
    }
    #[test]
    fn effective_config_grants_respect_groups_roles_and_admin_list() {
        let cfg = crate::config::HeimdallConfig::from_yaml("realms: [a, b]\nauth:\n  public_url: http://localhost\n  oidc:\n    issuer: https://example.com\n    client_id: client\n    client_secret_env: SECRET\n    role_mappings:\n      - {group: team, role: editor, realms: [a]}\n      - {group: admins, role: admin, realms: ['*']}\n    default_role: {role: viewer, realms: [b]}\n").unwrap();
        let mut p = Principal {
            kind: "user",
            name: "alice".into(),
            grants: vec![],
            groups: vec!["team".into(), "admins".into()],
            csrf_token: None,
            scope: None,
            admin_allowed: false,
        };
        p.add_config_grants(&cfg);
        p.add_config_grants(&cfg);
        assert_eq!(p.grants.len(), 2);
        assert!(p.can("viewer", "a") && p.can("editor", "a") && p.can("viewer", "b"));
        assert!(!p.can("admin", "a") && !p.can("editor", "b"));
        assert_eq!(p.readable_realms(&cfg.realms), cfg.realms);
        let mut allowed = cfg.clone();
        allowed.admins.push("alice".into());
        p.admin_allowed = true;
        p.add_config_grants(&allowed);
        assert!(p.can("admin", "b"));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn grant_cache_honors_ttl_and_zero_ttl(pool: PgPool) {
        let user: i64 = sqlx::query_scalar(
            "INSERT INTO users(username,password_hash) VALUES ('cached','test') RETURNING id",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO user_grants(user_id, role, realm) VALUES ($1,'viewer','a')")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        let cache = GrantCache::new(Duration::from_secs(30));
        assert_eq!(cache.get(&pool, user).await.unwrap().len(), 1);
        sqlx::query("DELETE FROM user_grants WHERE user_id=$1")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(cache.get(&pool, user).await.unwrap().len(), 1);
        cache.entries.lock().unwrap().get_mut(&user).unwrap().0 =
            Instant::now() - Duration::from_secs(31);
        assert!(cache.get(&pool, user).await.unwrap().is_empty());
        let uncached = GrantCache::new(Duration::ZERO);
        assert!(uncached.get(&pool, user).await.unwrap().is_empty());
        sqlx::query("INSERT INTO user_grants(user_id, role, realm) VALUES ($1,'viewer','b')")
            .bind(user)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(uncached.get(&pool, user).await.unwrap()[0].realm, "b");
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
        assert_eq!(n, 5);
        let attempts: i64 = sqlx::query_scalar("SELECT count(*) FROM login_failures")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(attempts, 5);
        create_user(&pool, &[], "bob", "correct", None)
            .await
            .unwrap();
        let request = Request::builder()
            .method("POST")
            .uri("/auth/local")
            .header("content-type", "application/json")
            .extension(axum::extract::ConnectInfo(
                "192.0.2.9:1234".parse::<std::net::SocketAddr>().unwrap(),
            ))
            .body(Body::from(r#"{"username":"bob","password":"correct"}"#))
            .unwrap();
        assert_eq!(
            app.oneshot(request).await.unwrap().status(),
            StatusCode::NO_CONTENT
        );
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
        for i in 0..20 {
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
