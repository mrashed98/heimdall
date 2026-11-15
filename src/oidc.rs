//! OpenID Connect authorization-code login.
use crate::{
    error::ApiError,
    local_auth::{hash, random_token},
    AppState,
};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/auth/oidc/start", get(start))
        .route("/auth/oidc/callback", get(callback))
}

async fn metadata(state: &AppState, refresh: bool) -> anyhow::Result<CoreProviderMetadata> {
    if !refresh {
        if let Some(m) = state.oidc_metadata.read().await.clone() {
            return Ok(m);
        }
    }
    let cfg = state
        .cfg
        .auth
        .as_ref()
        .and_then(|a| a.oidc.as_ref())
        .ok_or_else(|| anyhow::anyhow!("OIDC disabled"))?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let m = CoreProviderMetadata::discover_async(IssuerUrl::new(cfg.issuer.clone())?, &http)
        .await
        .map_err(|e| anyhow::anyhow!("discovery failed: {e}"))?;
    *state.oidc_metadata.write().await = Some(m.clone());
    Ok(m)
}

async fn start(State(state): State<AppState>) -> Result<Response, ApiError> {
    let auth = state.cfg.auth.as_ref().ok_or(ApiError::Unauthorized)?;
    let cfg = auth.oidc.as_ref().ok_or(ApiError::Unauthorized)?;
    let m = metadata(&state, false).await.map_err(ApiError::Internal)?;
    let client = CoreClient::from_provider_metadata(m, ClientId::new(cfg.client_id.clone()), None)
        .set_redirect_uri(
            RedirectUrl::new(format!(
                "{}/auth/oidc/callback",
                auth.public_url.trim_end_matches('/')
            ))
            .map_err(|e| ApiError::Internal(e.into()))?,
        );
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    for scope in &cfg.scopes {
        if scope != "openid" {
            request = request.add_scope(Scope::new(scope.clone()));
        }
    }
    let (url, csrf, nonce) = request.url();
    sqlx::query("DELETE FROM oidc_pending WHERE expires_at <= now()")
        .execute(&state.pool)
        .await?;
    sqlx::query("INSERT INTO oidc_pending(state_hash,nonce,verifier) VALUES ($1,$2,$3)")
        .bind(hash(csrf.secret()))
        .bind(nonce.secret())
        .bind(verifier.secret())
        .execute(&state.pool)
        .await?;
    let secure = if auth.public_url.starts_with("http://localhost") {
        ""
    } else {
        "; Secure"
    };
    let cookie = format!("heimdall_oidc_state={}; HttpOnly; SameSite=Lax; Path=/auth/oidc/callback; Max-Age=600{secure}", csrf.secret());
    let mut response = (StatusCode::SEE_OTHER, [("location", url.to_string())]).into_response();
    response.headers_mut().insert(
        "set-cookie",
        HeaderValue::from_str(&cookie).map_err(|e| ApiError::Internal(e.into()))?,
    );
    Ok(response)
}

#[derive(Deserialize)]
struct Callback {
    state: Option<String>,
    code: Option<String>,
    error: Option<String>,
}
async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    peer: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    Query(query): Query<Callback>,
) -> Result<Response, ApiError> {
    let ip = peer.as_ref().map(|v| v.0 .0.ip().to_string());
    let result = finish(&state, &headers, query, ip.as_deref()).await;
    if let Err(ref e) = result {
        let _ = sqlx::query(
            "INSERT INTO audit_log(action,method,detail,ip) VALUES ('login_failure','oidc',$1,$2)",
        )
        .bind(serde_json::json!({"reason": e.to_string()}))
        .bind(&ip)
        .execute(&state.pool)
        .await;
    }
    result.map_err(|_| ApiError::Unauthorized)
}

async fn finish(
    state: &AppState,
    headers: &HeaderMap,
    query: Callback,
    ip: Option<&str>,
) -> anyhow::Result<Response> {
    let auth = state
        .cfg
        .auth
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OIDC disabled"))?;
    let cfg = auth
        .oidc
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OIDC disabled"))?;
    let received = query
        .state
        .ok_or_else(|| anyhow::anyhow!("missing state"))?;
    let cookie = headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.split(';')
                .map(str::trim)
                .find_map(|p| p.strip_prefix("heimdall_oidc_state="))
        })
        .unwrap_or("");
    anyhow::ensure!(
        bool::from(received.as_bytes().ct_eq(cookie.as_bytes())),
        "invalid state"
    );
    let pending: Option<(String,String)> = sqlx::query_as("DELETE FROM oidc_pending WHERE state_hash=$1 AND expires_at>now() RETURNING nonce,verifier").bind(hash(&received)).fetch_optional(&state.pool).await?;
    let (nonce, verifier) = pending.ok_or_else(|| anyhow::anyhow!("invalid or expired state"))?;
    anyhow::ensure!(query.error.is_none(), "provider rejected login");
    let code = query.code.ok_or_else(|| anyhow::anyhow!("missing code"))?;
    let secret = std::env::var(&cfg.client_secret_env)?;
    let m = metadata(state, false).await?;
    let client = CoreClient::from_provider_metadata(
        m,
        ClientId::new(cfg.client_id.clone()),
        Some(ClientSecret::new(secret)),
    )
    .set_redirect_uri(RedirectUrl::new(format!(
        "{}/auth/oidc/callback",
        auth.public_url.trim_end_matches('/')
    ))?);
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))?
        .set_pkce_verifier(PkceCodeVerifier::new(verifier))
        .request_async(&http)
        .await
        .map_err(|_| anyhow::anyhow!("token exchange failed"))?;
    let id_token = token
        .extra_fields()
        .id_token()
        .ok_or_else(|| anyhow::anyhow!("missing ID token"))?;
    let nonce = Nonce::new(nonce);
    if let Err(error) = id_token.claims(&client.id_token_verifier(), &nonce) {
        if !matches!(
            error,
            openidconnect::ClaimsVerificationError::SignatureVerification(
                openidconnect::SignatureVerificationError::NoMatchingKey
            )
        ) {
            return Err(anyhow::anyhow!("invalid ID token: {error}"));
        }
        let m = metadata(state, true).await?;
        let refreshed =
            CoreClient::from_provider_metadata(m, ClientId::new(cfg.client_id.clone()), None);
        id_token
            .claims(&refreshed.id_token_verifier(), &nonce)
            .map_err(|e| anyhow::anyhow!("invalid ID token: {e}"))?;
    }
    // The payload is read only after the library has verified its signature and claims.
    let serialized = serde_json::to_value(id_token)?;
    let jwt = serialized
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("invalid ID token"))?;
    let payload = jwt
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("invalid ID token"))?;
    let claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?;
    let sub = claims["sub"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing subject"))?;
    let email = claims["email"].as_str();
    let preferred = claims["preferred_username"].as_str();
    let name = preferred.or(email).unwrap_or(sub);
    let display = claims["name"].as_str().or(preferred);
    let groups: Vec<String> = claims
        .get(cfg.groups_claim.as_deref().unwrap_or("groups"))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let mut tx = state.pool.begin().await?;
    let user: (i64,bool) = sqlx::query_as("INSERT INTO users(kind,username,oidc_issuer,oidc_subject,email,display_name,preferred_username,last_login_at) VALUES ('oidc',$1,$2,$3,$4,$5,$6,now()) ON CONFLICT (oidc_issuer,oidc_subject) WHERE kind='oidc' DO UPDATE SET username=excluded.username,email=excluded.email,display_name=excluded.display_name,preferred_username=excluded.preferred_username,last_login_at=now() RETURNING id,disabled")
        .bind(name).bind(&cfg.issuer).bind(sub).bind(email).bind(display).bind(preferred).fetch_one(&mut *tx).await?;
    anyhow::ensure!(!user.1, "user disabled");
    let session = random_token();
    let csrf = random_token();
    sqlx::query("INSERT INTO sessions(id_hash,user_id,csrf_token,groups,expires_at) VALUES ($1,$2,$3,$4,now()+($5 * interval '1 day'))").bind(hash(&session)).bind(user.0).bind(csrf).bind(groups).bind(i64::from(auth.session.absolute_days)).execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO audit_log(action,method,username,ip) VALUES ('login_success','oidc',$1,$2)",
    )
    .bind(name)
    .bind(ip)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let secure = if auth.public_url.starts_with("http://localhost") {
        ""
    } else {
        "; Secure"
    };
    let cookie = format!("heimdall_session={session}; HttpOnly; SameSite=Lax; Path=/{secure}");
    let mut response = (StatusCode::SEE_OTHER, [("location", "/")]).into_response();
    response
        .headers_mut()
        .insert("set-cookie", HeaderValue::from_str(&cookie)?);
    Ok(response)
}
