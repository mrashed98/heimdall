use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use heimdall::{config::HeimdallConfig, server, AppState};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{
    pkcs8::{EncodePrivateKey, LineEnding},
    traits::PublicKeyParts,
    RsaPrivateKey,
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

async fn request(app: &Router, uri: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut b = Request::builder().uri(uri);
    if let Some(c) = cookie {
        b = b.header("cookie", c);
    }
    app.clone()
        .oneshot(b.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn oidc_flow_verifies_tokens_and_updates_identity(pool: PgPool) {
    std::env::set_var("HEIMDALL_TEST_OIDC_SECRET", "test-secret");
    let idp = MockServer::start().await;
    let issuer = idp.uri();
    let key = RsaPrivateKey::new(&mut rand08::thread_rng(), 2048).unwrap();
    let pem = key.to_pkcs8_pem(LineEnding::LF).unwrap();
    let jwk = json!({"kty":"RSA","kid":"test-key","use":"sig","alg":"RS256","n":URL_SAFE_NO_PAD.encode(key.n().to_bytes_be()),"e":URL_SAFE_NO_PAD.encode(key.e().to_bytes_be())});
    Mock::given(method("GET")).and(path("/.well-known/openid-configuration")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"issuer":issuer,"authorization_endpoint":format!("{issuer}/authorize"),"token_endpoint":format!("{issuer}/token"),"jwks_uri":format!("{issuer}/jwks"),"response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}))).mount(&idp).await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys":[jwk]})))
        .mount(&idp)
        .await;
    let yaml = format!("realms: [prod]\nadmins: [admin@example.com]\nauth:\n  public_url: http://localhost:8080\n  oidc:\n    issuer: {issuer}\n    client_id: client\n    client_secret_env: HEIMDALL_TEST_OIDC_SECRET\n    groups_claim: teams\n    role_mappings:\n      - {{group: engineers, role: editor, realms: [prod]}}\n      - {{group: ops, role: admin, realms: ['*']}}\n");
    let cfg = HeimdallConfig::from_yaml(&yaml).unwrap();
    let app = server::router(AppState::new(
        pool.clone(),
        Arc::new(cfg),
        reqwest::Client::new(),
    ));
    for scenario in [
        "success",
        "returning",
        "state",
        "nonce",
        "aud",
        "expired",
        "signature",
    ] {
        let start = request(&app, "/auth/oidc/start", None).await;
        assert_eq!(start.status(), StatusCode::SEE_OTHER);
        let cookie = start.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let url = url::Url::parse(start.headers()["location"].to_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
        assert_eq!(params["code_challenge_method"], "S256");
        // Exception: a token/date the server checks against its real clock.
        #[allow(clippy::disallowed_methods)]
        let now = chrono::Utc::now().timestamp();
        let claims = json!({"iss":issuer,"sub":"subject-1","aud":if scenario == "aud" {"other"} else {"client"},"exp":if scenario == "expired" {now-1000} else {now+300},"iat":now,"nonce":if scenario == "nonce" {"wrong"} else {&params["nonce"]},"preferred_username":"alice","email_verified":true,"email":if scenario == "returning" {"updated@example.com"} else {"admin@example.com"},"name":if scenario == "returning" {"Updated"} else {"Alice"},"teams":["engineers","ops"]});
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key".into());
        let signing_key = if scenario == "signature" {
            RsaPrivateKey::new(&mut rand08::thread_rng(), 2048)
                .unwrap()
                .to_pkcs8_pem(LineEnding::LF)
                .unwrap()
        } else {
            pem.clone()
        };
        let token = encode(
            &header,
            &claims,
            &EncodingKey::from_rsa_pem(signing_key.as_bytes()).unwrap(),
        )
        .unwrap();
        let token_mock = Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({"access_token":"unused","token_type":"Bearer","id_token":token}),
            ))
            .mount_as_scoped(&idp)
            .await;
        let state = if scenario == "state" {
            "wrong"
        } else {
            &params["state"]
        };
        let response = request(
            &app,
            &format!("/auth/oidc/callback?code=code&state={state}"),
            Some(&cookie),
        )
        .await;
        assert!(response.headers().get_all("set-cookie").iter().any(|h| h
            .to_str()
            .unwrap()
            .starts_with("heimdall_oidc_state=; Max-Age=0")));
        if scenario == "success" || scenario == "returning" {
            assert_eq!(response.status(), StatusCode::SEE_OTHER, "{scenario}");
            assert_eq!(response.headers()["location"], "/");
            let session = response.headers()["set-cookie"]
                .to_str()
                .unwrap()
                .split(';')
                .next()
                .unwrap();
            let me = request(&app, "/auth/me", Some(session)).await;
            let body = http_body_util::BodyExt::collect(me.into_body())
                .await
                .unwrap()
                .to_bytes();
            let me: Value = serde_json::from_slice(&body).unwrap();
            let grants = me["grants"].as_array().unwrap();
            assert!(grants.iter().any(|g| g["role"] == "editor"));
            assert_eq!(
                grants.iter().any(|g| g["role"] == "admin"),
                scenario == "success"
            );
        } else {
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{scenario}");
        }
        drop(token_mock);
    }
    // Pending transactions are pruned and bounded under the same database lock.
    sqlx::query("DELETE FROM oidc_pending")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO oidc_pending(state_hash,nonce,verifier,expires_at) VALUES (decode('ff','hex'),'n','v',now()-interval '1 minute')").execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "/auth/oidc/start", None).await.status(),
        StatusCode::SEE_OTHER
    );
    let expired: i64 =
        sqlx::query_scalar("SELECT count(*) FROM oidc_pending WHERE expires_at <= now()")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(expired, 0);
    sqlx::query("INSERT INTO oidc_pending(state_hash,nonce,verifier) SELECT convert_to('pending-' || n::text,'UTF8'),'n','v' FROM generate_series(1,999) n").execute(&pool).await.unwrap();
    assert_eq!(
        request(&app, "/auth/oidc/start", None).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    let row: (i64, String, String) = sqlx::query_as(
        "SELECT count(*), max(email), max(display_name) FROM users WHERE kind='oidc'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row, (1, "updated@example.com".into(), "Updated".into()));
    let successes: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_log WHERE method='oidc' AND action='login_success'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let failures: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE method='oidc' AND action='login_failure' AND detail->>'reason' IS NOT NULL").fetch_one(&pool).await.unwrap();
    assert_eq!((successes, failures), (2, 5));
}

#[sqlx::test(migrations = "./migrations")]
async fn oidc_request_rate_limit_does_not_audit_rejections(pool: PgPool) {
    let cfg =
        HeimdallConfig::from_yaml("realms: [prod]\nauth: {public_url: http://localhost}").unwrap();
    let app = server::router(AppState::new(
        pool.clone(),
        Arc::new(cfg),
        reqwest::Client::new(),
    ));
    for _ in 0..30 {
        assert_eq!(
            request(&app, "/auth/oidc/callback", None).await.status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = request(&app, "/auth/oidc/callback", None).await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .contains("Max-Age=0"));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 30);
    assert_eq!(
        request(&app, "/auth/oidc/start", None).await.status(),
        StatusCode::TOO_MANY_REQUESTS
    );
}
