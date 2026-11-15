use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use heimdall::{auth, config::HeimdallConfig, server, AppState};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

const BOOT: &str = "hd_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
async fn setup(pool: &PgPool) -> Router {
    auth::ensure_bootstrap(pool, BOOT).await.unwrap();
    let cfg: HeimdallConfig = serde_saphyr::from_str("realms: [prod, dev]\nadmins: [alice]\nauth:\n  public_url: http://localhost\n  local: {enabled: true}\n").unwrap();
    server::router(AppState::new(
        pool.clone(),
        Arc::new(cfg),
        reqwest::Client::new(),
    ))
}
async fn user(pool: &PgPool, name: &str, grants: &[(&str, &str)]) -> (i64, String) {
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO users(username,password_hash) VALUES ($1,'test') RETURNING id",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    for (role, realm) in grants {
        sqlx::query("INSERT INTO user_grants VALUES ($1,$2,$3)")
            .bind(id)
            .bind(role)
            .bind(realm)
            .execute(pool)
            .await
            .unwrap();
    }
    let token = format!("session-{name}");
    sqlx::query("INSERT INTO sessions(id_hash,user_id,csrf_token,expires_at) VALUES ($1,$2,'csrf',now()+interval '1 day')").bind(Sha256::digest(token.as_bytes()).to_vec()).bind(id).execute(pool).await.unwrap();
    (id, token)
}
async fn call(
    app: &Router,
    method: &str,
    path: &str,
    credential: &str,
    body: Value,
) -> (StatusCode, Value) {
    let mut req = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    req = if credential.starts_with("hd_") {
        req.header("authorization", format!("Bearer {credential}"))
    } else {
        req.header("cookie", format!("heimdall_session={credential}"))
            .header("x-csrf-token", "csrf")
    };
    let resp = app
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
fn oath(realm: &str, all: bool) -> Value {
    json!({"advisory_id":"CVE-2025-1234","purl":"pkg:generic/test@1","service":"svc","realm":realm,"all_realms":all,"kind":"ignore","reason":"test"})
}

#[sqlx::test(migrations = "./migrations")]
async fn oath_permissions_and_audit(pool: PgPool) {
    let app = setup(&pool).await;
    let (_, editor) = user(&pool, "editor", &[("editor", "prod"), ("viewer", "dev")]).await;
    let (_, viewer) = user(&pool, "viewer", &[("viewer", "prod")]).await;
    let (_, global) = user(&pool, "global", &[("editor", "*")]).await;
    let (_, admin) = user(&pool, "alice", &[("admin", "prod")]).await;
    let read = auth::create_key(&pool, &[], "reader", auth::Scope::Read)
        .await
        .unwrap();
    for who in [&viewer, &read] {
        assert_eq!(
            call(&app, "POST", "/api/v1/oaths", who, oath("prod", false))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    for (realm, all) in [("dev", false), ("", true)] {
        assert_eq!(
            call(&app, "POST", "/api/v1/oaths", &editor, oath(realm, all))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    for who in [&global, &admin, BOOT] {
        assert_eq!(
            call(&app, "POST", "/api/v1/oaths", who, oath("", true))
                .await
                .0,
            StatusCode::OK
        );
    }
    let (_, created) = call(&app, "POST", "/api/v1/oaths", &editor, oath("prod", false)).await;
    let id = created["id"].as_i64().unwrap();
    let until = (chrono::Utc::now().date_naive() + chrono::Duration::days(4)).to_string();
    for action in ["extend", "revoke"] {
        let path = format!("/api/v1/oaths/{id}/{action}");
        for who in [&viewer, &read] {
            let (status, body) = call(&app, "POST", &path, who, json!({"until":until})).await;
            assert_eq!(
                (status, body),
                (StatusCode::FORBIDDEN, json!({"error":"forbidden"}))
            );
        }
        assert_eq!(
            call(&app, "POST", &path, &editor, json!({"until":until}))
                .await
                .0,
            StatusCode::OK
        );
    }
    let (_, dev) = call(&app, "POST", "/api/v1/oaths", BOOT, oath("dev", false)).await;
    for action in ["extend", "revoke"] {
        let path = format!("/api/v1/oaths/{}/{action}", dev["id"]);
        assert_eq!(
            call(&app, "POST", &path, &editor, json!({"until":until}))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let (_, all) = call(&app, "POST", "/api/v1/oaths", BOOT, oath("", true)).await;
    for action in ["extend", "revoke"] {
        let path = format!("/api/v1/oaths/{}/{action}", all["id"]);
        assert_eq!(
            call(&app, "POST", &path, &editor, json!({"until":until}))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&app, "POST", &path, &global, json!({"until":until}))
                .await
                .0,
            StatusCode::OK
        );
    }
    for who in [&admin, BOOT] {
        let (_, created) = call(&app, "POST", "/api/v1/oaths", who, oath("dev", false)).await;
        for action in ["extend", "revoke"] {
            let path = format!("/api/v1/oaths/{}/{action}", created["id"]);
            assert_eq!(
                call(&app, "POST", &path, who, json!({"until":until}))
                    .await
                    .0,
                StatusCode::OK
            );
        }
    }
    let (_, rows) = call(&app, "GET", "/api/v1/audit?actor=editor", BOOT, Value::Null).await;
    let actions: Vec<_> = rows
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        actions,
        vec!["oath_revoked", "oath_extended", "oath_created"]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn administration_validation_sessions_and_audit(pool: PgPool) {
    let app = setup(&pool).await;
    let (id, target) = user(&pool, "target", &[("viewer", "prod")]).await;
    let (_, nonadmin) = user(&pool, "nonadmin", &[("viewer", "*")]).await;
    let (_, admin) = user(&pool, "alice", &[("admin", "*")]).await;
    let grants = format!("/api/v1/users/{id}/grants");
    let user_path = format!("/api/v1/users/{id}");
    for (method, path, body) in [
        ("GET", "/api/v1/users", Value::Null),
        ("PATCH", user_path.as_str(), json!({"disabled":true})),
        ("GET", grants.as_str(), Value::Null),
        ("PUT", grants.as_str(), json!([])),
        ("GET", "/api/v1/audit", Value::Null),
    ] {
        assert_eq!(
            call(&app, method, path, &nonadmin, body).await.0,
            StatusCode::FORBIDDEN
        );
    }
    for (body, error) in [
        (json!([{"role":"unknown","realm":"prod"}]), "invalid_role"),
        (
            json!([{"role":"editor","realm":"missing"}]),
            "invalid_realm",
        ),
        (json!([{"role":"admin","realm":"*"}]), "admin_not_allowed"),
    ] {
        let (status, result) = call(&app, "PUT", &grants, BOOT, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(result["error"], error);
    }
    // Prime the grant cache before replacement.
    assert_eq!(
        call(&app, "POST", "/api/v1/oaths", &target, oath("prod", false))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &app,
            "PUT",
            &grants,
            &admin,
            json!([{"role":"editor","realm":"prod"}])
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "POST", "/api/v1/oaths", &target, oath("prod", false))
            .await
            .0,
        StatusCode::OK
    );
    let (_, list) = call(&app, "GET", "/api/v1/users", BOOT, Value::Null).await;
    assert!(list.as_array().unwrap().iter().any(|u| u["id"] == id
        && u["kind"] == "local"
        && u["name"] == "target"
        && u["email"].is_null()
        && u["grants"][0]["role"] == "editor"));
    assert_eq!(
        call(&app, "PATCH", &user_path, BOOT, json!({"disabled":true}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "GET", "/api/v1/oaths", &target, Value::Null)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(&app, "PATCH", &user_path, BOOT, json!({"disabled":false}))
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &app,
            "POST",
            "/api/v1/keys",
            BOOT,
            json!({"name":"ci","scope":"ingest"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "DELETE", "/api/v1/keys/ci", BOOT, Value::Null)
            .await
            .0,
        StatusCode::OK
    );
    let (_, rows) = call(
        &app,
        "GET",
        "/api/v1/audit?actor=bootstrap&limit=2&offset=1",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert_eq!(rows[0]["action"], "api_key_created");
    assert_eq!(rows[1]["action"], "user_enabled");
    let (_, filtered) = call(&app,"GET","/api/v1/audit?action=grants_replaced&since=2020-01-01T00%3A00%3A00Z&until=2100-01-01T00%3A00%3A00Z",BOOT,Value::Null).await;
    assert_eq!(filtered.as_array().unwrap().len(), 1);
    assert_eq!(filtered[0]["detail"]["old"][0]["role"], "viewer");
    assert_eq!(filtered[0]["detail"]["new"][0]["role"], "editor");
    let (_, empty) = call(
        &app,
        "GET",
        "/api/v1/audit?since=2100-01-01T00%3A00%3A00Z",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(empty, json!([]));
    let (_, all) = call(&app, "GET", "/api/v1/audit", BOOT, Value::Null).await;
    for action in [
        "user_disabled",
        "user_enabled",
        "grants_replaced",
        "api_key_created",
        "api_key_revoked",
    ] {
        assert!(
            all.as_array()
                .unwrap()
                .iter()
                .any(|r| r["action"] == action),
            "{action}"
        );
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_default_and_maximum_page_size(pool: PgPool) {
    let app = setup(&pool).await;
    sqlx::query("INSERT INTO audit_log(action,username,occurred_at) SELECT 'paging', 'batch', now() - (n * interval '1 second') FROM generate_series(1, 510) n").execute(&pool).await.unwrap();
    let (_, default) = call(
        &app,
        "GET",
        "/api/v1/audit?action=paging",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(default.as_array().unwrap().len(), 100);
    let (_, capped) = call(
        &app,
        "GET",
        "/api/v1/audit?action=paging&limit=999",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(capped.as_array().unwrap().len(), 500);
    let (_, rest) = call(
        &app,
        "GET",
        "/api/v1/audit?action=paging&limit=500&offset=500",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(rest.as_array().unwrap().len(), 10);
    assert!(
        capped[499]["occurred_at"].as_str().unwrap() > rest[0]["occurred_at"].as_str().unwrap()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn access_lists_page_and_sort_without_changing_defaults(pool: PgPool) {
    let app = setup(&pool).await;
    user(&pool, "zebra", &[("viewer", "prod")]).await;
    user(&pool, "alpha", &[("viewer", "dev")]).await;
    for name in ["zkey", "akey"] {
        auth::create_key(&pool, &[], name, auth::Scope::Read)
            .await
            .unwrap();
    }
    let (_, all) = call(&app, "GET", "/api/v1/users", BOOT, Value::Null).await;
    assert_eq!(all.as_array().unwrap().len(), 2);
    let (_, first) = call(
        &app,
        "GET",
        "/api/v1/users?sort=name&order=asc&limit=1",
        BOOT,
        Value::Null,
    )
    .await;
    let (_, second) = call(
        &app,
        "GET",
        "/api/v1/users?sort=name&order=asc&limit=1&offset=1",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(first[0]["name"], "alpha");
    assert_eq!(second[0]["name"], "zebra");
    let (_, keys) = call(
        &app,
        "GET",
        "/api/v1/keys?sort=name&order=desc&limit=1",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(keys[0]["name"], "zkey");
    sqlx::query("INSERT INTO audit_log(action,username) VALUES ('a','z'),('z','a')")
        .execute(&pool)
        .await
        .unwrap();
    let (_, audit) = call(
        &app,
        "GET",
        "/api/v1/audit?sort=actor&order=asc&limit=1",
        BOOT,
        Value::Null,
    )
    .await;
    assert_eq!(audit[0]["actor"], "a");
    let (_, viewer) = user(&pool, "viewer2", &[("viewer", "*")]).await;
    for path in [
        "/api/v1/users?limit=1",
        "/api/v1/keys?limit=1",
        "/api/v1/audit?limit=1",
    ] {
        assert_eq!(
            call(&app, "GET", path, &viewer, Value::Null).await.0,
            StatusCode::FORBIDDEN
        );
    }
}
