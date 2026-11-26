//! Admin API for alert channels: the config channels and the ones created in
//! the UI, listed together, plus create, edit, delete and a test send.
//! No response ever carries a secret value or an environment variable's
//! value: secrets show as `{"set": bool}`, missing variables by name.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::admin::require_admin;
use crate::config::ChannelConfig;
use crate::egress::{Egress, Origin};
use crate::error::ApiError;
use crate::local_auth::Principal;
use crate::model::Severity;
use crate::notify::channels::{self, email::SmtpMailer, Secrets};
use crate::notify::outbox::{self, Delivery, Health};
use crate::notify::store::{self, ChannelPatch, NewChannel, StoreError, UiState};
use crate::AppState;

/// One test send per channel name in this interval.
const TEST_INTERVAL: Duration = Duration::from_secs(10);

/// Keys `settings` leaves out: shown as their own fields (or not at all).
const NOT_SETTINGS: &[&str] = &["type", "name", "realms", "min_severity", "digest"];

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/channels", get(list).post(create))
        .route(
            "/api/v1/channels/{id}",
            axum::routing::patch(update).delete(remove),
        )
        .route("/api/v1/channels/{id}/queued", get(queued))
        .route("/api/v1/channels/{name}/test", post(test))
}

/// A handler error: an `ApiError`, or a status it has no variant for
/// (409, 502), with the same `{"error": ...}` body.
enum Fail {
    Api(ApiError),
    Status(StatusCode, String),
}

impl IntoResponse for Fail {
    fn into_response(self) -> Response {
        match self {
            Fail::Api(e) => e.into_response(),
            Fail::Status(s, m) => (s, Json(json!({ "error": m }))).into_response(),
        }
    }
}

impl From<ApiError> for Fail {
    fn from(e: ApiError) -> Self {
        Fail::Api(e)
    }
}

impl From<sqlx::Error> for Fail {
    fn from(e: sqlx::Error) -> Self {
        Fail::Api(e.into())
    }
}

impl From<anyhow::Error> for Fail {
    fn from(e: anyhow::Error) -> Self {
        Fail::Api(e.into())
    }
}

impl From<StoreError> for Fail {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NoKey | StoreError::NameTaken => {
                Fail::Status(StatusCode::CONFLICT, e.to_string())
            }
            StoreError::NotFound => Fail::Api(ApiError::NotFound),
            StoreError::Invalid(m) => Fail::Api(ApiError::BadRequest(m)),
            StoreError::Db(e) => e.into(),
        }
    }
}

#[derive(Serialize)]
struct List {
    management_enabled: bool,
    channels: Vec<ChannelView>,
}

#[derive(Serialize)]
struct ChannelView {
    id: Option<i64>,
    source: &'static str,
    #[serde(rename = "type")]
    kind: String,
    name: String,
    realms: Vec<String>,
    min_severity: Severity,
    digest: bool,
    settings: Map<String, Value>,
    secrets: BTreeMap<&'static str, SecretSet>,
    missing_env: Vec<String>,
    state: &'static str,
    health: HealthView,
}

#[derive(Serialize)]
struct SecretSet {
    set: bool,
}

#[derive(Serialize, Default)]
struct HealthView {
    queued: i64,
    last_sent_at: Option<DateTime<Utc>>,
    failing: Option<String>,
}

fn health_of(all: &HashMap<(String, String), Health>, name: &str, kind: &str) -> HealthView {
    // A channel with no outbox rows has no entry.
    all.get(&(name.to_string(), kind.to_string()))
        .map(|h| HealthView {
            queued: h.queued,
            last_sent_at: h.last_sent_at,
            failing: h.failing.clone(),
        })
        .unwrap_or_default()
}

/// `h` without a delivery older than `created`: that one went to an
/// earlier channel with the same name and type. (Creating a channel
/// discards the unsent rows, so `queued` and `failing` are already its own.)
fn since(mut h: HealthView, created: DateTime<Utc>) -> HealthView {
    h.last_sent_at = h.last_sent_at.filter(|at| *at >= created);
    h
}

fn state_name(s: UiState) -> &'static str {
    match s {
        UiState::Ok => "ok",
        UiState::KeyMissing => "key_missing",
        UiState::Unreadable => "unreadable",
        UiState::Invalid => "invalid",
        UiState::NameClash => "name_clash",
    }
}

/// `ch` serialized, without the keys `ChannelView` shows on its own and
/// without any `*_env` key.
fn settings(ch: &ChannelConfig) -> Map<String, Value> {
    let Ok(Value::Object(mut obj)) = serde_json::to_value(ch) else {
        return Map::new();
    };
    obj.retain(|k, _| !k.ends_with("_env") && !NOT_SETTINGS.contains(&k.as_str()));
    obj
}

/// A config channel: its secrets are environment variables, reported as
/// set or not and, when unset, by name.
fn config_view(ch: &ChannelConfig, health: &HashMap<(String, String), Health>) -> ChannelView {
    let obj = serde_json::to_value(ch).unwrap_or(Value::Null);
    let no_ui = Secrets::new();
    let mut secrets = BTreeMap::new();
    let mut missing_env: Vec<String> = Vec::new();
    for f in store::secret_fields(ch.type_name()).unwrap_or(&[]) {
        let var = obj[format!("{}_env", f.name)].as_str();
        let set = var.is_some_and(|v| channels::secret(v, &no_ui).is_some());
        if let (Some(v), false) = (var, set) {
            if !missing_env.iter().any(|m| m == v) {
                missing_env.push(v.to_string());
            }
        }
        secrets.insert(f.name, SecretSet { set });
    }
    ChannelView {
        id: None,
        source: "config",
        kind: ch.type_name().to_string(),
        name: ch.name().to_string(),
        realms: ch.realms().to_vec(),
        min_severity: ch.min_severity(),
        digest: ch.wants_digest(),
        settings: settings(ch),
        secrets,
        missing_env,
        state: "ok",
        health: health_of(health, ch.name(), ch.type_name()),
    }
}

/// The stored fields of a UI channel. Its realms are shown as stored, even
/// those since removed from the config (which `load` drops).
#[derive(sqlx::FromRow)]
struct UiRow {
    id: i64,
    realms: Vec<String>,
    min_severity: Severity,
    digest: Option<bool>,
    settings: sqlx::types::Json<Map<String, Value>>,
    created_at: DateTime<Utc>,
}

async fn list(State(st): State<AppState>, p: Principal) -> Result<Json<List>, Fail> {
    require_admin(&p)?;
    let chans = store::load(&st.pool, &st.cfg, st.secret_key.as_deref()).await?;
    let health = outbox::health(&st.pool).await?;
    let rows: Vec<UiRow> = sqlx::query_as(
        "SELECT id, realms, min_severity, digest, settings, created_at FROM alert_channels",
    )
    .fetch_all(&st.pool)
    .await?;
    let rows: HashMap<i64, UiRow> = rows.into_iter().map(|r| (r.id, r)).collect();

    let mut channels: Vec<ChannelView> = st
        .cfg
        .channels()
        .iter()
        .map(|c| config_view(c, &health))
        .collect();
    let mut ui = chans.ui;
    ui.sort_by(|a, b| a.name.cmp(&b.name));
    for u in ui {
        // Deleted since `load` read it.
        let Some(row) = rows.get(&u.id) else {
            continue;
        };
        let fields = store::secret_fields(&u.kind).unwrap_or(&[]);
        channels.push(ChannelView {
            id: Some(u.id),
            source: "ui",
            health: since(health_of(&health, &u.name, &u.kind), row.created_at),
            digest: match &u.config {
                Some(c) => c.wants_digest(),
                None => row
                    .digest
                    .unwrap_or(!matches!(u.kind.as_str(), "pagerduty" | "alertmanager")),
            },
            settings: u
                .config
                .as_ref()
                .map_or_else(|| row.settings.0.clone(), settings),
            secrets: fields
                .iter()
                .map(|f| {
                    let set = u.present.iter().any(|n| n == f.name);
                    (f.name, SecretSet { set })
                })
                .collect(),
            missing_env: Vec::new(),
            state: state_name(u.state),
            realms: row.realms.clone(),
            min_severity: row.min_severity,
            kind: u.kind,
            name: u.name,
        });
    }
    Ok(Json(List {
        management_enabled: st.secret_key.is_some(),
        channels,
    }))
}

async fn create(
    State(st): State<AppState>,
    p: Principal,
    Json(body): Json<NewChannel>,
) -> Result<(StatusCode, Json<Value>), Fail> {
    require_admin(&p)?;
    let id = store::create(&st.pool, &st.cfg, st.secret_key.as_deref(), &p.name, &body).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": id }))))
}

async fn update(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<i64>,
    Json(body): Json<ChannelPatch>,
) -> Result<StatusCode, Fail> {
    require_admin(&p)?;
    store::update(
        &st.pool,
        &st.cfg,
        st.secret_key.as_deref(),
        &p.name,
        id,
        &body,
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn queued(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<i64>,
) -> Result<Json<Value>, Fail> {
    require_admin(&p)?;
    let n = store::queued_count(&st.pool, &st.cfg, id).await?;
    Ok(Json(json!({ "queued": n })))
}

async fn remove(
    State(st): State<AppState>,
    p: Principal,
    Path(id): Path<i64>,
) -> Result<Json<Value>, Fail> {
    require_admin(&p)?;
    let n = store::delete(&st.pool, &st.cfg, &p.name, id).await?;
    Ok(Json(json!({ "discarded": n })))
}

/// Send a fixed test alert to channel `name` now, not through the outbox.
/// A config channel wins over a UI channel of the same name, as in delivery.
async fn test(
    State(st): State<AppState>,
    p: Principal,
    Path(name): Path<String>,
) -> Result<StatusCode, Fail> {
    require_admin(&p)?;
    let chans = store::load(&st.pool, &st.cfg, st.secret_key.as_deref()).await?;
    let (ch, origin) = match st.cfg.channels().into_iter().find(|c| c.name() == name) {
        Some(c) => (c, Origin::Config),
        None => {
            let u = chans
                .ui
                .iter()
                .find(|u| u.name == name)
                .ok_or(ApiError::NotFound)?;
            match (&u.config, u.state) {
                (Some(c), UiState::Ok) => (c.clone(), Origin::Console),
                (_, s) => {
                    return Err(Fail::Status(
                        StatusCode::CONFLICT,
                        format!("channel state is {}", state_name(s)),
                    ))
                }
            }
        }
    };
    {
        let mut tests = st.channel_tests.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        tests.retain(|_, at| now.duration_since(*at) < TEST_INTERVAL);
        if tests.contains_key(&name) {
            return Err(ApiError::TooManyRequests.into());
        }
        tests.insert(name.clone(), now);
    }
    let mailer = SmtpMailer {
        secrets: &chans.secrets,
    };
    let egress = Egress::new(&st.cfg.console_channels);
    let d = Delivery {
        egress: &egress,
        mailer: &mailer,
    };
    // The error is already redacted.
    let sent = outbox::send_now(&d, &ch, origin, &chans.secrets, Utc::now()).await;
    let mut conn = st.pool.acquire().await?;
    crate::admin::record(
        &mut conn,
        &p.name,
        "channel_tested",
        json!({"name": name, "type": ch.type_name(), "ok": sent.is_ok()}),
    )
    .await?;
    match sent {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(why) => Err(Fail::Status(StatusCode::BAD_GATEWAY, why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{create_key, Scope};
    use crate::config::HeimdallConfig;
    use crate::secrets::SecretKey;
    use crate::server::router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use sqlx::PgPool;
    use std::sync::Arc;
    use tower::ServiceExt;

    const UNSET_VAR: &str = "HEIMDALL_TEST_CHANNELS_API_UNSET";

    fn cfg() -> HeimdallConfig {
        HeimdallConfig::from_yaml(&format!(
            "realms: [prod, dev]\nadmins: [admin]\nchannels:\n  \
             - type: slack\n    name: cfg-path\n    webhook_env: PATH\n    min_severity: high\n  \
             - type: discord\n    name: cfg-unset\n    webhook_env: {UNSET_VAR}\n    min_severity: critical\n    realms: [prod]\n"
        ))
        .unwrap()
    }

    fn key() -> SecretKey {
        SecretKey::parse(&STANDARD.encode([7u8; 32])).unwrap()
    }

    fn app(pool: &PgPool, key: Option<SecretKey>) -> Router {
        let mut st = AppState::new(pool.clone(), Arc::new(cfg()), reqwest::Client::new());
        st.secret_key = key.map(Arc::new);
        router(st)
    }

    async fn call(
        app: &Router,
        method: &str,
        path: &str,
        key: &str,
        body: Option<Value>,
    ) -> (StatusCode, String) {
        let req = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {key}"))
            .header("content-type", "application/json");
        let body = body.map_or_else(Body::empty, |b| Body::from(b.to_string()));
        let resp = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    async fn admin(pool: &PgPool) -> String {
        create_key(pool, &["admin".to_string()], "admin", Scope::Admin)
            .await
            .unwrap()
    }

    fn slack(name: &str, url: &str) -> Value {
        json!({"type":"slack","name":name,"min_severity":"high","realms":["prod"],
               "secrets":{"webhook":url}})
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn non_admin_gets_403(pool: PgPool) {
        let app = app(&pool, Some(key()));
        let read = create_key(&pool, &[], "reader", Scope::Read).await.unwrap();
        for (method, path, body) in [
            ("GET", "/api/v1/channels", None),
            (
                "POST",
                "/api/v1/channels",
                Some(slack("s", "https://hooks.example/x")),
            ),
            ("PATCH", "/api/v1/channels/1", Some(json!({}))),
            ("GET", "/api/v1/channels/1/queued", None),
            ("DELETE", "/api/v1/channels/1", None),
            ("POST", "/api/v1/channels/cfg-path/test", None),
        ] {
            let (status, body) = call(&app, method, path, &read, body).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {body}");
        }
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM alert_channels")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn list_shows_config_and_ui_channels_without_secrets(pool: PgPool) {
        let app = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        let secret = "https://hooks.example/topsecret-a1b2c3";
        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("ui-slack", secret)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let id = serde_json::from_str::<Value>(&body).unwrap()["id"]
            .as_i64()
            .unwrap();
        let (status, body) = call(&app, "GET", "/api/v1/channels", &admin, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(!body.contains(secret), "{body}");
        assert!(!body.contains("topsecret"), "{body}");
        let path = std::env::var("PATH").unwrap();
        assert!(!body.contains(&path), "env value leaked: {body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["management_enabled"], true);
        let chans = v["channels"].as_array().unwrap();
        let names: Vec<&str> = chans.iter().map(|c| c["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["cfg-path", "cfg-unset", "ui-slack"]);

        assert_eq!(chans[0]["source"], "config");
        assert_eq!(chans[0]["id"], Value::Null);
        assert_eq!(chans[0]["type"], "slack");
        assert_eq!(chans[0]["secrets"], json!({"webhook":{"set":true}}));
        assert_eq!(chans[0]["missing_env"], json!([]));
        assert_eq!(chans[0]["state"], "ok");
        assert_eq!(chans[0]["digest"], true);
        assert_eq!(chans[0]["realms"], json!([]));

        assert_eq!(chans[1]["source"], "config");
        assert_eq!(chans[1]["secrets"], json!({"webhook":{"set":false}}));
        assert_eq!(chans[1]["missing_env"], json!([UNSET_VAR]));
        assert_eq!(chans[1]["min_severity"], "critical");
        assert_eq!(chans[1]["realms"], json!(["prod"]));

        let ui = &chans[2];
        assert_eq!(ui["source"], "ui");
        assert_eq!(ui["id"], id);
        assert_eq!(ui["type"], "slack");
        assert_eq!(ui["realms"], json!(["prod"]));
        assert_eq!(ui["min_severity"], "high");
        assert_eq!(ui["secrets"], json!({"webhook":{"set":true}}));
        assert_eq!(ui["missing_env"], json!([]));
        assert_eq!(ui["state"], "ok");
        assert_eq!(
            ui["health"],
            json!({"queued":0,"last_sent_at":null,"failing":null})
        );
        for c in chans {
            let settings = c["settings"].as_object().unwrap();
            for k in settings.keys() {
                assert!(
                    !k.ends_with("_env")
                        && !["type", "name", "realms", "min_severity", "digest"]
                            .contains(&k.as_str()),
                    "{k} in settings: {c}"
                );
            }
        }

        // A realm since removed from the config is still listed as stored.
        sqlx::query("UPDATE alert_channels SET realms='{prod,gone}' WHERE id=$1")
            .bind(id)
            .execute(&pool)
            .await
            .unwrap();
        let (_, body) = call(&app, "GET", "/api/v1/channels", &admin, None).await;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["channels"][2]["realms"], json!(["prod", "gone"]));
        assert_eq!(v["channels"][2]["state"], "ok");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_without_key_is_409_and_list_says_disabled(pool: PgPool) {
        let app = app(&pool, None);
        let admin = admin(&pool).await;
        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("s", "https://hooks.example/x")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let (status, body) = call(&app, "GET", "/api/v1/channels", &admin, None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["management_enabled"], false);
        assert_eq!(v["channels"].as_array().unwrap().len(), 2);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn create_maps_store_errors(pool: PgPool) {
        let app = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("cfg-path", "https://hooks.example/x")),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
        let mut bad = slack("s", "https://hooks.example/x");
        bad["realms"] = json!(["nope"]);
        let (status, body) = call(&app, "POST", "/api/v1/channels", &admin, Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert!(body.contains("nope"), "{body}");
        let (status, body) = call(
            &app,
            "PATCH",
            "/api/v1/channels/999",
            &admin,
            Some(json!({"min_severity":"low"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn patch_updates_and_returns_204(pool: PgPool) {
        let app = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        let (_, body) = call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("s", "https://hooks.example/x")),
        )
        .await;
        let id = serde_json::from_str::<Value>(&body).unwrap()["id"]
            .as_i64()
            .unwrap();
        let (status, body) = call(
            &app,
            "PATCH",
            &format!("/api/v1/channels/{id}"),
            &admin,
            Some(json!({"min_severity":"critical"})),
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (_, body) = call(&app, "GET", "/api/v1/channels", &admin, None).await;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["channels"][2]["min_severity"], "critical");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_endpoint_rate_limits(pool: PgPool) {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let app = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        let url = format!("{}/hook/secret-token-xyz", server.uri());
        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("ui-slack", &url)),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let (status, body) =
            call(&app, "POST", "/api/v1/channels/ui-slack/test", &admin, None).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        let (status, body) =
            call(&app, "POST", "/api/v1/channels/ui-slack/test", &admin, None).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
        let (status, _) = call(&app, "POST", "/api/v1/channels/nope/test", &admin, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        let rows: Vec<Value> = sqlx::query_scalar(
            "SELECT detail FROM audit_log WHERE action='channel_tested' ORDER BY id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(rows, [json!({"name":"ui-slack","type":"slack","ok":true})]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn test_failure_is_502_redacted_and_key_missing_is_409(pool: PgPool) {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400))
            .mount(&server)
            .await;
        let app_with_key = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        let url = format!("{}/hook/secret-token-xyz", server.uri());
        call(
            &app_with_key,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("ui-slack", &url)),
        )
        .await;
        let (status, body) = call(
            &app_with_key,
            "POST",
            "/api/v1/channels/ui-slack/test",
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(!body.contains("secret-token-xyz"), "{body}");
        assert!(
            serde_json::from_str::<Value>(&body).unwrap()["error"].is_string(),
            "{body}"
        );
        let detail: Value = sqlx::query_scalar(
            "SELECT detail FROM audit_log WHERE action='channel_tested' ORDER BY id DESC LIMIT 1",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(detail, json!({"name":"ui-slack","type":"slack","ok":false}));

        let no_key = app(&pool, None);
        let (status, body) = call(
            &no_key,
            "POST",
            "/api/v1/channels/ui-slack/test",
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT, "{body}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn delete_returns_discarded_count(pool: PgPool) {
        let app = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        let (_, body) = call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("ui-slack", "https://hooks.example/x")),
        )
        .await;
        let id = serde_json::from_str::<Value>(&body).unwrap()["id"]
            .as_i64()
            .unwrap();
        for g in ["a", "b"] {
            sqlx::query(
                "INSERT INTO outbox (group_key, card, route, channel_type) \
                 VALUES ($1, '{}', 'ui-slack', 'slack')",
            )
            .bind(g)
            .execute(&pool)
            .await
            .unwrap();
        }
        let (status, body) = call(
            &app,
            "GET",
            &format!("/api/v1/channels/{id}/queued"),
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({"queued":2})
        );
        let (_, body) = call(&app, "GET", "/api/v1/channels", &admin, None).await;
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["channels"][2]["health"]["queued"], 2);
        let (status, body) = call(
            &app,
            "DELETE",
            &format!("/api/v1/channels/{id}"),
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            json!({"discarded":2})
        );
        let (status, _) = call(
            &app,
            "DELETE",
            &format!("/api/v1/channels/{id}"),
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    /// A re-created channel does not show the last delivery of the deleted
    /// channel it replaced.
    #[sqlx::test(migrations = "./migrations")]
    async fn recreated_channel_shows_only_its_own_deliveries(pool: PgPool) {
        let app = app(&pool, Some(key()));
        let admin = admin(&pool).await;
        call(
            &app,
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("ui-slack", "https://hooks.example/x")),
        )
        .await;
        let sent = |offset: &'static str| {
            let pool = pool.clone();
            async move {
                sqlx::query(
                    "INSERT INTO outbox (group_key, card, route, channel_type, sent_at) \
                     SELECT 'g', '{}', 'ui-slack', 'slack', created_at + $1::interval \
                     FROM alert_channels WHERE name = 'ui-slack'",
                )
                .bind(offset)
                .execute(&pool)
                .await
                .unwrap();
            }
        };
        let last_sent = || async {
            let (_, body) = call(&app, "GET", "/api/v1/channels", &admin, None).await;
            let v: Value = serde_json::from_str(&body).unwrap();
            v["channels"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == "ui-slack")
                .unwrap()["health"]["last_sent_at"]
                .clone()
        };
        sent("-1 day").await;
        assert_eq!(last_sent().await, Value::Null);
        sent("1 minute").await;
        assert!(last_sent().await.is_string());
    }

    /// Test on a console channel obeys `console_channels.allowed_hosts`, as
    /// delivery does; a config channel to the same host is not limited.
    #[sqlx::test(migrations = "./migrations")]
    async fn test_send_of_a_console_channel_obeys_the_allowlist(pool: PgPool) {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let admin = admin(&pool).await;
        let hook = format!("{}/hook", server.uri());
        // Saved while nothing limited console channels.
        call(
            &app(&pool, Some(key())),
            "POST",
            "/api/v1/channels",
            &admin,
            Some(slack("ui-slack", &hook)),
        )
        .await;
        std::env::set_var("HEIMDALL_TEST_ALLOWLIST_HOOK", &hook);
        let limited = HeimdallConfig::from_yaml(
            "realms: [prod, dev]\nadmins: [admin]\nchannels:\n  \
             - type: slack\n    name: cfg-slack\n    webhook_env: HEIMDALL_TEST_ALLOWLIST_HOOK\n    \
             min_severity: high\n\
             console_channels:\n  allowed_hosts: ['10.0.0.0/8']\n",
        )
        .unwrap();
        let mut st = AppState::new(pool.clone(), Arc::new(limited), reqwest::Client::new());
        st.secret_key = Some(Arc::new(key()));
        let app = router(st);
        let (status, body) =
            call(&app, "POST", "/api/v1/channels/ui-slack/test", &admin, None).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
        assert!(body.contains("allowed_hosts"), "{body}");
        let (status, body) = call(
            &app,
            "POST",
            "/api/v1/channels/cfg-slack/test",
            &admin,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
        server.verify().await;
    }
}
