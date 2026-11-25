//! Where alerts may go: forbidden addresses, redirects and
//! `console_channels.allowed_hosts`, through the real outbox and store.

use chrono::{DateTime, TimeZone, Utc};
use serde_json::json;
use sqlx::PgPool;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::outbox::drain_once;
use super::store::{self, StoreError};
use crate::config::HeimdallConfig;
use crate::egress::Egress;
use crate::secrets::SecretKey;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

fn cfg(yaml: &str) -> HeimdallConfig {
    let c: HeimdallConfig = serde_saphyr::from_str(yaml).unwrap();
    c.validate().unwrap();
    c
}

fn key() -> SecretKey {
    use base64::{engine::general_purpose::STANDARD, Engine};
    SecretKey::parse(&STANDARD.encode([7u8; 32])).unwrap()
}

async fn queue(pool: &PgPool, route: &str) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO outbox (group_key, card, route, channel_type, next_attempt_at) \
         VALUES ('alert|x', $1, $2, 'alertmanager', '2000-01-01') RETURNING id",
    )
    .bind(json!({"alerts": [{"labels": {"alertname": "x"}, "annotations": {}}]}))
    .bind(route)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// `sent_at` and `last_error` of row `id`.
async fn state(pool: &PgPool, id: i64) -> (Option<DateTime<Utc>>, Option<String>) {
    sqlx::query_as("SELECT sent_at, last_error FROM outbox WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn drain(pool: &PgPool, c: &HeimdallConfig) {
    let chans = store::load(pool, c, Some(&key())).await.unwrap();
    let egress = Egress::new(&c.console_channels);
    drain_once(pool, &egress, c, &chans, now()).await.unwrap();
}

fn alertmanager(name: &str, url: &str) -> store::NewChannel {
    serde_json::from_value(json!({
        "type": "alertmanager", "name": name, "min_severity": "high",
        "settings": {"url": url},
    }))
    .unwrap()
}

/// A metadata address is refused even for a config channel, and its alert
/// stays queued with the reason instead of being lost.
#[sqlx::test(migrations = "./migrations")]
async fn metadata_destination_holds_the_queue(pool: PgPool) {
    let c = cfg(
        "realms: [prod]\nchannels:\n  - {type: alertmanager, name: am, \
                 url: 'http://169.254.169.254', min_severity: high}\n",
    );
    let id = queue(&pool, "am").await;
    drain(&pool, &c).await;
    let (sent, err) = state(&pool, id).await;
    assert!(sent.is_none());
    assert!(err.unwrap_or_default().contains("metadata"));
}

/// A redirect is not followed: the target is never called and the alert
/// stays queued, saying why.
#[sqlx::test(migrations = "./migrations")]
async fn redirects_are_not_followed(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v2/alerts"))
        .respond_with(
            ResponseTemplate::new(307)
                .insert_header("location", format!("{}/elsewhere", server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/elsewhere"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: alertmanager, name: am, url: '{}', \
         min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(&pool, "am").await;
    drain(&pool, &c).await;
    let (sent, err) = state(&pool, id).await;
    assert!(sent.is_none());
    assert!(err.unwrap_or_default().contains("redirect"));
    server.verify().await;
}

/// `allowed_hosts` limits console channels at send time; a config channel
/// to the same address still sends.
#[sqlx::test(migrations = "./migrations")]
async fn allowlist_holds_console_channels_only(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    let channels = format!(
        "realms: [prod]\nchannels:\n  - {{type: alertmanager, name: cfg, url: '{}', \
         min_severity: high}}\n",
        server.uri()
    );
    // Saved before the allowlist was added.
    store::create(
        &pool,
        &cfg(&channels),
        Some(&key()),
        "alice",
        &alertmanager("ui", &server.uri()),
    )
    .await
    .unwrap();
    let c = cfg(&format!(
        "{channels}console_channels:\n  allowed_hosts: ['10.0.0.0/8']\n"
    ));
    let from_config = queue(&pool, "cfg").await;
    let from_console = queue(&pool, "ui").await;
    drain(&pool, &c).await;
    drain(&pool, &c).await;
    assert!(state(&pool, from_config).await.0.is_some());
    let (sent, err) = state(&pool, from_console).await;
    assert!(sent.is_none());
    assert!(err.unwrap_or_default().contains("allowed_hosts"));
    server.verify().await;
}

/// Saving a console channel refuses a destination it could never send to.
#[sqlx::test(migrations = "./migrations")]
async fn saving_checks_the_destination(pool: PgPool) {
    let open = cfg("realms: [prod]\n");
    let refused = |r: Result<i64, StoreError>, want: &str| match r {
        Err(StoreError::Invalid(m)) => assert!(m.contains(want), "{m}"),
        other => panic!("expected Invalid({want}), got {other:?}"),
    };
    refused(
        store::create(
            &pool,
            &open,
            Some(&key()),
            "alice",
            &alertmanager("a", "http://169.254.169.254:9093"),
        )
        .await,
        "metadata",
    );
    let only_example =
        cfg("realms: [prod]\nconsole_channels:\n  allowed_hosts: ['*.example.com']\n");
    refused(
        store::create(
            &pool,
            &only_example,
            Some(&key()),
            "alice",
            &alertmanager("b", "http://127.0.0.1:9093"),
        )
        .await,
        "allowed_hosts",
    );
    let loopback = cfg("realms: [prod]\nconsole_channels:\n  allowed_hosts: ['127.0.0.0/8']\n");
    let id = store::create(
        &pool,
        &loopback,
        Some(&key()),
        "alice",
        &alertmanager("c", "http://127.0.0.1:9093"),
    )
    .await
    .unwrap();
    // An edit is checked the same way.
    let patch: store::ChannelPatch =
        serde_json::from_value(json!({"settings": {"url": "http://169.254.169.254"}})).unwrap();
    let err = store::update(&pool, &loopback, Some(&key()), "alice", id, &patch)
        .await
        .unwrap_err();
    assert!(
        matches!(&err, StoreError::Invalid(m) if m.contains("metadata")),
        "{err:?}"
    );
}

#[test]
fn allowed_hosts_are_parsed_at_load() {
    let err = serde_saphyr::from_str::<HeimdallConfig>(
        "realms: [prod]\nconsole_channels:\n  allowed_hosts: ['not a host']\n",
    )
    .unwrap_err();
    assert!(err.to_string().contains("not a host"), "{err}");
}
