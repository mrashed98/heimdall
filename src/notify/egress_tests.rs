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
    queue_as(
        pool,
        route,
        "alertmanager",
        json!({"alerts": [{"labels": {"alertname": "x"}, "annotations": {}}]}),
    )
    .await
}

async fn queue_as(pool: &PgPool, route: &str, kind: &str, card: serde_json::Value) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO outbox (group_key, card, route, channel_type, next_attempt_at) \
         VALUES ('alert|x', $1, $2, $3, '2000-01-01') RETURNING id",
    )
    .bind(card)
    .bind(route)
    .bind(kind)
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
    let err = err.unwrap_or_default();
    assert!(err.contains("allowed_hosts"), "{err}");
    // Never the host: for some webhooks it is part of the secret URL.
    assert!(!err.contains("127.0.0.1"), "{err}");
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

/// A channel URL that does not parse, or is not http(s), keeps the alerts
/// queued instead of discarding them.
#[sqlx::test(migrations = "./migrations")]
async fn bad_url_keeps_alerts_queued(pool: PgPool) {
    std::env::set_var("EGRESS_BAD_URL", "hooks.example.com/no-scheme");
    std::env::set_var("EGRESS_FILE_URL", "file:///etc/passwd");
    let c = cfg(
        "realms: [prod]\nchannels:\n  - {type: webhook, name: bad, url_env: EGRESS_BAD_URL, \
                 min_severity: high}\n  - {type: webhook, name: file, url_env: EGRESS_FILE_URL, \
                 min_severity: high}\n",
    );
    let bad = queue_as(&pool, "bad", "webhook", json!({"title": "x"})).await;
    let file = queue_as(&pool, "file", "webhook", json!({"title": "x"})).await;
    drain(&pool, &c).await;
    drain(&pool, &c).await;
    for id in [bad, file] {
        let (sent, err) = state(&pool, id).await;
        assert!(sent.is_none(), "row {id} was discarded");
        assert!(err.unwrap_or_default().contains("URL"));
    }
}

/// A minimal SMTP server that accepts one message; returns its address.
async fn smtp_server() -> std::net::SocketAddr {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (r, mut w) = sock.into_split();
        let mut lines = BufReader::new(r).lines();
        w.write_all(b"220 test\r\n").await.unwrap();
        let mut data = false;
        while let Ok(Some(line)) = lines.next_line().await {
            let reply: &[u8] = if data {
                if line != "." {
                    continue;
                }
                data = false;
                b"250 queued\r\n"
            } else {
                match line.get(..4).unwrap_or("").to_ascii_uppercase().as_str() {
                    "EHLO" | "HELO" | "MAIL" | "RCPT" | "RSET" | "NOOP" => b"250 ok\r\n",
                    "DATA" => {
                        data = true;
                        b"354 go\r\n"
                    }
                    "QUIT" => {
                        let _ = w.write_all(b"221 bye\r\n").await;
                        return;
                    }
                    _ => b"500 what\r\n",
                }
            };
            w.write_all(reply).await.unwrap();
        }
    });
    addr
}

/// The real mailer tries each checked address until one answers, as lettre
/// did when it resolved the host itself (a host listed as `::1` first but
/// served on `127.0.0.1` still gets its mail).
#[tokio::test]
async fn email_falls_back_to_the_next_address() {
    use super::channels::email::{self, Mailer, SmtpMailer};
    use crate::config::ChannelConfig;
    let live = smtp_server().await;
    // Bound and dropped: nothing listens there any more.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let ChannelConfig::Email(c) = serde_saphyr::from_str::<ChannelConfig>(
        "{type: email, name: mail, host: localhost, security: none, \
         from: heimdall@example.com, to: [ops@example.com], min_severity: high}",
    )
    .unwrap() else {
        unreachable!()
    };
    let alert = super::alert::Alert::test(now());
    let msg = email::message(&c, &email::render(&alert)).unwrap();
    let secrets = super::channels::Secrets::new();
    let mailer = SmtpMailer { secrets: &secrets };
    mailer.send(&c, &[dead, live], msg).await.unwrap();
}
