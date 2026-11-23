//! Formatter tests per channel type, and delivery tests against a real
//! database (sqlx::test) with the channels as wiremocks.

use std::sync::Mutex;

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request as WireRequest, ResponseTemplate};

use super::email::{MailError, Mailer};
use super::*;
use crate::config::{EmailChannel, HeimdallConfig};
use crate::model::{FindingKind, Severity};
use crate::notify::alert::{Alert, Line, Link, Section};
use crate::notify::outbox::{drain_with, Delivery, DrainResult};
use crate::notify::store::Channels;
use crate::notify::{AdvisoryInfo, AlertGroup, AlertItem, ReleaseInfo};

/// The config channels alone.
fn chans(c: &HeimdallConfig) -> Channels {
    Channels::from_config(c)
}

// ---- fixtures ----

fn item(id: i64, realm: &str, service: &str, details: Value) -> AlertItem {
    AlertItem {
        finding_id: id,
        kind: FindingKind::Vuln,
        realm: realm.to_string(),
        service: Some(service.to_string()),
        severity: Severity::High,
        details,
    }
}

fn vuln_details(purl: &str, direct: bool) -> Value {
    json!({
        "purl": purl,
        "version": "v1.9.0",
        "advice": {"suggest": "v1.9.1", "latest": "v1.10.0"},
        "direct": direct,
        "match_source": "osv",
        "scores": {"osv": 7.5, "nvd": 9.8},
    })
}

/// The Vuln group the Teams snapshot uses: one advisory in two services.
fn vuln_group() -> AlertGroup {
    AlertGroup {
        kind: FindingKind::Vuln,
        ref_id: "GHSA-gin-0001".to_string(),
        items: vec![
            item(
                1,
                "prod",
                "api",
                vuln_details("pkg:golang/github.com/gin-gonic/gin@v1.9.0", true),
            ),
            item(
                2,
                "prod",
                "worker",
                vuln_details("pkg:golang/github.com/gin-gonic/gin@v1.9.0", false),
            ),
        ],
        absorbed: vec![],
        advisory: Some(AdvisoryInfo {
            summary: "gin mishandles header parsing".to_string(),
            scores: json!({"osv": 7.5, "nvd": 9.8}),
        }),
        release: None,
    }
}

fn vuln_alert() -> Alert {
    Alert::from_group(&vuln_group())
}

/// An alert whose text is hostile to every markup language.
fn hostile_alert() -> Alert {
    let mut g = vuln_group();
    g.ref_id = "GHSA-<b>&x".to_string();
    g.advisory = Some(AdvisoryInfo {
        summary: "<script>alert(1)</script> & *bold* _it_ @everyone <@123> \"q\"".to_string(),
        scores: json!({}),
    });
    g.items[0].service = Some("api<i>".to_string());
    Alert::from_group(&g)
}

fn major_alert() -> Alert {
    let g = AlertGroup {
        kind: FindingKind::MajorRelease,
        ref_id: "17.0".to_string(),
        items: vec![AlertItem {
            finding_id: 9,
            kind: FindingKind::MajorRelease,
            realm: "prod".to_string(),
            service: None,
            severity: Severity::Unknown,
            details: json!({"target": "postgres", "version": "17.0", "current": "16.4"}),
        }],
        absorbed: vec![],
        advisory: None,
        release: Some(ReleaseInfo {
            notes_url: Some("https://example.com/notes/17.0".to_string()),
            breaking: vec!["drops <old> syntax".to_string()],
        }),
    };
    Alert::from_group(&g)
}

fn digest_alert() -> Alert {
    Alert::digest(
        "2026-11-16",
        vec![Section {
            title: "Security releases".to_string(),
            lines: vec![Line {
                link: Some(Link {
                    title: "postgres 17.2".to_string(),
                    url: "https://example.com/17.2".to_string(),
                }),
                // Upstream release-note text with its own Markdown link.
                text: ": fixes [click](https://evil.example/x) & more".to_string(),
            }],
        }],
    )
}

const EVIL: &str = "https://evil.example/x";

/// 500 services with long names: every formatter must stay in its limits.
fn huge_alert() -> Alert {
    let long = format!("pkg:npm/{}@1.0.0", "x".repeat(2000));
    let mut g = vuln_group();
    g.items = (0..500)
        .map(|i| {
            item(
                i,
                "prod",
                &format!("service-{i:03}-{}", "s".repeat(200)),
                vuln_details(&long, false),
            )
        })
        .collect();
    Alert::from_group(&g)
}

fn snapshot(name: &str, got: &Value) {
    let path = format!("tests/fixtures/channels/{name}.json");
    if std::env::var("HEIMDALL_UPDATE_SNAPSHOTS").is_ok() {
        std::fs::create_dir_all("tests/fixtures/channels").unwrap();
        std::fs::write(&path, serde_json::to_string_pretty(got).unwrap() + "\n").unwrap();
    }
    let want: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(got, &want, "{name} snapshot differs");
}

fn ch(yaml: &str) -> ChannelConfig {
    serde_saphyr::from_str(yaml).unwrap()
}

// ---- formatters ----

#[test]
fn teams_channel_renders_the_teams_card() {
    let teams = ch("{type: teams, name: t, webhook_env: X, min_severity: high}");
    assert_eq!(
        render(&teams, &vuln_alert()),
        crate::notify::teams::card(&vuln_group())
    );
}

#[test]
fn slack_snapshot_and_limits() {
    let got = slack::render(&vuln_alert());
    snapshot("slack_vuln", &got);
    assert_eq!(got["blocks"][0]["type"], "header");
    let t = got.to_string();
    assert!(
        t.contains("https://osv.dev/vulnerability/GHSA-gin-0001"),
        "{t}"
    );

    let huge = slack::render(&huge_alert());
    let blocks = huge["blocks"].as_array().unwrap();
    assert!(blocks.len() <= 50, "{}", blocks.len());
    for b in blocks {
        if let Some(text) = b["text"]["text"].as_str() {
            assert!(text.chars().count() <= 3000, "{}", text.len());
        }
    }
}

#[test]
fn slack_escapes_and_converts_links() {
    let t = slack::render(&hostile_alert()).to_string();
    assert!(
        t.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp;"),
        "{t}"
    );
    assert!(!t.contains("<script>"), "{t}");
    let d = slack::render(&digest_alert()).to_string();
    assert!(
        d.contains("<https://example.com/17.2|postgres 17.2>: fixes [click](https://evil.example/x) &amp; more"),
        "{d}"
    );
    assert!(!d.contains(&format!("<{EVIL}")), "{d}");
}

#[test]
fn discord_snapshot_and_limits() {
    let got = discord::render(&vuln_alert());
    snapshot("discord_vuln", &got);
    assert_eq!(got["allowed_mentions"], json!({"parse": []}));
    assert_eq!(got["embeds"][0]["color"], 0xE65100);
    let huge = discord::render(&huge_alert());
    let desc = huge["embeds"][0]["description"].as_str().unwrap();
    assert!(desc.chars().count() <= 4096, "{}", desc.len());
}

#[test]
fn discord_escapes_markdown_and_mentions() {
    let t = discord::render(&hostile_alert())["embeds"][0]["description"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(t.contains(r"\*bold\* \_it\_ \@everyone \<\@123\>"), "{t}");
    let d = discord::render(&digest_alert())["embeds"][0]["description"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        d.contains(r"[postgres 17.2](https://example.com/17.2): fixes \[click\](https://evil.example/x) & more"),
        "{d}"
    );
    // The brackets are escaped, so Discord shows the text, not a link.
    assert!(!d.contains(&format!("[click]({EVIL}")), "{d}");
}

#[test]
fn telegram_snapshot_and_limits() {
    let got = telegram::render(&vuln_alert(), "-100123");
    snapshot("telegram_vuln", &got);
    assert_eq!(got["parse_mode"], "HTML");
    assert_eq!(got["chat_id"], "-100123");
    let huge = telegram::render(&huge_alert(), "1");
    assert!(huge["text"].as_str().unwrap().chars().count() <= 4096);
}

#[test]
fn telegram_escapes_html() {
    let text = telegram::render(&hostile_alert(), "1")["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        text.starts_with("<b>⚠ GHSA-&lt;b&gt;&amp;x (high)"),
        "{text}"
    );
    assert!(
        text.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp;"),
        "{text}"
    );
    assert!(text.contains("&quot;q&quot;"), "{text}");
    assert!(text.contains("<b>prod / api&lt;i&gt;</b>"), "{text}");
    assert!(!text.contains("<script>"), "{text}");
    // Only the tags Heimdall writes remain.
    let tags: Vec<&str> = text
        .split('<')
        .skip(1)
        .map(|t| t.split('>').next().unwrap())
        .collect();
    assert!(
        tags.iter()
            .all(|t| matches!(*t, "b" | "/b" | "/a") || t.starts_with("a href=")),
        "{tags:?}"
    );
    let d = telegram::render(&digest_alert(), "1").to_string();
    assert!(
        d.contains(r#"<a href=\"https://example.com/17.2\">postgres 17.2</a>: fixes [click](https://evil.example/x) &amp; more"#),
        "{d}"
    );
    assert!(!d.contains(&format!("href=\\\"{EVIL}")), "{d}");
}

#[test]
fn pagerduty_snapshot() {
    let got = pagerduty::render(&vuln_alert());
    snapshot("pagerduty_vuln", &got);
    assert_eq!(got["dedup_key"], "alert|vuln|GHSA-gin-0001");
    assert_eq!(got["payload"]["severity"], "error");
    assert_eq!(got["payload"]["group"], "prod");
    assert!(
        got.get("routing_key").is_none(),
        "the key is added at send time"
    );
    assert_eq!(
        pagerduty::render(&major_alert())["payload"]["severity"],
        "error"
    );
}

#[test]
fn alertmanager_one_alert_per_finding() {
    let got = alertmanager::render(&vuln_alert());
    snapshot("alertmanager_vuln", &got);
    let alerts = got["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 2);
    assert_eq!(
        alerts[0]["labels"],
        json!({"alertname": "HeimdallVuln", "kind": "vuln", "severity": "high",
               "realm": "prod", "service": "api", "advisory": "GHSA-gin-0001"})
    );
    assert_eq!(alerts[1]["labels"]["service"], "worker");
    assert_eq!(
        alerts[0]["annotations"]["summary"],
        "⚠ GHSA-gin-0001 (high) affects 2 service(s)"
    );
    assert_eq!(
        alerts[0]["generatorURL"],
        "https://osv.dev/vulnerability/GHSA-gin-0001"
    );

    // A release is High; the digest is info and has no realm.
    let m = alertmanager::render(&major_alert());
    assert_eq!(m["alerts"][0]["labels"]["severity"], "high");
    assert_eq!(
        m["alerts"][0]["labels"]["alertname"],
        "HeimdallMajorRelease"
    );
    let d = alertmanager::render(&digest_alert());
    assert_eq!(
        d["alerts"][0]["labels"],
        json!({"alertname": "HeimdallDigest", "kind": "digest", "severity": "info"})
    );
}

#[test]
fn alertmanager_times_are_set_at_send() {
    let now = Utc.with_ymd_and_hms(2026, 11, 13, 10, 0, 0).unwrap();
    let out = alertmanager::with_times(&alertmanager::render(&vuln_alert()), now, 24).unwrap();
    assert_eq!(out[0]["startsAt"], "2026-11-13T10:00:00Z");
    assert_eq!(out[0]["endsAt"], "2026-11-14T10:00:00Z");
    assert!(alertmanager::with_times(&json!({"x": 1}), now, 24).is_err());
}

#[test]
fn webhook_payload_and_signature() {
    let got = webhook::render(&vuln_alert());
    snapshot("webhook_vuln", &got);
    assert_eq!(got["version"], 1);
    assert_eq!(got["alert"]["kind"], "vuln");
    assert_eq!(got["alert"]["severity"], "high");
    // RFC 4231 test case 2.
    assert_eq!(
        webhook::hmac_hex("Jefe", b"what do ya want for nothing?"),
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // The timestamp is signed with the body: "{ts}.{body}".
    assert_eq!(
        webhook::signature("k", 1700000000, b"{}"),
        format!("sha256={}", webhook::hmac_hex("k", b"1700000000.{}"))
    );
    assert_ne!(
        webhook::signature("k", 1700000000, b"{}"),
        webhook::signature("k", 1700000001, b"{}")
    );
    // Upstream Markdown in a digest row stays text in the JSON too.
    let d = webhook::render(&digest_alert());
    assert_eq!(
        d["alert"]["sections"][0]["lines"][0]["link"]["url"],
        "https://example.com/17.2"
    );
}

fn email_channel() -> EmailChannel {
    match ch("{type: email, name: mail, host: smtp.example.com, from: 'Heimdall <heimdall@example.com>', \
              to: [ops@example.com, sec@example.com], min_severity: high}")
    {
        ChannelConfig::Email(c) => c,
        _ => unreachable!(),
    }
}

#[test]
fn email_payload_and_message() {
    let got = email::render(&hostile_alert());
    assert_eq!(
        got["subject"],
        "[Heimdall] ⚠ GHSA-<b>&x (high) affects 2 service(s)"
    );
    let html = got["html"].as_str().unwrap();
    assert!(
        html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp;"),
        "{html}"
    );
    assert!(!html.contains("<script>"), "{html}");
    let text = got["text"].as_str().unwrap();
    assert!(
        text.contains("<script>alert(1)</script>"),
        "plain text is not escaped: {text}"
    );

    snapshot("email_vuln", &email::render(&vuln_alert()));
    let msg = email::message(&email_channel(), &email::render(&vuln_alert())).unwrap();
    let raw = String::from_utf8(msg.formatted()).unwrap();
    assert!(
        raw.contains("From: Heimdall <heimdall@example.com>"),
        "{raw}"
    );
    assert!(
        raw.contains("To: ops@example.com, sec@example.com"),
        "{raw}"
    );
    assert!(raw.contains("Subject: "), "{raw}");
    assert!(raw.contains("multipart/alternative"), "{raw}");
    assert!(raw.contains("text/plain"), "{raw}");
    assert!(raw.contains("text/html"), "{raw}");
    assert!(email::message(&email_channel(), &json!({"subject": "x"})).is_err());
}

#[test]
fn email_digest_links_only_heimdalls_links() {
    let got = email::render(&digest_alert());
    assert!(got["text"].as_str().unwrap().contains(
        "postgres 17.2 <https://example.com/17.2>: fixes [click](https://evil.example/x) & more"
    ));
    let html = got["html"].as_str().unwrap();
    assert!(html.contains(
        "<a href=\"https://example.com/17.2\">postgres 17.2</a>: fixes [click](https://evil.example/x) &amp; more"
    ), "{html}");
    assert!(!html.contains(&format!("href=\"{EVIL}")), "{html}");
}

#[test]
fn teams_digest_breaks_upstream_markdown_links() {
    let c = crate::notify::teams::render(&digest_alert()).to_string();
    assert!(
        c.contains("- [postgres 17.2](https://example.com/17.2): fixes [click] (https://evil.example/x) & more"),
        "{c}"
    );
    assert!(!c.contains(&format!("]({EVIL}")), "{c}");
}

#[test]
fn smtp_auth_failures_hold_the_channel() {
    use email::{classify, MailError};
    for code in [530, 534, 535] {
        assert_eq!(
            classify(Some(code), true, "x".into()),
            MailError::Auth("x".into())
        );
    }
    assert_eq!(
        classify(Some(550), true, "x".into()),
        MailError::Permanent("x".into())
    );
    assert_eq!(
        classify(Some(421), false, "x".into()),
        MailError::Transient("x".into())
    );
    assert_eq!(
        classify(None, false, "x".into()),
        MailError::Transient("x".into())
    );
}

#[test]
fn missing_env_names_the_variable() {
    let c = ch(
        "{type: webhook, name: w, url_env: CHANNELS_TEST_UNSET_URL, \
                secret_env: CHANNELS_TEST_UNSET_SECRET, min_severity: high}",
    );
    assert_eq!(
        missing_env(&c, &Secrets::new()).as_deref(),
        Some("CHANNELS_TEST_UNSET_URL")
    );
    let am = ch("{type: alertmanager, name: am, url: 'http://am:9093', min_severity: high}");
    assert_eq!(
        missing_env(&am, &Secrets::new()),
        None,
        "no secret needed without auth"
    );
}

#[test]
fn request_reads_secret_from_map_before_env() {
    let c = ch("{type: slack, name: s, webhook_env: 'ui:s:webhook', min_severity: high}");
    let url = "https://hooks.example/services/T/B/ui";
    let secrets = Secrets::from([("ui:s:webhook".to_string(), url.to_string())]);
    assert_eq!(
        missing_env(&c, &Secrets::new()).as_deref(),
        Some("ui:s:webhook")
    );
    assert_eq!(missing_env(&c, &secrets), None);
    let Request::Http { url: got, .. } = request(&c, &json!({}), now(), &secrets).unwrap() else {
        panic!("not http")
    };
    assert_eq!(got, url);
    // An empty value counts as unset.
    let empty = Secrets::from([("ui:s:webhook".to_string(), String::new())]);
    assert_eq!(missing_env(&c, &empty).as_deref(), Some("ui:s:webhook"));
}

#[test]
fn request_redacts_every_secret_it_uses() {
    let url = "https://hooks.example/services/T/B/secret-path";
    let secrets = Secrets::from([
        ("ui:x:url".to_string(), url.to_string()),
        ("ui:x:secret".to_string(), "hmac-key".to_string()),
    ]);
    for (yaml, want) in [
        (
            "{type: teams, name: x, webhook_env: 'ui:x:url', min_severity: high}",
            vec![url],
        ),
        (
            "{type: slack, name: x, webhook_env: 'ui:x:url', min_severity: high}",
            vec![url],
        ),
        (
            "{type: discord, name: x, webhook_env: 'ui:x:url', min_severity: high}",
            vec![url],
        ),
        (
            "{type: webhook, name: x, url_env: 'ui:x:url', secret_env: 'ui:x:secret', min_severity: high}",
            vec![url, "hmac-key"],
        ),
    ] {
        let c = ch(yaml);
        let Request::Http { redact, .. } = request(&c, &json!({}), now(), &secrets).unwrap() else {
            panic!("not http")
        };
        assert_eq!(redact, want, "{yaml}");
        assert_eq!(secret_values(&c, &secrets).len(), want.len(), "{yaml}");
    }
}

// ---- delivery ----

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 13, 10, 0, 0).unwrap()
}

fn cfg(yaml: &str) -> HeimdallConfig {
    HeimdallConfig::from_yaml(yaml).unwrap()
}

/// Queue `payload` for channel `name` of type `kind`, due long ago.
async fn queue(pool: &PgPool, name: &str, kind: &str, payload: &Value) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO outbox (group_key, card, route, channel_type, next_attempt_at) \
         VALUES ('alert|x', $1, $2, $3, '2000-01-01') RETURNING id",
    )
    .bind(payload)
    .bind(name)
    .bind(kind)
    .fetch_one(pool)
    .await
    .unwrap()
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
    card: Value,
}

async fn row(pool: &PgPool, id: i64) -> Row {
    sqlx::query_as("SELECT attempts, next_attempt_at, sent_at, card FROM outbox WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

/// A mailer that records messages and answers with `reply`.
struct FakeMailer {
    sent: Mutex<Vec<Vec<u8>>>,
    reply: Result<(), MailError>,
}

impl Mailer for FakeMailer {
    fn send<'a>(
        &'a self,
        _ch: &'a EmailChannel,
        msg: lettre::Message,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), MailError>> + Send + 'a>>
    {
        self.sent.lock().unwrap().push(msg.formatted());
        let reply = self.reply.clone();
        Box::pin(async move { reply })
    }
}

fn mailer(reply: Result<(), MailError>) -> FakeMailer {
    FakeMailer {
        sent: Mutex::new(Vec::new()),
        reply,
    }
}

async fn drain(pool: &PgPool, c: &HeimdallConfig) -> DrainResult {
    let http = reqwest::Client::new();
    let m = mailer(Ok(()));
    let d = Delivery {
        http: &http,
        mailer: &m,
    };
    drain_with(pool, &d, c, &chans(c), now()).await.unwrap()
}

async fn requests(server: &MockServer) -> Vec<WireRequest> {
    server.received_requests().await.unwrap_or_default()
}

#[sqlx::test(migrations = "./migrations")]
async fn slack_delivers_the_blocks(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/services/T/B/x"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_SLACK_OK", format!("{}/services/T/B/x", server.uri()));
    let c = cfg("realms: [prod]\nchannels:\n  - {type: slack, name: s, webhook_env: CH_SLACK_OK, min_severity: high}\n");
    let payload = slack::render(&vuln_alert());
    let id = queue(&pool, "s", "slack", &payload).await;
    let r = drain(&pool, &c).await;
    assert_eq!((r.sent, r.channel_type), (1, Some("slack")));
    assert!(row(&pool, id).await.sent_at.is_some());
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert_eq!(got, payload);
    // Exactly once: nothing left to send.
    assert_eq!(drain(&pool, &c).await, DrainResult::default());
}

#[sqlx::test(migrations = "./migrations")]
async fn discord_429_body_retry_after_is_honoured(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({"retry_after": 119.2})))
        .mount(&server)
        .await;
    std::env::set_var(
        "CH_DISCORD_429",
        format!("{}/api/webhooks/1/x", server.uri()),
    );
    let c = cfg("realms: [prod]\nchannels:\n  - {type: discord, name: d, webhook_env: CH_DISCORD_429, min_severity: high}\n");
    let id = queue(&pool, "d", "discord", &discord::render(&vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.retry, 1);
    let r = row(&pool, id).await;
    assert_eq!(r.attempts, 1);
    assert_eq!(r.next_attempt_at, now() + Duration::seconds(120));
}

#[sqlx::test(migrations = "./migrations")]
async fn telegram_sends_to_the_bot_path_and_hides_the_token(pool: PgPool) {
    let token = "123456:AAH-ch-tg-SECRET";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(format!("/bot{token}/sendMessage")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_TG_TOKEN", token);
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: telegram, name: tg, bot_token_env: CH_TG_TOKEN, \
         chat_id: -100123, api_url: '{}', min_severity: high}}\n",
        server.uri()
    ));
    let ChannelConfig::Telegram(t) = &c.channels[0] else {
        unreachable!()
    };
    assert_eq!(t.chat_id.as_string(), "-100123");
    let payload = render(&c.channels[0], &hostile_alert());
    let id = queue(&pool, "tg", "telegram", &payload).await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    assert!(row(&pool, id).await.sent_at.is_some());
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert_eq!(got["chat_id"], "-100123");
    assert!(got["text"].as_str().unwrap().contains("&lt;script&gt;"));
    // The payload stored in the database never holds the token.
    assert!(!row(&pool, id).await.card.to_string().contains("SECRET"));
}

#[sqlx::test(migrations = "./migrations")]
async fn telegram_429_parameters_retry_after_and_400_rejects(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/botT1/sendMessage"))
        .respond_with(ResponseTemplate::new(429).set_body_json(
            json!({"ok": false, "error_code": 429, "parameters": {"retry_after": 90}}),
        ))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/botT2/sendMessage"))
        .respond_with(ResponseTemplate::new(400).set_body_json(
            json!({"ok": false, "description": "Bad Request: can't parse entities"}),
        ))
        .mount(&server)
        .await;
    std::env::set_var("CH_TG_T1", "T1");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: telegram, name: tg, bot_token_env: CH_TG_T1, \
         chat_id: '@ops', api_url: '{}', min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(
        &pool,
        "tg",
        "telegram",
        &render(&c.channels[0], &vuln_alert()),
    )
    .await;
    assert_eq!(drain(&pool, &c).await.retry, 1);
    assert_eq!(
        row(&pool, id).await.next_attempt_at,
        now() + Duration::seconds(90)
    );

    std::env::set_var("CH_TG_T2", "T2");
    let c2 = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: telegram, name: tg2, bot_token_env: CH_TG_T2, \
         chat_id: '@ops', api_url: '{}', min_severity: high}}\n",
        server.uri()
    ));
    let id2 = queue(
        &pool,
        "tg2",
        "telegram",
        &render(&c2.channels[0], &vuln_alert()),
    )
    .await;
    let r = drain(&pool, &c2).await;
    assert_eq!((r.failed, r.channel_type), (1, Some("telegram")));
    let r2 = row(&pool, id2).await;
    assert!(r2.sent_at.is_some());
    assert_eq!(r2.card["failed"], json!(true));
}

#[sqlx::test(migrations = "./migrations")]
async fn pagerduty_adds_the_routing_key_at_send(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v2/enqueue"))
        .respond_with(ResponseTemplate::new(202).set_body_json(json!({"status": "success"})))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_PD_KEY", "R0UTINGKEY");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: pagerduty, name: pd, routing_key_env: CH_PD_KEY, \
         url: '{}/v2/enqueue', min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(&pool, "pd", "pagerduty", &pagerduty::render(&vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert_eq!(got["routing_key"], "R0UTINGKEY");
    assert_eq!(got["dedup_key"], "alert|vuln|GHSA-gin-0001");
    assert!(!row(&pool, id).await.card.to_string().contains("R0UTINGKEY"));
}

#[sqlx::test(migrations = "./migrations")]
async fn pagerduty_5xx_retries_with_retry_after(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "300"))
        .mount(&server)
        .await;
    std::env::set_var("CH_PD_503", "K");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: pagerduty, name: pd, routing_key_env: CH_PD_503, \
         url: '{}/v2/enqueue', min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(&pool, "pd", "pagerduty", &pagerduty::render(&vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.retry, 1);
    let r = row(&pool, id).await;
    assert!(r.sent_at.is_none());
    assert_eq!(r.next_attempt_at, now() + Duration::seconds(300));
}

#[sqlx::test(migrations = "./migrations")]
async fn alertmanager_posts_alerts_with_basic_auth_and_times(pool: PgPool) {
    let server = MockServer::start().await;
    // "am:s3cret" in base64.
    Mock::given(method("POST"))
        .and(path("/api/v2/alerts"))
        .and(header("authorization", "Basic YW06czNjcmV0"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_AM_USER", "am");
    std::env::set_var("CH_AM_PASS", "s3cret");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: alertmanager, name: am, url: '{}/', \
         username_env: CH_AM_USER, password_env: CH_AM_PASS, expire_after_hours: 6, min_severity: high}}\n",
        server.uri()
    ));
    queue(
        &pool,
        "am",
        "alertmanager",
        &alertmanager::render(&vuln_alert()),
    )
    .await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    let alerts = got.as_array().unwrap();
    assert_eq!(alerts.len(), 2);
    assert_eq!(alerts[0]["startsAt"], "2026-11-13T10:00:00Z");
    assert_eq!(alerts[0]["endsAt"], "2026-11-13T16:00:00Z");
    assert_eq!(alerts[0]["labels"]["alertname"], "HeimdallVuln");
}

#[sqlx::test(migrations = "./migrations")]
async fn alertmanager_bearer_and_4xx(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("authorization", "Bearer T0KEN"))
        .respond_with(ResponseTemplate::new(400))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_AM_BEARER", "T0KEN");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: alertmanager, name: am, url: '{}', \
         bearer_token_env: CH_AM_BEARER, min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(
        &pool,
        "am",
        "alertmanager",
        &alertmanager::render(&vuln_alert()),
    )
    .await;
    assert_eq!(drain(&pool, &c).await.failed, 1);
    assert_eq!(row(&pool, id).await.card["failed"], json!(true));
}

#[sqlx::test(migrations = "./migrations")]
async fn webhook_signature_verifies(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_WH_URL", format!("{}/in", server.uri()));
    std::env::set_var("CH_WH_SECRET", "shh");
    let c = cfg(
        "realms: [prod]\nchannels:\n  - {type: webhook, name: w, url_env: CH_WH_URL, \
                 secret_env: CH_WH_SECRET, min_severity: high}\n",
    );
    queue(&pool, "w", "webhook", &webhook::render(&vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    let req = &requests(&server).await[0];
    let sig = req
        .headers
        .get("x-heimdall-signature")
        .unwrap()
        .to_str()
        .unwrap();
    // The timestamp is the send time; recompute the HMAC over
    // "{timestamp}.{body}" as the receiver got them.
    let ts: i64 = req
        .headers
        .get("x-heimdall-timestamp")
        .unwrap()
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(ts, now().timestamp());
    assert_eq!(sig, webhook::signature("shh", ts, &req.body));
    assert_ne!(sig, webhook::signature("wrong", ts, &req.body));
    assert_ne!(sig, webhook::signature("shh", ts + 1, &req.body));
    assert_eq!(req.headers.get("content-type").unwrap(), "application/json");
    let got: Value = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(got["alert"]["key"], "alert|vuln|GHSA-gin-0001");
}

#[sqlx::test(migrations = "./migrations")]
async fn webhook_without_secret_is_unsigned_and_5xx_backs_off(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    std::env::set_var("CH_WH_500", format!("{}/in", server.uri()));
    let c = cfg("realms: [prod]\nchannels:\n  - {type: webhook, name: w, url_env: CH_WH_500, min_severity: high}\n");
    let id = queue(&pool, "w", "webhook", &webhook::render(&vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.retry, 1);
    assert_eq!(
        row(&pool, id).await.next_attempt_at,
        now() + Duration::seconds(30)
    );
    assert!(requests(&server).await[0]
        .headers
        .get("x-heimdall-signature")
        .is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn email_goes_through_the_mailer(pool: PgPool) {
    let c = cfg(
        "realms: [prod]\nchannels:\n  - {type: email, name: mail, host: smtp.example.com, \
                 from: heimdall@example.com, to: [ops@example.com], min_severity: high}\n",
    );
    let http = reqwest::Client::new();

    let ok = mailer(Ok(()));
    let id = queue(&pool, "mail", "email", &email::render(&vuln_alert())).await;
    let d = Delivery {
        http: &http,
        mailer: &ok,
    };
    assert_eq!(
        drain_with(&pool, &d, &c, &chans(&c), now())
            .await
            .unwrap()
            .sent,
        1
    );
    let sent = ok.sent.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let raw = String::from_utf8(sent[0].clone()).unwrap();
    assert!(raw.contains("To: ops@example.com"), "{raw}");
    assert!(row(&pool, id).await.sent_at.is_some());

    let flaky = mailer(Err(MailError::Transient("421 try later".into())));
    let id = queue(&pool, "mail", "email", &email::render(&vuln_alert())).await;
    let d = Delivery {
        http: &http,
        mailer: &flaky,
    };
    assert_eq!(
        drain_with(&pool, &d, &c, &chans(&c), now())
            .await
            .unwrap()
            .retry,
        1
    );
    assert!(row(&pool, id).await.sent_at.is_none());

    let refusing = mailer(Err(MailError::Permanent("550 no such user".into())));
    let d = Delivery {
        http: &http,
        mailer: &refusing,
    };
    sqlx::query("UPDATE outbox SET next_attempt_at = '2000-01-01' WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        drain_with(&pool, &d, &c, &chans(&c), now())
            .await
            .unwrap()
            .failed,
        1
    );
    assert_eq!(row(&pool, id).await.card["failed"], json!(true));
}

#[sqlx::test(migrations = "./migrations")]
async fn smtp_auth_failure_holds_the_backlog(pool: PgPool) {
    let c = cfg(
        "realms: [prod]\nchannels:\n  - {type: email, name: mail, host: smtp.example.com, \
                 from: heimdall@example.com, to: [ops@example.com], min_severity: high}\n",
    );
    let http = reqwest::Client::new();
    let bad_login = mailer(Err(MailError::Auth("535 bad credentials".into())));
    let d = Delivery {
        http: &http,
        mailer: &bad_login,
    };
    let ids = [
        queue(&pool, "mail", "email", &email::render(&vuln_alert())).await,
        queue(&pool, "mail", "email", &email::render(&vuln_alert())).await,
        queue(&pool, "mail", "email", &email::render(&vuln_alert())).await,
    ];
    let r = drain_with(&pool, &d, &c, &chans(&c), now()).await.unwrap();
    assert_eq!((r.retry, r.failed), (1, 0));
    for id in ids {
        let row = row(&pool, id).await;
        assert!(row.sent_at.is_none(), "nothing discarded");
        assert_eq!(row.next_attempt_at, now() + Duration::seconds(30));
    }
    // The whole channel waits: nothing else is tried until then.
    assert_eq!(
        drain_with(&pool, &d, &c, &chans(&c), now()).await.unwrap(),
        DrainResult::default()
    );
    assert_eq!(bad_login.sent.lock().unwrap().len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn orphaned_rows_are_found(pool: PgPool) {
    let c = cfg("realms: [prod]\nteams:\n  - {name: ops, webhook_env: CH_ORPHAN_UNSET, min_severity: high}\n");
    queue(&pool, "ops", "teams", &json!({})).await;
    queue(&pool, "ops", "slack", &json!({})).await;
    queue(&pool, "gone", "teams", &json!({})).await;
    let sent = queue(&pool, "old", "email", &json!({})).await;
    sqlx::query("UPDATE outbox SET sent_at = now() WHERE id = $1")
        .bind(sent)
        .execute(&pool)
        .await
        .unwrap();
    let o = crate::notify::outbox::orphaned(&pool, &chans(&c))
        .await
        .unwrap();
    assert_eq!(
        o,
        vec![
            ("gone".to_string(), "teams".to_string()),
            ("ops".to_string(), "slack".to_string())
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rows_of_another_type_or_without_secret_stay_queued(pool: PgPool) {
    // A Teams card queued for "ops", which is now a Slack channel.
    std::env::set_var("CH_TYPE_CHANGED", "http://127.0.0.1:9/never");
    let c = cfg("realms: [prod]\nchannels:\n  - {type: slack, name: ops, webhook_env: CH_TYPE_CHANGED, min_severity: high}\n");
    let id = queue(&pool, "ops", "teams", &json!({"type": "message"})).await;
    assert_eq!(drain(&pool, &c).await, DrainResult::default());
    // A channel whose secret is not set.
    let c = cfg("realms: [prod]\nchannels:\n  - {type: pagerduty, name: pd, routing_key_env: CH_NEVER_SET_KEY, min_severity: high}\n");
    let id2 = queue(&pool, "pd", "pagerduty", &json!({})).await;
    assert_eq!(drain(&pool, &c).await, DrainResult::default());
    for id in [id, id2] {
        let r = row(&pool, id).await;
        assert!(r.sent_at.is_none());
        assert_eq!(r.attempts, 0);
    }
}

// ---- end to end ----

async fn open_vuln(pool: &PgPool, realm: &str, svc: &str, key: &str) -> i64 {
    let sid = crate::inventory::store::upsert_service(pool, realm, svc)
        .await
        .unwrap();
    sqlx::query_scalar(
        "INSERT INTO findings (key, kind, realm, service_id, ref_id, severity, details) \
         VALUES ($1, 'vuln', $2, $3, 'GHSA-e2e', 'critical', $4) RETURNING id",
    )
    .bind(key)
    .bind(realm)
    .bind(sid)
    .bind(
        json!({"purl": "pkg:npm/a@1.0.0", "version": "1.0.0", "advice": null,
                 "oath": null, "direct": true, "match_source": "osv"}),
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn teams_and_slack_routes_in_different_realms(pool: PgPool) {
    let teams = MockServer::start().await;
    let slack_srv = MockServer::start().await;
    for s in [&teams, &slack_srv] {
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(s)
            .await;
    }
    std::env::set_var("CH_E2E_TEAMS", format!("{}/teams", teams.uri()));
    std::env::set_var("CH_E2E_SLACK", format!("{}/slack", slack_srv.uri()));
    let c = cfg("realms: [prod, dev, stage]\n\
                 teams:\n  - {name: prod-teams, webhook_env: CH_E2E_TEAMS, realms: [prod], min_severity: high}\n\
                 channels:\n  - {type: slack, name: dev-slack, webhook_env: CH_E2E_SLACK, realms: [dev], min_severity: high}\n");
    let prod = open_vuln(&pool, "prod", "api", "e2e|prod").await;
    let dev = open_vuln(&pool, "dev", "web", "e2e|dev").await;
    let stage = open_vuln(&pool, "stage", "db", "e2e|stage").await;

    assert_eq!(
        crate::notify::enqueue_alerts(&pool, &c, &chans(&c))
            .await
            .unwrap(),
        2
    );
    let rows: Vec<(String, String, Value)> =
        sqlx::query_as("SELECT route, channel_type, card FROM outbox ORDER BY route")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        (rows[0].0.as_str(), rows[0].1.as_str()),
        ("dev-slack", "slack")
    );
    assert_eq!(
        (rows[1].0.as_str(), rows[1].1.as_str()),
        ("prod-teams", "teams")
    );
    // Each channel sees only its realm.
    assert!(rows[0].2.to_string().contains("dev / web"));
    assert!(!rows[0].2.to_string().contains("prod / api"));
    assert!(rows[1].2.to_string().contains("prod / api"));

    // The realm no channel covers stays pending.
    let pending: Vec<i64> =
        sqlx::query_scalar("SELECT id FROM findings WHERE notified_at IS NULL ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(pending, vec![stage]);
    let _ = (prod, dev);

    // Queued "now" by the database; the test clock is fixed, so make them due.
    sqlx::query("UPDATE outbox SET next_attempt_at = '2000-01-01'")
        .execute(&pool)
        .await
        .unwrap();
    let mut sent = 0;
    for _ in 0..3 {
        sent += drain(&pool, &c).await.sent;
    }
    assert_eq!(sent, 2);
    let t: Value = serde_json::from_slice(&requests(&teams).await[0].body).unwrap();
    assert_eq!(t["type"], "message");
    let s: Value = serde_json::from_slice(&requests(&slack_srv).await[0].body).unwrap();
    assert_eq!(s["blocks"][0]["type"], "header");
    teams.verify().await;
    slack_srv.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_and_first_run_go_to_every_covering_channel(pool: PgPool) {
    let c = cfg("realms: [prod, dev, stage]\n\
                 digest: {weekday: Mon, hour: 9, timezone: UTC}\n\
                 teams:\n  - {name: t, webhook_env: X, realms: [prod], min_severity: high}\n\
                 channels:\n\
                 \x20 - {type: email, name: m, host: h, from: a@b.c, to: [d@e.f], realms: [dev], min_severity: low}\n\
                 \x20 - {type: alertmanager, name: am, url: 'http://am:9093', min_severity: critical}\n\
                 \x20 - {type: pagerduty, name: pd, routing_key_env: K, realms: [stage], min_severity: low}\n\
                 \x20 - {type: alertmanager, name: am2, url: 'http://am:9093', realms: [dev], min_severity: critical, digest: true}\n");
    // A medium vuln in a realm only paging channels cover: no digest takes
    // it, so it stays pending.
    let sid = crate::inventory::store::upsert_service(&pool, "stage", "db")
        .await
        .unwrap();
    let medium: i64 = sqlx::query_scalar(
        "INSERT INTO findings (key, kind, realm, service_id, ref_id, severity, details) \
         VALUES ('d|stage', 'vuln', 'stage', $1, 'GHSA-m', 'medium', '{}') RETURNING id",
    )
    .bind(sid)
    .fetch_one(&pool)
    .await
    .unwrap();
    let monday = Utc.with_ymd_and_hms(2026, 11, 16, 9, 30, 0).unwrap();
    assert!(
        crate::notify::digest::maybe_send(&pool, &c, &chans(&c), monday)
            .await
            .unwrap()
    );
    assert!(
        crate::notify::enqueue_first_run_summary(&pool, &c, &chans(&c), "dev")
            .await
            .unwrap()
    );
    let rows: Vec<(String, String, String)> =
        sqlx::query_as("SELECT group_key, route, channel_type FROM outbox ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let digest: Vec<&str> = rows
        .iter()
        .filter(|r| r.0.starts_with("digest|"))
        .map(|r| r.1.as_str())
        .collect();
    // Paging channels skip the digest unless they opt in (am2).
    assert_eq!(digest, vec!["t", "m", "am2"]);
    let first: Vec<&str> = rows
        .iter()
        .filter(|r| r.0 == "first_run|dev")
        .map(|r| r.1.as_str())
        .collect();
    assert_eq!(first, vec!["m", "am2"]);
    assert!(
        !crate::notify::enqueue_first_run_summary(&pool, &c, &chans(&c), "stage")
            .await
            .unwrap(),
        "no summary for a realm only a paging channel covers"
    );
    let pending: Option<DateTime<Utc>> =
        sqlx::query_scalar("SELECT notified_at FROM findings WHERE id = $1")
            .bind(medium)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(pending.is_none());
}
