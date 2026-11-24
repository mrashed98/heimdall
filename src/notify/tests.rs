//! Gjallarhorn tests against a real database (sqlx::test); Teams is a wiremock.

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::digest::maybe_send;
use super::outbox::drain_once;
use super::store::{Channels, UiState};
use super::*;
use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
use crate::model::Source;
use crate::secrets::SecretKey;

const ADV: &str = "GHSA-gin-0001";
const GIN: &str = "pkg:golang/github.com/gin-gonic/gin";

fn cfg(yaml: &str) -> HeimdallConfig {
    serde_saphyr::from_str(yaml).unwrap()
}

/// Realms prod and dev, one route for everything high or worse.
fn one_route(env: &str) -> HeimdallConfig {
    cfg(&format!(
        "realms: [prod, dev]\n\
         teams:\n  - name: all\n    webhook_env: {env}\n    min_severity: high\n"
    ))
}

/// The config channels alone.
fn chans(c: &HeimdallConfig) -> Channels {
    Channels::from_config(c)
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 13, 10, 0, 0).unwrap()
}

async fn service(pool: &PgPool, realm: &str, name: &str) -> i64 {
    upsert_service(pool, realm, name).await.unwrap()
}

static NEXT_KEY: AtomicU64 = AtomicU64::new(0);

/// Insert an open finding directly (the matcher and watchers are tested
/// elsewhere); returns its id.
async fn finding(
    pool: &PgPool,
    kind: &str,
    realm: &str,
    service_id: Option<i64>,
    ref_id: &str,
    severity: &str,
    details: Value,
) -> i64 {
    let k = format!("test|{}", NEXT_KEY.fetch_add(1, Ordering::SeqCst));
    sqlx::query_scalar(
        "INSERT INTO findings (key, kind, realm, service_id, ref_id, severity, details) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
    )
    .bind(k)
    .bind(kind)
    .bind(realm)
    .bind(service_id)
    .bind(ref_id)
    .bind(severity)
    .bind(details)
    .fetch_one(pool)
    .await
    .unwrap()
}

fn vuln_details(version: &str, advice: Value, oath: Value) -> Value {
    json!({
        "purl": format!("{GIN}@{version}"),
        "version": version,
        "fixed": [],
        "advice": advice,
        "oath": oath,
        "direct": true,
        "match_source": "osv",
        "scores": {"osv": 7.5},
    })
}

async fn vuln(pool: &PgPool, realm: &str, svc: &str, severity: &str) -> i64 {
    let sid = service(pool, realm, svc).await;
    finding(
        pool,
        "vuln",
        realm,
        Some(sid),
        ADV,
        severity,
        vuln_details("v1.9.0", Value::Null, Value::Null),
    )
    .await
}

async fn fix(pool: &PgPool, realm: &str, svc: &str, severity: &str) -> i64 {
    let sid = service(pool, realm, svc).await;
    finding(
        pool,
        "fixavailable",
        realm,
        Some(sid),
        ADV,
        severity,
        json!({
            "purl": format!("{GIN}@v1.9.0"),
            "version": "v1.9.0",
            "advice": {"suggest": "v1.9.1", "latest": "v1.10.0"},
            "direct": true,
            "advisory": ADV,
        }),
    )
    .await
}

#[derive(Debug, sqlx::FromRow)]
struct OutRow {
    id: i64,
    group_key: String,
    route: String,
    card: Value,
    attempts: i32,
    next_attempt_at: DateTime<Utc>,
    sent_at: Option<DateTime<Utc>>,
}

async fn outbox(pool: &PgPool) -> Vec<OutRow> {
    sqlx::query_as(
        "SELECT id, group_key, route, card, attempts, next_attempt_at, sent_at \
         FROM outbox ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

/// The card's title (the first TextBlock).
fn title(card: &Value) -> String {
    card["attachments"][0]["content"]["body"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

async fn notified_status(pool: &PgPool, id: i64) -> (bool, String) {
    let (n, s): (Option<DateTime<Utc>>, String) =
        sqlx::query_as("SELECT notified_at, status FROM findings WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await
            .unwrap();
    (n.is_some(), s)
}

// ---- enqueue ----

#[sqlx::test(migrations = "./migrations")]
async fn one_card_per_advisory_across_services(pool: PgPool) {
    for svc in ["api", "web", "worker"] {
        vuln(&pool, "prod", svc, "high").await;
    }
    let n = enqueue_alerts(
        &pool,
        &one_route("NOTIFY_T1"),
        &chans(&one_route("NOTIFY_T1")),
    )
    .await
    .unwrap();
    assert_eq!(n, 1);
    let rows = outbox(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].route, "all");
    assert_eq!(
        title(&rows[0].card),
        format!("⚠ {ADV} (high) affects 3 service(s)")
    );
    let text = rows[0].card.to_string();
    for svc in ["api", "web", "worker"] {
        assert!(text.contains(svc), "{svc} missing: {text}");
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn oathed_vuln_not_alerted_but_fix_available_is(pool: PgPool) {
    let sid = service(&pool, "prod", "api").await;
    let v = finding(
        &pool,
        "vuln",
        "prod",
        Some(sid),
        ADV,
        "critical",
        vuln_details("v1.9.0", Value::Null, json!(7)),
    )
    .await;
    let f = fix(&pool, "prod", "api", "critical").await;
    enqueue_alerts(
        &pool,
        &one_route("NOTIFY_T2"),
        &chans(&one_route("NOTIFY_T2")),
    )
    .await
    .unwrap();
    let rows = outbox(&pool).await;
    assert_eq!(rows.len(), 1);
    assert!(
        title(&rows[0].card).starts_with("Fix available: upgrade github.com/gin-gonic/gin"),
        "{}",
        title(&rows[0].card)
    );
    assert_eq!(notified_status(&pool, v).await, (false, "open".into()));
    assert_eq!(notified_status(&pool, f).await, (true, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn medium_not_immediate(pool: PgPool) {
    let v = vuln(&pool, "prod", "api", "medium").await;
    let low_route =
        cfg("realms: [prod]\nteams:\n  - {name: all, webhook_env: X, min_severity: low}\n");
    assert_eq!(
        enqueue_alerts(&pool, &low_route, &chans(&low_route))
            .await
            .unwrap(),
        0
    );
    assert!(outbox(&pool).await.is_empty());
    assert_eq!(notified_status(&pool, v).await, (false, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn enqueue_is_idempotent(pool: PgPool) {
    vuln(&pool, "prod", "api", "critical").await;
    let c = one_route("NOTIFY_T4");
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 1);
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 0);
    assert_eq!(outbox(&pool).await.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn first_run_summary_once_and_first(pool: PgPool) {
    vuln(&pool, "prod", "api", "high").await;
    vuln(&pool, "prod", "web", "medium").await;
    let c = one_route("NOTIFY_T5");
    assert!(enqueue_first_run_summary(&pool, &c, &chans(&c), "prod")
        .await
        .unwrap());
    enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap();
    assert!(!enqueue_first_run_summary(&pool, &c, &chans(&c), "prod")
        .await
        .unwrap());

    let rows = outbox(&pool).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(title(&rows[0].card), "Heimdall has opened his eyes");
    assert!(rows[0].id < rows[1].id);
    let text = rows[0].card.to_string();
    assert!(text.contains("prod"), "{text}");
    assert!(text.contains("\"High\""), "{text}");
    assert!(text.contains("\"Medium\""), "{text}");
}

#[sqlx::test(migrations = "./migrations")]
async fn routes_by_realm_and_severity(pool: PgPool) {
    let c = cfg("realms: [prod, dev]\n\
         teams:\n\
           - {name: crit, webhook_env: A, min_severity: critical}\n\
           - {name: prodhigh, webhook_env: B, realms: [prod], min_severity: high}\n\
           - {name: devlow, webhook_env: C, realms: [dev], min_severity: low}\n");
    vuln(&pool, "prod", "api", "high").await;
    finding(
        &pool,
        "majorrelease",
        "dev",
        None,
        "17.0",
        "high",
        json!({"target": "postgres", "version": "17.0", "current": "16.4", "line": "17"}),
    )
    .await;
    // A medium release-note CVE still reaches a high route.
    finding(
        &pool,
        "releasenotecve",
        "prod",
        None,
        "GHSA-other",
        "medium",
        json!({"target": "pkg:npm/p", "version": "1.2.3", "id": "CVE-2026-1",
               "ids": ["CVE-2026-1"], "advisory": "GHSA-other", "services": ["api"],
               "notes_url": "https://example.com/notes"}),
    )
    .await;
    enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap();
    let mut got: Vec<(String, String)> = outbox(&pool)
        .await
        .into_iter()
        .map(|r| (r.route, title(&r.card)))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            (
                "devlow".to_string(),
                "postgres 17.0 released (major)".to_string()
            ),
            (
                "prodhigh".to_string(),
                "pkg:npm/p 1.2.3 release notes mention CVE-2026-1 (affects api)".to_string()
            ),
            (
                "prodhigh".to_string(),
                format!("⚠ {ADV} (high) affects 1 service(s)")
            ),
        ]
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn oath_expired_and_vuln_give_one_card(pool: PgPool) {
    let v = vuln(&pool, "prod", "api", "high").await;
    let o = finding(
        &pool,
        "oathexpired",
        "prod",
        None,
        ADV,
        "high",
        json!({"oath": 3, "advisory": ADV, "name_key": GIN, "service": "api", "realm": "prod",
               "kind": "snooze", "reason": "not reachable", "version_at_creation": "v1.9.0"}),
    )
    .await;
    enqueue_alerts(
        &pool,
        &one_route("NOTIFY_T7"),
        &chans(&one_route("NOTIFY_T7")),
    )
    .await
    .unwrap();
    let rows = outbox(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(title(&rows[0].card), format!("Oath expired: {ADV} on api"));
    assert_eq!(notified_status(&pool, v).await, (true, "open".into()));
    // One-shot: resolved when announced.
    assert_eq!(notified_status(&pool, o).await, (true, "resolved".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn one_shot_kinds_resolve_when_notified(pool: PgPool) {
    let k = finding(
        &pool,
        "k8scve",
        "prod",
        None,
        "CVE-2026-9",
        "high",
        json!({"id": "CVE-2026-9", "summary": "kubelet bug", "url": "https://github.com/k/k/issues/1"}),
    )
    .await;
    let e = finding(
        &pool,
        "eol",
        "prod",
        None,
        "16",
        "high",
        json!({"target": "postgres", "cycle": "16", "eol": "2026-12-01", "version": "16.4", "latest": "16.9"}),
    )
    .await;
    enqueue_alerts(
        &pool,
        &one_route("NOTIFY_T8"),
        &chans(&one_route("NOTIFY_T8")),
    )
    .await
    .unwrap();
    assert_eq!(notified_status(&pool, k).await, (true, "resolved".into()));
    assert_eq!(notified_status(&pool, e).await, (true, "open".into()));
    let titles: Vec<String> = outbox(&pool).await.iter().map(|r| title(&r.card)).collect();
    assert!(titles.contains(&"Kubernetes security advisory CVE-2026-9".to_string()));
    assert!(titles.contains(&"postgres 16 reaches end of support on 2026-12-01".to_string()));
}

#[sqlx::test(migrations = "./migrations")]
async fn revoked_oath_vuln_alerts(pool: PgPool) {
    // Opened under an oath: quiet.
    let sid = service(&pool, "prod", "api").await;
    let v = finding(
        &pool,
        "vuln",
        "prod",
        Some(sid),
        ADV,
        "high",
        vuln_details("v1.9.0", Value::Null, json!(4)),
    )
    .await;
    let c = one_route("NOTIFY_T9");
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 0);
    // The oath was revoked; the matcher clears details.oath.
    sqlx::query("UPDATE findings SET details = jsonb_set(details, '{oath}', 'null') WHERE id = $1")
        .bind(v)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn fix_for_alerted_vuln_folds_into_its_card(pool: PgPool) {
    vuln(&pool, "prod", "api", "high").await;
    let f = fix(&pool, "prod", "api", "high").await;
    enqueue_alerts(
        &pool,
        &one_route("NOTIFY_T10"),
        &chans(&one_route("NOTIFY_T10")),
    )
    .await
    .unwrap();
    let rows = outbox(&pool).await;
    assert_eq!(
        rows.len(),
        1,
        "{:?}",
        rows.iter().map(|r| title(&r.card)).collect::<Vec<_>>()
    );
    assert!(title(&rows[0].card).starts_with("⚠"));
    assert_eq!(notified_status(&pool, f).await, (true, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn no_routes_leaves_findings_pending(pool: PgPool) {
    let v = vuln(&pool, "prod", "api", "critical").await;
    let c = cfg("realms: [prod]\n");
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 0);
    assert_eq!(notified_status(&pool, v).await, (false, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn medium_fix_and_expired_oath_reach_a_high_route(pool: PgPool) {
    // The medium vuln was opened a day before its fix appeared (and went to
    // the digest), so the fix alerts.
    let v = vuln(&pool, "prod", "api", "medium").await;
    sqlx::query("UPDATE findings SET opened_at = now() - interval '1 day', notified_at = now() WHERE id = $1")
        .bind(v)
        .execute(&pool)
        .await
        .unwrap();
    let f = fix(&pool, "prod", "api", "medium").await;
    finding(
        &pool,
        "oathexpired",
        "prod",
        None,
        "GHSA-med",
        "medium",
        json!({"oath": 9, "advisory": "GHSA-med", "name_key": GIN, "service": "web",
               "realm": "prod", "kind": "ignore", "reason": "r", "version_at_creation": "v1"}),
    )
    .await;
    assert_eq!(
        enqueue_alerts(
            &pool,
            &one_route("NOTIFY_T11"),
            &chans(&one_route("NOTIFY_T11"))
        )
        .await
        .unwrap(),
        2
    );
    let titles: Vec<String> = outbox(&pool).await.iter().map(|r| title(&r.card)).collect();
    assert!(
        titles.iter().any(|t| t.starts_with("Fix available")),
        "{titles:?}"
    );
    assert!(
        titles.contains(&"Oath expired: GHSA-med on web".to_string()),
        "{titles:?}"
    );
    assert_eq!(notified_status(&pool, f).await, (true, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn realm_without_route_stays_pending(pool: PgPool) {
    let c = cfg("realms: [prod, dev]\n\
         teams:\n  - {name: prod, webhook_env: A, realms: [prod], min_severity: low}\n");
    let v = vuln(&pool, "dev", "api", "critical").await;
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 0);
    assert!(outbox(&pool).await.is_empty());
    assert_eq!(notified_status(&pool, v).await, (false, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn severity_opt_out_is_marked(pool: PgPool) {
    let c = cfg("realms: [prod]\n\
         teams:\n  - {name: crit, webhook_env: A, min_severity: critical}\n");
    let v = vuln(&pool, "prod", "api", "high").await;
    assert_eq!(enqueue_alerts(&pool, &c, &chans(&c)).await.unwrap(), 0);
    assert!(outbox(&pool).await.is_empty());
    assert_eq!(notified_status(&pool, v).await, (true, "open".into()));
}

// ---- drain ----

/// One queued card for route `all`, due long ago.
async fn queued(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "INSERT INTO outbox (group_key, card, route, next_attempt_at) \
         VALUES ('alert|x', '{\"type\": \"message\"}', 'all', '2000-01-01') RETURNING id",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

fn with_webhook(env: &str, server: &MockServer) -> HeimdallConfig {
    std::env::set_var(env, format!("{}/hook", server.uri()));
    one_route(env)
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_429_honours_retry_after(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "120"))
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_429", &server);
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r.retry, 1);
    assert_eq!(r.sent, 0);
    let row = &outbox(&pool).await[0];
    assert_eq!(row.attempts, 1);
    assert_eq!(row.next_attempt_at, now() + Duration::seconds(120));
    assert!(row.sent_at.is_none());
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_5xx_backs_off_exponentially(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_503", &server);
    let id = queued(&pool).await;
    sqlx::query("UPDATE outbox SET attempts = 2 WHERE id = $1")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    let row = &outbox(&pool).await[0];
    assert_eq!(row.attempts, 3);
    // 30 s x 2^2
    assert_eq!(row.next_attempt_at, now() + Duration::seconds(120));
    // Not due yet: nothing is sent.
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r, outbox::DrainResult::default());
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_sends_exactly_once_after_restart(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_OK", &server);
    queued(&pool).await;
    let first = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(first.sent, 1);
    // A fresh client, as after a restart.
    let again = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(again.sent, 0);
    assert!(outbox(&pool).await[0].sent_at.is_some());
    server.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_other_4xx_marks_failed(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_400", &server);
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r.failed, 1);
    let row = &outbox(&pool).await[0];
    assert!(row.sent_at.is_some());
    assert_eq!(row.card["failed"], json!(true));
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_without_webhook_leaves_rows_queued(pool: PgPool) {
    let c = one_route("NOTIFY_HOOK_UNSET_NEVER_DEFINED");
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r, outbox::DrainResult::default());
    let row = &outbox(&pool).await[0];
    assert!(row.sent_at.is_none());
    assert_eq!(row.attempts, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_network_error_retries(pool: PgPool) {
    // Nothing listens on port 9 (discard).
    std::env::set_var("NOTIFY_HOOK_DOWN", "http://127.0.0.1:9/hook");
    let c = one_route("NOTIFY_HOOK_DOWN");
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r.retry, 1);
    let row = &outbox(&pool).await[0];
    assert_eq!(row.next_attempt_at, now() + Duration::seconds(30));
}

#[sqlx::test(migrations = "./migrations")]
async fn drain_huge_retry_after_is_clamped(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "99999999999999999"))
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_HUGE", &server);
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r.retry, 1);
    let row = &outbox(&pool).await[0];
    assert_eq!(row.next_attempt_at, now() + Duration::hours(1));
}

// ---- digest ----

/// Digest on Monday 09:00 Berlin time, one route for everything.
fn digest_cfg() -> HeimdallConfig {
    cfg("realms: [prod]\n\
         digest: {weekday: Mon, hour: 9, timezone: Europe/Berlin}\n\
         teams:\n  - {name: all, webhook_env: X, min_severity: high}\n")
}

/// 2026-11-16 is a Monday; Berlin is UTC+1 in November.
fn monday_0910() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 16, 8, 10, 0).unwrap()
}

async fn digest_text(pool: &PgPool) -> String {
    let rows = outbox(pool).await;
    let d: Vec<&OutRow> = rows
        .iter()
        .filter(|r| r.group_key.starts_with("digest|"))
        .collect();
    assert_eq!(d.len(), 1);
    d[0].card.to_string()
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_monday_9_once(pool: PgPool) {
    let c = digest_cfg();
    assert!(maybe_send(&pool, &c, &chans(&c), monday_0910())
        .await
        .unwrap());
    assert!(
        !maybe_send(&pool, &c, &chans(&c), monday_0910() + Duration::minutes(30))
            .await
            .unwrap()
    );
    assert!(
        !maybe_send(&pool, &c, &chans(&c), monday_0910() + Duration::days(1))
            .await
            .unwrap()
    );
    // 08:40 on the next Monday is before the slot.
    assert!(!maybe_send(
        &pool,
        &c,
        &chans(&c),
        monday_0910() + Duration::days(7) - Duration::minutes(30)
    )
    .await
    .unwrap());
    assert!(
        maybe_send(&pool, &c, &chans(&c), monday_0910() + Duration::days(7))
            .await
            .unwrap()
    );
    assert_eq!(outbox(&pool).await.len(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_catches_up_after_missing_the_slot(pool: PgPool) {
    let c = digest_cfg();
    assert!(maybe_send(&pool, &c, &chans(&c), monday_0910())
        .await
        .unwrap());
    // The pod was down all of the next Monday's 09:00 hour.
    let next_monday_1010 = monday_0910() + Duration::days(7) + Duration::hours(1);
    assert!(maybe_send(&pool, &c, &chans(&c), next_monday_1010)
        .await
        .unwrap());
    // Once per slot, even on later days.
    assert!(
        !maybe_send(&pool, &c, &chans(&c), next_monday_1010 + Duration::days(2))
            .await
            .unwrap()
    );
    assert_eq!(outbox(&pool).await.len(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_hour_in_dst_gap_fires_at_next_valid_time(pool: PgPool) {
    // Berlin 2026-03-29: 02:00 does not exist (clocks jump to 03:00 CEST).
    let c = cfg("realms: [prod]\n\
         digest: {weekday: Sun, hour: 2, timezone: Europe/Berlin}\n\
         teams:\n  - {name: all, webhook_env: X, min_severity: high}\n");
    // The previous week's slot was sent, so only the gap day is under test.
    sqlx::query("INSERT INTO kv (key, value) VALUES ('digest_last', '2026-03-22')")
        .execute(&pool)
        .await
        .unwrap();
    // 00:59 UTC = 01:59 CET: before the slot.
    let before = Utc.with_ymd_and_hms(2026, 3, 29, 0, 59, 0).unwrap();
    assert!(!maybe_send(&pool, &c, &chans(&c), before).await.unwrap());
    // 01:00 UTC = 03:00 CEST: the first valid local time.
    let at = Utc.with_ymd_and_hms(2026, 3, 29, 1, 0, 0).unwrap();
    assert!(maybe_send(&pool, &c, &chans(&c), at).await.unwrap());
    assert!(!maybe_send(&pool, &c, &chans(&c), at + Duration::hours(1))
        .await
        .unwrap());
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_lists_medium_vulns_and_marks_them(pool: PgPool) {
    let m = vuln(&pool, "prod", "api", "medium").await;
    let h = vuln(&pool, "prod", "web", "high").await;
    assert!(
        maybe_send(&pool, &digest_cfg(), &chans(&digest_cfg()), monday_0910())
            .await
            .unwrap()
    );
    let text = digest_text(&pool).await;
    assert!(text.contains(&format!("{ADV} (medium)")), "{text}");
    assert_eq!(notified_status(&pool, m).await, (true, "open".into()));
    assert_eq!(notified_status(&pool, h).await, (false, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_flags_carried_oath(pool: PgPool) {
    let sid = service(&pool, "prod", "api").await;
    replace_components(
        &pool,
        sid,
        Source::Git,
        &[InventoryItem {
            purl: format!("{GIN}@v1.9.2"),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        }],
    )
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO oaths (advisory_id, name_key, service_name, realm, kind, reason, \
         version_at_creation, expires_at, created_by) \
         VALUES ($1, $2, 'api', 'prod', 'snooze', 'not reachable', 'v1.9.0', '2026-12-31T00:00:00Z', 'alice')",
    )
    .bind(ADV)
    .bind(GIN)
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        maybe_send(&pool, &digest_cfg(), &chans(&digest_cfg()), monday_0910())
            .await
            .unwrap()
    );
    let text = digest_text(&pool).await;
    assert!(text.contains(ADV), "{text}");
    assert!(text.contains("expires 2026-12-31"), "{text}");
    assert!(text.contains("carried to new version v1.9.2"), "{text}");
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_lists_release_notes_by_class(pool: PgPool) {
    let rows = [
        ("1.0.1", "plain", json!(null)),
        (
            "1.0.2",
            "bugfix",
            json!({"fix": ["fix crash on empty input", "fix leak"], "breaking": []}),
        ),
        ("1.0.3", "none", json!(null)),
        ("1.0.4", "security", json!(null)),
        ("2.0.0", "plain", json!(null)),
    ];
    for (v, class, excerpt) in rows {
        sqlx::query(
            "INSERT INTO releases (target, version, published_at, is_major, notes_class, excerpt) \
             VALUES ('pkg:npm/lib', $1, '2026-11-14T00:00:00Z', $2, $3, $4)",
        )
        .bind(v)
        .bind(v == "2.0.0")
        .bind(class)
        .bind(excerpt)
        .execute(&pool)
        .await
        .unwrap();
    }
    assert!(
        maybe_send(&pool, &digest_cfg(), &chans(&digest_cfg()), monday_0910())
            .await
            .unwrap()
    );
    let text = digest_text(&pool).await;
    let at = |s: &str| {
        text.find(s)
            .unwrap_or_else(|| panic!("{s} missing: {text}"))
    };
    assert!(at("Security") < at("1.0.4"));
    assert!(at("1.0.4") < at("Bug fixes"));
    assert!(at("Bug fixes") < at("fix crash on empty input"));
    assert!(at("fix crash on empty input") < at("Other"));
    assert!(at("Other") < at("1.0.1"));
    assert!(at("1.0.1") < at("No release notes found"));
    assert!(at("No release notes found") < at("1.0.3"));
    assert!(
        !text.contains("2.0.0"),
        "major releases are not digest material"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_lists_declared_since(pool: PgPool) {
    let sid = service(&pool, "prod", "postgres-vm").await;
    replace_components(
        &pool,
        sid,
        Source::Declared,
        &[InventoryItem {
            purl: "pkg:generic/postgresql@17.2".to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        }],
    )
    .await
    .unwrap();
    sqlx::query("UPDATE service_components SET declared_since = '2026-11-13T12:00:00Z'")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        maybe_send(&pool, &digest_cfg(), &chans(&digest_cfg()), monday_0910())
            .await
            .unwrap()
    );
    let text = digest_text(&pool).await;
    assert!(
        text.contains("postgres-vm: postgresql 17.2, declared since 2026-11-13"),
        "{text}"
    );
}

async fn release(pool: &PgPool, version: &str, published: &str) {
    sqlx::query(
        "INSERT INTO releases (target, version, published_at, notes_class) \
         VALUES ('pkg:npm/lib', $1, $2::timestamptz, 'plain')",
    )
    .bind(version)
    .bind(published)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_takes_releases_stored_late(pool: PgPool) {
    let c = digest_cfg();
    // First digest: only recent history counts.
    release(&pool, "1.0.0", "2026-10-01T00:00:00Z").await;
    release(&pool, "1.0.1", "2026-11-14T00:00:00Z").await;
    assert!(maybe_send(&pool, &c, &chans(&c), monday_0910())
        .await
        .unwrap());
    let first = digest_text(&pool).await;
    assert!(first.contains("1.0.1"), "{first}");
    assert!(!first.contains("1.0.0"), "{first}");

    // Published before the first digest, stored after it.
    release(&pool, "1.0.2", "2026-11-10T00:00:00Z").await;
    let next = monday_0910() + Duration::days(7);
    assert!(maybe_send(&pool, &c, &chans(&c), next).await.unwrap());
    let rows = outbox(&pool).await;
    let second = rows.last().unwrap().card.to_string();
    assert!(second.contains("1.0.2"), "{second}");
    assert!(!second.contains("1.0.1"), "{second}");
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_leaves_uncovered_realm_pending(pool: PgPool) {
    let c = cfg("realms: [prod, dev]\n\
         digest: {weekday: Mon, hour: 9, timezone: Europe/Berlin}\n\
         teams:\n  - {name: prod, webhook_env: X, realms: [prod], min_severity: high}\n");
    let covered = vuln(&pool, "prod", "api", "medium").await;
    let uncovered = vuln(&pool, "dev", "api", "medium").await;
    assert!(maybe_send(&pool, &c, &chans(&c), monday_0910())
        .await
        .unwrap());
    assert_eq!(notified_status(&pool, covered).await, (true, "open".into()));
    assert_eq!(
        notified_status(&pool, uncovered).await,
        (false, "open".into())
    );
}

// ---- when a fix alerts at once (the matcher writes the findings) ----

/// gin v1.9.0 in prod/api, linked to ADV at `severity`, with `fixed`.
async fn matched_gin(pool: &PgPool, severity: &str, fixed: &[&str]) {
    let sid = service(pool, "prod", "api").await;
    let purl = format!("{GIN}@v1.9.0");
    let item = InventoryItem {
        purl: purl.clone(),
        cpes: vec![],
        direct: true,
        via_image_digest: None,
    };
    replace_components(pool, sid, Source::Git, &[item])
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO advisories (id, severity, summary, fixed, source) \
         VALUES ($1, $2, 'test', $3, 'osv')",
    )
    .bind(ADV)
    .bind(severity)
    .bind(json!({ GIN: fixed }))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO component_advisories (component_id, advisory_id, match_source) \
         SELECT id, $2, 'osv' FROM components WHERE purl = $1",
    )
    .bind(&purl)
    .bind(ADV)
    .execute(pool)
    .await
    .unwrap();
}

async fn finding_id(pool: &PgPool, kind: &str) -> i64 {
    sqlx::query_scalar("SELECT id FROM findings WHERE kind = $1")
        .bind(kind)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test(migrations = "./migrations")]
async fn medium_vuln_with_fix_at_first_sight_goes_to_the_digest(pool: PgPool) {
    matched_gin(&pool, "medium", &["v1.9.1"]).await;
    crate::matcher::run(&pool, "prod", now()).await.unwrap();
    let low_route =
        cfg("realms: [prod]\nteams:\n  - {name: all, webhook_env: X, min_severity: low}\n");
    assert_eq!(
        enqueue_alerts(&pool, &low_route, &chans(&low_route))
            .await
            .unwrap(),
        0
    );
    let f = finding_id(&pool, "fixavailable").await;
    assert_eq!(notified_status(&pool, f).await, (false, "open".into()));

    // The digest lists the vuln with its fix, and takes the fix along.
    assert!(
        maybe_send(&pool, &digest_cfg(), &chans(&digest_cfg()), monday_0910())
            .await
            .unwrap()
    );
    let text = digest_text(&pool).await;
    assert!(text.contains(&format!("{ADV} (medium)")), "{text}");
    assert!(text.contains("fix: v1.9.1"), "{text}");
    assert_eq!(notified_status(&pool, f).await, (true, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn medium_vuln_whose_fix_appears_later_alerts_at_once(pool: PgPool) {
    matched_gin(&pool, "medium", &[]).await;
    crate::matcher::run(&pool, "prod", now()).await.unwrap();
    // A run later, OSV publishes a fixed version.
    sqlx::query("UPDATE advisories SET fixed = $1")
        .bind(json!({ GIN: ["v1.9.1"] }))
        .execute(&pool)
        .await
        .unwrap();
    crate::matcher::run(&pool, "prod", now() + Duration::minutes(15))
        .await
        .unwrap();
    assert_eq!(
        enqueue_alerts(
            &pool,
            &one_route("NOTIFY_I8B"),
            &chans(&one_route("NOTIFY_I8B"))
        )
        .await
        .unwrap(),
        1
    );
    let rows = outbox(&pool).await;
    assert!(
        title(&rows[0].card).starts_with("Fix available"),
        "{}",
        title(&rows[0].card)
    );
    let f = finding_id(&pool, "fixavailable").await;
    assert_eq!(notified_status(&pool, f).await, (true, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn high_vuln_with_fix_alerts_at_once(pool: PgPool) {
    matched_gin(&pool, "high", &["v1.9.1"]).await;
    crate::matcher::run(&pool, "prod", now()).await.unwrap();
    assert_eq!(
        enqueue_alerts(
            &pool,
            &one_route("NOTIFY_I8C"),
            &chans(&one_route("NOTIFY_I8C"))
        )
        .await
        .unwrap(),
        1,
        "one card: the fix folds into the vuln's"
    );
    let f = finding_id(&pool, "fixavailable").await;
    assert_eq!(notified_status(&pool, f).await, (true, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn late_fix_still_alerts_after_a_flap(pool: PgPool) {
    // Medium vuln first, its fix a run later (so the fix alerts at once).
    matched_gin(&pool, "medium", &[]).await;
    crate::matcher::run(&pool, "prod", now()).await.unwrap();
    sqlx::query("UPDATE advisories SET fixed = $1")
        .bind(json!({ GIN: ["v1.9.1"] }))
        .execute(&pool)
        .await
        .unwrap();
    crate::matcher::run(&pool, "prod", now() + Duration::minutes(15))
        .await
        .unwrap();
    // Before any alert went out, the service flaps away and back.
    let sid = service(&pool, "prod", "api").await;
    let item = InventoryItem {
        purl: format!("{GIN}@v1.9.0"),
        cpes: vec![],
        direct: true,
        via_image_digest: None,
    };
    replace_components(&pool, sid, Source::Git, &[])
        .await
        .unwrap();
    crate::matcher::run(&pool, "prod", now() + Duration::minutes(30))
        .await
        .unwrap();
    replace_components(&pool, sid, Source::Git, &[item])
        .await
        .unwrap();
    crate::matcher::run(&pool, "prod", now() + Duration::minutes(45))
        .await
        .unwrap();

    // The fix is still a late fix: it alerts, it is not swallowed.
    assert_eq!(
        enqueue_alerts(
            &pool,
            &one_route("NOTIFY_R3"),
            &chans(&one_route("NOTIFY_R3"))
        )
        .await
        .unwrap(),
        1
    );
    assert!(title(&outbox(&pool).await[0].card).starts_with("Fix available"));
}

// ---- baseline ----

#[sqlx::test(migrations = "./migrations")]
async fn baseline_marks_the_backlog_without_alerting(pool: PgPool) {
    let high = vuln(&pool, "prod", "api", "high").await;
    let fixed = fix(&pool, "prod", "api", "high").await;
    let k8s = finding(
        &pool,
        "k8scve",
        "prod",
        None,
        "CVE-2026-1",
        "high",
        json!({}),
    )
    .await;
    let other_realm = vuln(&pool, "dev", "api", "high").await;
    let cfg = one_route("NOTIFY_BASELINE");

    assert!(baseline(&pool, &cfg, &chans(&cfg), "nope").await.is_err());
    assert_eq!(
        baseline(&pool, &cfg, &chans(&cfg), "prod").await.unwrap(),
        3
    );

    assert_eq!(notified_status(&pool, high).await, (true, "open".into()));
    assert_eq!(notified_status(&pool, fixed).await, (true, "open".into()));
    // One-shot kinds resolve as if they had been sent.
    assert_eq!(notified_status(&pool, k8s).await, (true, "resolved".into()));
    assert_eq!(
        notified_status(&pool, other_realm).await,
        (false, "open".into())
    );
    let audited: i64 = sqlx::query_scalar(
        "SELECT (detail->>'findings')::bigint FROM audit_log WHERE action = 'findings_baseline'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audited, 3);

    // Only dev's finding is still pending; a new prod finding alerts again.
    assert_eq!(enqueue_alerts(&pool, &cfg, &chans(&cfg)).await.unwrap(), 1);
    assert_eq!(outbox(&pool).await.len(), 1);
    let sid = service(&pool, "prod", "web").await;
    finding(
        &pool,
        "vuln",
        "prod",
        Some(sid),
        "GHSA-new-0002",
        "critical",
        vuln_details("v1.9.0", Value::Null, Value::Null),
    )
    .await;
    assert_eq!(enqueue_alerts(&pool, &cfg, &chans(&cfg)).await.unwrap(), 1);
}

// ---- UI channels ----

fn key(b: u8) -> SecretKey {
    use base64::{engine::general_purpose::STANDARD, Engine};
    SecretKey::parse(&STANDARD.encode([b; 32])).unwrap()
}

/// Realm prod; config channels only when `channels` is given.
fn ui_cfg(channels: &str) -> HeimdallConfig {
    cfg(&format!("realms: [prod]\n{channels}"))
}

/// Create UI slack channel `name` posting to `url`, sealed with `k`.
async fn ui_slack(pool: &PgPool, c: &HeimdallConfig, k: &SecretKey, name: &str, url: &str) {
    let new: store::NewChannel = serde_json::from_value(json!({
        "type": "slack", "name": name, "min_severity": "high",
        "secrets": {"webhook": url},
    }))
    .unwrap();
    store::create(pool, c, Some(k), "alice", &new)
        .await
        .unwrap();
}

/// Make every queued row due before the fixed test clock, so a row that is
/// held back is held only because of its secrets.
async fn make_due(pool: &PgPool) {
    sqlx::query("UPDATE outbox SET next_attempt_at = '2000-01-01'")
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn ui_channel_is_delivered_like_a_config_one(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    let c = ui_cfg("");
    let k = key(7);
    ui_slack(
        &pool,
        &c,
        &k,
        "s",
        &format!("{}/services/T/B/ui", server.uri()),
    )
    .await;
    let ch = store::load(&pool, &c, Some(&k)).await.unwrap();
    assert_eq!(ch.ui[0].state, UiState::Ok);
    assert_eq!(ch.ui[0].present, ["webhook"]);
    assert_eq!(ch.list.len(), 1);

    let f = vuln(&pool, "prod", "api", "critical").await;
    assert_eq!(enqueue_alerts(&pool, &c, &ch).await.unwrap(), 1);
    assert!(notified_status(&pool, f).await.0);
    let rows = outbox(&pool).await;
    assert_eq!(rows[0].route, "s");
    make_due(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
        .await
        .unwrap();
    assert_eq!((r.sent, r.channel_type), (1, Some("slack")));
    let got: Value =
        serde_json::from_slice(&server.received_requests().await.unwrap()[0].body).unwrap();
    assert_eq!(got, rows[0].card);
    assert!(got["blocks"].is_array(), "{got}");
    server.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn ui_channel_rows_stay_queued_without_key(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let c = ui_cfg("");
    ui_slack(&pool, &c, &key(7), "s", &format!("{}/hook", server.uri())).await;
    let ch = store::load(&pool, &c, None).await.unwrap();
    assert_eq!(ch.ui[0].state, UiState::KeyMissing);
    assert_eq!(ch.ui[0].present, ["webhook"], "known without the key");
    assert!(ch.secrets.is_empty());
    assert_eq!(ch.list.iter().map(|c| c.name()).collect::<Vec<_>>(), ["s"]);

    // The finding is queued for the channel, not dropped.
    let f = vuln(&pool, "prod", "api", "critical").await;
    assert_eq!(enqueue_alerts(&pool, &c, &ch).await.unwrap(), 1);
    assert!(notified_status(&pool, f).await.0);
    make_due(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
        .await
        .unwrap();
    assert_eq!(r, outbox::DrainResult::default());
    let rows = outbox(&pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].route, "s");
    assert!(rows[0].sent_at.is_none());
    assert_eq!(rows[0].attempts, 0);
    assert!(outbox::orphaned(&pool, &ch).await.unwrap().is_empty());
    server.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn unreadable_secret_keeps_rows_queued(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let c = ui_cfg("");
    ui_slack(&pool, &c, &key(7), "s", &format!("{}/hook", server.uri())).await;
    let ch = store::load(&pool, &c, Some(&key(9))).await.unwrap();
    assert_eq!(ch.ui[0].state, UiState::Unreadable);
    assert!(ch.secrets.is_empty());
    assert_eq!(ch.list.len(), 1);

    vuln(&pool, "prod", "api", "critical").await;
    assert_eq!(enqueue_alerts(&pool, &c, &ch).await.unwrap(), 1);
    make_due(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
        .await
        .unwrap();
    assert_eq!(r, outbox::DrainResult::default());
    let rows = outbox(&pool).await;
    assert!(rows[0].sent_at.is_none());
    assert_eq!(rows[0].attempts, 0);
    server.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn config_wins_a_name_clash(pool: PgPool) {
    let c = ui_cfg(
        "channels:\n  - {type: slack, name: dup, webhook_env: NOTIFY_CLASH_URL, min_severity: high}\n",
    );
    sqlx::query(
        "INSERT INTO alert_channels (name, type, min_severity, created_by, updated_by) \
         VALUES ('dup', 'discord', 'high', 'alice', 'alice')",
    )
    .execute(&pool)
    .await
    .unwrap();
    let ch = store::load(&pool, &c, Some(&key(7))).await.unwrap();
    assert_eq!(ch.ui.len(), 1);
    assert_eq!(ch.ui[0].state, UiState::NameClash);
    assert_eq!(ch.list.len(), 1);
    let crate::config::ChannelConfig::Slack(w) = &ch.list[0] else {
        panic!("the config channel is not the one kept: {:?}", ch.list[0])
    };
    assert_eq!(w.webhook_env, "NOTIFY_CLASH_URL");
}

/// Create UI slack channel `s` covering `realms` under a config with
/// realms [prod, dev].
async fn ui_slack_in(pool: &PgPool, realms: &[&str]) {
    let new: store::NewChannel = serde_json::from_value(json!({
        "type": "slack", "name": "s", "min_severity": "high", "realms": realms,
        "secrets": {"webhook": "https://hooks.example/topsecret"},
    }))
    .unwrap();
    store::create(
        pool,
        &cfg("realms: [prod, dev]\n"),
        Some(&key(7)),
        "alice",
        &new,
    )
    .await
    .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn ui_channel_with_removed_realm_still_gets_remaining_realms(pool: PgPool) {
    ui_slack_in(&pool, &["prod", "dev"]).await;
    // `dev` is later removed from the config; a config channel covers prod.
    let c = ui_cfg(
        "channels:\n  - {type: slack, name: other, webhook_env: NOTIFY_REALM_URL, \
         min_severity: high, realms: [prod]}\n",
    );
    let ch = store::load(&pool, &c, Some(&key(7))).await.unwrap();
    assert_eq!(ch.ui[0].state, UiState::Ok);
    assert!(ch.ui[0].config.is_some());
    assert_eq!(
        ch.list.iter().map(|c| c.name()).collect::<Vec<_>>(),
        ["other", "s"]
    );
    assert!(!ch.secrets.is_empty());

    let f = vuln(&pool, "prod", "api", "critical").await;
    enqueue_alerts(&pool, &c, &ch).await.unwrap();
    assert!(notified_status(&pool, f).await.0);
    let mut routes: Vec<String> = outbox(&pool).await.into_iter().map(|r| r.route).collect();
    routes.sort();
    assert_eq!(routes, ["other", "s"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn ui_channel_with_only_removed_realms_stays_listed(pool: PgPool) {
    ui_slack_in(&pool, &["dev"]).await;
    // `dev` is later removed from the config.
    let c = ui_cfg(
        "channels:\n  - {type: slack, name: other, webhook_env: NOTIFY_REALM_URL, \
         min_severity: high}\n",
    );
    let ch = store::load(&pool, &c, Some(&key(7))).await.unwrap();
    assert_eq!(ch.ui[0].state, UiState::Ok);
    let s = ch
        .list
        .iter()
        .find(|c| c.name() == "s")
        .expect("s is listed");
    // It covers no configured realm, and is not widened to all of them.
    assert!(!s.covers("prod"));

    vuln(&pool, "prod", "api", "critical").await;
    enqueue_alerts(&pool, &c, &ch).await.unwrap();
    let routes: Vec<String> = outbox(&pool).await.into_iter().map(|r| r.route).collect();
    assert_eq!(routes, ["other"]);
    // A row queued for it earlier still drains: it is not orphaned.
    sqlx::query(
        "INSERT INTO outbox (group_key, card, route, channel_type, next_attempt_at) \
         VALUES ('alert|old', '{}', 's', 'slack', '2000-01-01')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(outbox::orphaned(&pool, &ch).await.unwrap().is_empty());
}

// ---- delivery errors, health, delete ----

/// `last_error_at` and `last_error` of the oldest row.
async fn last_error(pool: &PgPool) -> (Option<DateTime<Utc>>, Option<String>) {
    sqlx::query_as("SELECT last_error_at, last_error FROM outbox ORDER BY id LIMIT 1")
        .fetch_one(pool)
        .await
        .unwrap()
}

/// One due row for channel `route` of type `kind`.
async fn queued_for(pool: &PgPool, route: &str, kind: &str, card: Value) -> i64 {
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

fn key_of(route: &str, kind: &str) -> (String, String) {
    (route.to_string(), kind.to_string())
}

#[sqlx::test(migrations = "./migrations")]
async fn retry_records_last_error(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_ERR503", &server);
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r.retry, 1);
    let (at, err) = last_error(&pool).await;
    assert_eq!(at, Some(now()));
    let err = err.expect("last_error is set");
    assert!(err.contains("503"), "{err}");
    let h = outbox::health(&pool).await.unwrap();
    let all = &h[&key_of("all", "teams")];
    assert_eq!(all.queued, 1);
    assert!(all.failing.as_deref().unwrap_or_default().contains("503"));
}

#[sqlx::test(migrations = "./migrations")]
async fn rejected_records_last_error(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&server)
        .await;
    let c = with_webhook("NOTIFY_HOOK_ERR400", &server);
    queued(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &chans(&c), now())
        .await
        .unwrap();
    assert_eq!(r.failed, 1);
    let (at, err) = last_error(&pool).await;
    assert_eq!(at, Some(now()));
    assert!(err.unwrap_or_default().contains("400"));
}

#[sqlx::test(migrations = "./migrations")]
async fn last_error_is_redacted(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let c = ui_cfg("");
    let k = key(7);
    let token = "123456:AAH-telegram-TOKEN";
    let new: store::NewChannel = serde_json::from_value(json!({
        "type": "telegram", "name": "tg", "min_severity": "high",
        "settings": {"chat_id": "1", "api_url": server.uri()},
        "secrets": {"bot_token": token},
    }))
    .unwrap();
    store::create(&pool, &c, Some(&k), "alice", &new)
        .await
        .unwrap();
    let ch = store::load(&pool, &c, Some(&k)).await.unwrap();
    queued_for(
        &pool,
        "tg",
        "telegram",
        json!({"chat_id": "1", "text": "x"}),
    )
    .await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
        .await
        .unwrap();
    assert_eq!(r.retry, 1);
    let err = last_error(&pool).await.1.expect("last_error is set");
    assert!(err.contains("500"), "{err}");
    assert!(!err.contains(token) && !err.contains("TOKEN"), "{err}");
}

#[sqlx::test(migrations = "./migrations")]
async fn last_error_never_holds_a_webhook_url(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let c = ui_cfg("");
    let k = key(7);
    // Nothing listens on port 9: the send fails with a network error.
    let down = "http://127.0.0.1:9/services/T0/B0/SLACK-DOWN-SECRET";
    let failing = format!("{}/services/T0/B0/SLACK-500-SECRET", server.uri());
    ui_slack(&pool, &c, &k, "down", down).await;
    ui_slack(&pool, &c, &k, "five", &failing).await;
    let ch = store::load(&pool, &c, Some(&k)).await.unwrap();
    queued_for(&pool, "down", "slack", json!({})).await;
    queued_for(&pool, "five", "slack", json!({})).await;
    for _ in 0..2 {
        let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
            .await
            .unwrap();
        assert_eq!(r.retry, 1);
    }
    let errs: Vec<Option<String>> = sqlx::query_scalar("SELECT last_error FROM outbox")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(errs.len(), 2);
    for err in errs {
        let err = err.expect("last_error is set");
        assert!(
            !err.contains("SECRET") && !err.contains("/services/"),
            "{err}"
        );
    }
    // The test send redacts the same way.
    let mailer = outbox_mailer(&ch);
    let d = outbox::Delivery {
        http: &reqwest::Client::new(),
        mailer: &mailer,
    };
    let s = ch.list.iter().find(|x| x.name() == "down").unwrap();
    let err = outbox::send_now(&d, s, &ch.secrets, now())
        .await
        .unwrap_err();
    assert!(
        !err.contains("SECRET") && !err.contains("/services/"),
        "{err}"
    );
}

fn outbox_mailer(ch: &Channels) -> channels::email::SmtpMailer<'_> {
    channels::email::SmtpMailer {
        secrets: &ch.secrets,
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn health_reports_queue_and_last_sent(pool: PgPool) {
    let sent = now() - Duration::hours(2);
    sqlx::query(
        "INSERT INTO outbox (group_key, card, route, channel_type, sent_at) VALUES \
         ('a', '{}', 'x', 'slack', $1), \
         ('b', '{\"failed\": true}', 'x', 'slack', $2), \
         ('c', '{}', 'x', 'slack', NULL), \
         ('d', '{}', 'x', 'slack', NULL), \
         ('e', '{}', 'x', 'discord', NULL)",
    )
    .bind(sent)
    .bind(now())
    .execute(&pool)
    .await
    .unwrap();
    let h = outbox::health(&pool).await.unwrap();
    let x = &h[&key_of("x", "slack")];
    assert_eq!(x.queued, 2);
    // The rejected row is not a send.
    assert_eq!(x.last_sent_at, Some(sent));
    assert_eq!(x.failing, None);
    let d = &h[&key_of("x", "discord")];
    assert_eq!((d.queued, d.last_sent_at), (1, None));
    // Failing reflects the oldest queued row only.
    sqlx::query("UPDATE outbox SET last_error = 'boom' WHERE group_key = 'd'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        outbox::health(&pool).await.unwrap()[&key_of("x", "slack")].failing,
        None
    );
    sqlx::query("UPDATE outbox SET last_error = 'down' WHERE group_key = 'c'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        outbox::health(&pool).await.unwrap()[&key_of("x", "slack")]
            .failing
            .as_deref(),
        Some("down")
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_discards_queued_rows(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let c = ui_cfg("");
    let k = key(7);
    let url = format!("{}/hook", server.uri());
    ui_slack(&pool, &c, &k, "s", &url).await;
    let id = store::load(&pool, &c, Some(&k)).await.unwrap().ui[0].id;
    queued_for(&pool, "s", "slack", json!({})).await;
    queued_for(&pool, "s", "slack", json!({})).await;
    // Another type under the same name is not this channel's.
    queued_for(&pool, "s", "discord", json!({})).await;
    assert_eq!(store::queued_count(&pool, &c, id).await.unwrap(), 2);
    assert_eq!(store::delete(&pool, &c, "bob", id).await.unwrap(), 2);
    type Discarded = (String, Option<DateTime<Utc>>, Value, Option<String>);
    let rows: Vec<Discarded> =
        sqlx::query_as("SELECT channel_type, sent_at, card, last_error FROM outbox ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    for (kind, sent_at, card, err) in &rows[..2] {
        assert_eq!(kind, "slack");
        assert!(sent_at.is_some());
        assert_eq!(card["failed"], json!(true));
        assert_eq!(err.as_deref(), Some("channel deleted"));
    }
    assert!(rows[2].1.is_none(), "the discord row is untouched");
    let (action, detail): (String, Value) =
        sqlx::query_as("SELECT action, detail FROM audit_log WHERE action = 'channel_deleted'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(action, "channel_deleted");
    assert_eq!(
        detail,
        json!({"name": "s", "type": "slack", "discarded": 2})
    );
    assert!(matches!(
        store::delete(&pool, &c, "bob", id).await,
        Err(store::StoreError::NotFound)
    ));
    assert!(matches!(
        store::queued_count(&pool, &c, id).await,
        Err(store::StoreError::NotFound)
    ));

    // Recreated with the same name and type, it inherits nothing.
    ui_slack(&pool, &c, &k, "s", &url).await;
    let ch = store::load(&pool, &c, Some(&k)).await.unwrap();
    make_due(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
        .await
        .unwrap();
    assert_eq!(r.sent, 0);
    server.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn create_discards_orphaned_rows_for_same_name_and_type(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let c = ui_cfg("");
    let k = key(7);
    // Orphans: no channel named `s` exists (a lost race with delete, or a
    // removed config channel).
    queued_for(&pool, "s", "slack", json!({})).await;
    queued_for(&pool, "s", "discord", json!({})).await;
    ui_slack(&pool, &c, &k, "s", &format!("{}/hook", server.uri())).await;
    type Row = (String, Option<DateTime<Utc>>, Value, Option<String>);
    let rows: Vec<Row> =
        sqlx::query_as("SELECT channel_type, sent_at, card, last_error FROM outbox ORDER BY id")
            .fetch_all(&pool)
            .await
            .unwrap();
    let (kind, sent_at, card, err) = &rows[0];
    assert_eq!(kind, "slack");
    assert!(sent_at.is_some());
    assert_eq!(card["failed"], json!(true));
    assert_eq!(err.as_deref(), Some("channel recreated"));
    assert!(rows[1].1.is_none(), "the discord row is untouched");
    assert!(rows[1].3.is_none());
    let detail: Value =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'channel_created'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(detail["discarded"], json!(1));

    let ch = store::load(&pool, &c, Some(&k)).await.unwrap();
    make_due(&pool).await;
    let r = drain_once(&pool, &reqwest::Client::new(), &c, &ch, now())
        .await
        .unwrap();
    assert_eq!(r.sent, 0);
    server.verify().await;
}

#[sqlx::test(migrations = "./migrations")]
async fn delete_ui_channel_clashing_with_config_keeps_queued_rows(pool: PgPool) {
    let c = ui_cfg(
        "channels:\n  - {type: slack, name: s, webhook_env: NOTIFY_CLASH_URL, min_severity: high}\n",
    );
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO alert_channels (name, type, min_severity, created_by, updated_by) \
         VALUES ('s', 'slack', 'high', 'alice', 'alice') RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let row = queued_for(&pool, "s", "slack", json!({})).await;
    assert_eq!(store::queued_count(&pool, &c, id).await.unwrap(), 0);
    assert_eq!(store::delete(&pool, &c, "bob", id).await.unwrap(), 0);
    let (sent_at, card, err): (Option<DateTime<Utc>>, Value, Option<String>) =
        sqlx::query_as("SELECT sent_at, card, last_error FROM outbox WHERE id = $1")
            .bind(row)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(sent_at.is_none(), "the config channel's row stays queued");
    assert!(card.get("failed").is_none(), "{card}");
    assert_eq!(err, None);
    let left: i64 = sqlx::query_scalar("SELECT count(*) FROM alert_channels")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(left, 0, "the UI row is gone");
    let detail: Value =
        sqlx::query_scalar("SELECT detail FROM audit_log WHERE action = 'channel_deleted'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        detail,
        json!({"name": "s", "type": "slack", "discarded": 0})
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn send_now_reports_errors(pool: PgPool) {
    let bad = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&bad)
        .await;
    let good = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&good)
        .await;
    let c = ui_cfg("");
    let k = key(7);
    ui_slack(&pool, &c, &k, "bad", &format!("{}/hook", bad.uri())).await;
    ui_slack(&pool, &c, &k, "good", &format!("{}/hook", good.uri())).await;
    let ch = store::load(&pool, &c, Some(&k)).await.unwrap();
    let mailer = outbox_mailer(&ch);
    let http = reqwest::Client::new();
    let d = outbox::Delivery {
        http: &http,
        mailer: &mailer,
    };
    let err = outbox::send_now(&d, &ch.list[0], &ch.secrets, now())
        .await
        .unwrap_err();
    assert!(err.contains("400"), "{err}");
    outbox::send_now(&d, &ch.list[1], &ch.secrets, now())
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&good.received_requests().await.unwrap()[0].body).unwrap();
    assert!(body.to_string().contains("Heimdall test alert"), "{body}");
    assert!(
        body.to_string()
            .contains("This is a test from Heimdall. No action is needed."),
        "{body}"
    );
    // Not through the outbox.
    assert!(outbox(&pool).await.is_empty());
    good.verify().await;
}
