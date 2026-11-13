//! Gjallarhorn tests against a real database (sqlx::test); Teams is a wiremock.

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, TimeZone, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::digest::maybe_send;
use super::outbox::drain_once;
use super::*;
use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
use crate::model::Source;

const ADV: &str = "GHSA-gin-0001";
const GIN: &str = "pkg:golang/github.com/gin-gonic/gin";

fn cfg(yaml: &str) -> HeimdallConfig {
    serde_yaml::from_str(yaml).unwrap()
}

/// Realms prod and dev, one route for everything high or worse.
fn one_route(env: &str) -> HeimdallConfig {
    cfg(&format!(
        "realms: [prod, dev]\n\
         teams:\n  - name: all\n    webhook_env: {env}\n    min_severity: high\n"
    ))
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
    let n = enqueue_alerts(&pool, &one_route("NOTIFY_T1"))
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
    enqueue_alerts(&pool, &one_route("NOTIFY_T2"))
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
    assert_eq!(enqueue_alerts(&pool, &low_route).await.unwrap(), 0);
    assert!(outbox(&pool).await.is_empty());
    assert_eq!(notified_status(&pool, v).await, (false, "open".into()));
}

#[sqlx::test(migrations = "./migrations")]
async fn enqueue_is_idempotent(pool: PgPool) {
    vuln(&pool, "prod", "api", "critical").await;
    let c = one_route("NOTIFY_T4");
    assert_eq!(enqueue_alerts(&pool, &c).await.unwrap(), 1);
    assert_eq!(enqueue_alerts(&pool, &c).await.unwrap(), 0);
    assert_eq!(outbox(&pool).await.len(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn first_run_summary_once_and_first(pool: PgPool) {
    vuln(&pool, "prod", "api", "high").await;
    vuln(&pool, "prod", "web", "medium").await;
    let c = one_route("NOTIFY_T5");
    assert!(enqueue_first_run_summary(&pool, &c, "prod").await.unwrap());
    enqueue_alerts(&pool, &c).await.unwrap();
    assert!(!enqueue_first_run_summary(&pool, &c, "prod").await.unwrap());

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
    enqueue_alerts(&pool, &c).await.unwrap();
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
    enqueue_alerts(&pool, &one_route("NOTIFY_T7"))
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
    enqueue_alerts(&pool, &one_route("NOTIFY_T8"))
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
    assert_eq!(enqueue_alerts(&pool, &c).await.unwrap(), 0);
    // The oath was revoked; the matcher clears details.oath.
    sqlx::query("UPDATE findings SET details = jsonb_set(details, '{oath}', 'null') WHERE id = $1")
        .bind(v)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(enqueue_alerts(&pool, &c).await.unwrap(), 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn fix_for_alerted_vuln_folds_into_its_card(pool: PgPool) {
    vuln(&pool, "prod", "api", "high").await;
    let f = fix(&pool, "prod", "api", "high").await;
    enqueue_alerts(&pool, &one_route("NOTIFY_T10"))
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
    assert_eq!(enqueue_alerts(&pool, &c).await.unwrap(), 0);
    assert_eq!(notified_status(&pool, v).await, (false, "open".into()));
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
    let r = drain_once(&pool, &reqwest::Client::new(), &c, now())
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
    drain_once(&pool, &reqwest::Client::new(), &c, now())
        .await
        .unwrap();
    let row = &outbox(&pool).await[0];
    assert_eq!(row.attempts, 3);
    // 30 s x 2^2
    assert_eq!(row.next_attempt_at, now() + Duration::seconds(120));
    // Not due yet: nothing is sent.
    let r = drain_once(&pool, &reqwest::Client::new(), &c, now())
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
    let first = drain_once(&pool, &reqwest::Client::new(), &c, now())
        .await
        .unwrap();
    assert_eq!(first.sent, 1);
    // A fresh client, as after a restart.
    let again = drain_once(&pool, &reqwest::Client::new(), &c, now())
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
    let r = drain_once(&pool, &reqwest::Client::new(), &c, now())
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
    let r = drain_once(&pool, &reqwest::Client::new(), &c, now())
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
    let r = drain_once(&pool, &reqwest::Client::new(), &c, now())
        .await
        .unwrap();
    assert_eq!(r.retry, 1);
    let row = &outbox(&pool).await[0];
    assert_eq!(row.next_attempt_at, now() + Duration::seconds(30));
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
    assert!(maybe_send(&pool, &c, monday_0910()).await.unwrap());
    assert!(
        !maybe_send(&pool, &c, monday_0910() + Duration::minutes(30))
            .await
            .unwrap()
    );
    assert!(!maybe_send(&pool, &c, monday_0910() + Duration::days(1))
        .await
        .unwrap());
    // 10:10 on the next Monday is the wrong hour.
    assert!(!maybe_send(
        &pool,
        &c,
        monday_0910() + Duration::days(7) + Duration::hours(1)
    )
    .await
    .unwrap());
    assert!(maybe_send(&pool, &c, monday_0910() + Duration::days(7))
        .await
        .unwrap());
    assert_eq!(outbox(&pool).await.len(), 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn digest_lists_medium_vulns_and_marks_them(pool: PgPool) {
    let m = vuln(&pool, "prod", "api", "medium").await;
    let h = vuln(&pool, "prod", "web", "high").await;
    assert!(maybe_send(&pool, &digest_cfg(), monday_0910())
        .await
        .unwrap());
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
    assert!(maybe_send(&pool, &digest_cfg(), monday_0910())
        .await
        .unwrap());
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
    assert!(maybe_send(&pool, &digest_cfg(), monday_0910())
        .await
        .unwrap());
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
    assert!(maybe_send(&pool, &digest_cfg(), monday_0910())
        .await
        .unwrap());
    let text = digest_text(&pool).await;
    assert!(
        text.contains("postgres-vm: postgresql 17.2, declared since 2026-11-13"),
        "{text}"
    );
}
