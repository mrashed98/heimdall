//! Mattermost and Jira: formatting, escaping, limits and delivery.

use base64::Engine;

use super::*;

// ---- Mattermost ----

#[test]
fn mattermost_snapshot_and_limits() {
    let got = mattermost::render(&vuln_alert());
    snapshot("mattermost_vuln", &got);
    let huge = mattermost::render(&huge_alert()).to_string();
    // A post holds at most 16383 characters.
    assert!(huge.chars().count() < 16383, "{}", huge.len());
}

/// Advisory text can neither mention anyone nor add a link.
#[test]
fn mattermost_escapes_and_never_mentions() {
    let mut a = hostile_alert();
    a.title = "@channel @all *x*".to_string();
    let got = mattermost::render(&a);
    let text = got.to_string();
    assert!(
        !text.contains("@channel") && !text.contains("@all"),
        "{text}"
    );
    assert!(!text.contains("@everyone"), "{text}");
    let att = &got["attachments"][0];
    assert!(att["text"].as_str().unwrap().contains(r"\*bold\*"), "{att}");
    let digest = mattermost::render(&digest_alert()).to_string();
    assert!(!digest.contains(&format!("[click]({EVIL}")), "{digest}");
}

#[sqlx::test(migrations = "./migrations")]
async fn mattermost_posts_to_the_webhook(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hooks/abc"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_MM_OK", format!("{}/hooks/abc", server.uri()));
    let c = cfg("realms: [prod]\nchannels:\n  - {type: mattermost, name: mm, webhook_env: CH_MM_OK, min_severity: high}\n");
    let payload = render(&c.channels[0], &vuln_alert());
    let id = queue(&pool, "mm", "mattermost", &payload).await;
    let r = drain(&pool, &c).await;
    assert_eq!((r.sent, r.channel_type), (1, Some("mattermost")));
    assert!(row(&pool, id).await.sent_at.is_some());
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert_eq!(got, payload);
}

// ---- Jira ----

#[test]
fn jira_snapshot_and_limits() {
    let got = jira::render(&vuln_alert());
    snapshot("jira_vuln", &got);
    assert_eq!(
        got["fields"]["labels"],
        json!(["heimdall", "severity-high"])
    );
    let huge = jira::render(&huge_alert());
    assert!(
        huge["fields"]["description"]
            .as_str()
            .unwrap()
            .chars()
            .count()
            <= 32767
    );
    assert!(huge["fields"]["summary"].as_str().unwrap().chars().count() <= 255);
}

/// Advisory text cannot add markup or a link, and the summary is one line.
#[test]
fn jira_escapes_wiki_markup() {
    let mut a = hostile_alert();
    a.title = "line one\nline two".to_string();
    let got = jira::render(&a);
    assert_eq!(got["fields"]["summary"], "line one line two");
    let d = got["fields"]["description"].as_str().unwrap();
    assert!(d.contains(r"\*bold\*") && d.contains(r"\_it\_"), "{d}");
    let digest = jira::render(&digest_alert()).to_string();
    assert!(!digest.contains(&format!("|{EVIL}]")), "{digest}");
}

#[test]
fn jira_skips_the_digest_unless_asked() {
    let c = cfg(
        "realms: [prod]\nchannels:\n  - {type: jira, name: j, url: 'https://x.atlassian.net', \
                 project: SEC, token_env: T, min_severity: high}\n  - {type: mattermost, name: m, \
                 webhook_env: M, min_severity: high}\n",
    );
    assert!(!c.channels[0].wants_digest());
    assert!(c.channels[1].wants_digest());
}

#[test]
fn jira_config_is_validated() {
    let bad = |yaml: &str| {
        let c: HeimdallConfig = serde_saphyr::from_str(yaml).unwrap();
        format!("{:#}", c.validate().unwrap_err())
    };
    let e = bad("realms: [prod]\nchannels:\n  - {type: jira, name: j, url: 'https://x', project: ' ', token_env: T, min_severity: high}\n");
    assert!(e.contains("project"), "{e}");
    let e = bad("realms: [prod]\nchannels:\n  - {type: jira, name: j, url: 'ftp://x', project: S, token_env: T, min_severity: high}\n");
    assert!(e.contains("url"), "{e}");
}

/// Cloud: basic auth with the account email. The project and issue type
/// come from the channel when sending, so a row queued before the project
/// changed goes to the new project.
#[sqlx::test(migrations = "./migrations")]
async fn jira_creates_an_issue_in_the_current_project(pool: PgPool) {
    let server = MockServer::start().await;
    let basic = base64::engine::general_purpose::STANDARD.encode("ops@example.com:jira-TOKEN");
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue"))
        .and(header("authorization", format!("Basic {basic}").as_str()))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"key": "NEW-1"})))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_JIRA_USER", "ops@example.com");
    std::env::set_var("CH_JIRA_TOKEN", "jira-TOKEN");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: jira, name: j, url: '{}/', project: NEW, \
         issue_type: Bug, username_env: CH_JIRA_USER, token_env: CH_JIRA_TOKEN, min_severity: high}}\n",
        server.uri()
    ));
    let mut queued = jira::render(&vuln_alert());
    // Queued while the channel pointed at another project.
    queued["fields"]["project"] = json!({"key": "OLD"});
    let id = queue(&pool, "j", "jira", &queued).await;
    let r = drain(&pool, &c).await;
    assert_eq!((r.sent, r.channel_type), (1, Some("jira")));
    assert!(row(&pool, id).await.sent_at.is_some());
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert_eq!(got["fields"]["project"], json!({"key": "NEW"}));
    assert_eq!(got["fields"]["issuetype"], json!({"name": "Bug"}));
    assert_eq!(got["fields"]["summary"], queued["fields"]["summary"]);
    server.verify().await;
}

/// Data Center: no username, so the token goes as a bearer token, and the
/// issue type defaults to Task.
#[sqlx::test(migrations = "./migrations")]
async fn jira_without_username_sends_a_bearer_token(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue"))
        .and(header("authorization", "Bearer dc-pat"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"key": "SEC-1"})))
        .expect(1)
        .mount(&server)
        .await;
    std::env::set_var("CH_JIRA_PAT", "dc-pat");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: jira, name: dc, url: '{}', project: SEC, \
         token_env: CH_JIRA_PAT, min_severity: high}}\n",
        server.uri()
    ));
    queue(&pool, "dc", "jira", &render(&c.channels[0], &vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert_eq!(got["fields"]["issuetype"], json!({"name": "Task"}));
    server.verify().await;
}

/// An expired token or a missing permission (401, 403) holds the queue
/// instead of discarding the alert.
#[sqlx::test(migrations = "./migrations")]
async fn jira_auth_failure_keeps_the_issue_queued(pool: PgPool) {
    for status in [401, 403] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(status))
            .expect(1)
            .mount(&server)
            .await;
        std::env::set_var("CH_JIRA_EXPIRED", "old");
        let name = format!("j{status}");
        let c = cfg(&format!(
            "realms: [prod]\nchannels:\n  - {{type: jira, name: {name}, url: '{}', project: SEC, \
             token_env: CH_JIRA_EXPIRED, min_severity: high}}\n",
            server.uri()
        ));
        let id = queue(&pool, &name, "jira", &render(&c.channels[0], &vuln_alert())).await;
        let r = drain(&pool, &c).await;
        assert_eq!((r.retry, r.failed), (1, 0), "{status}");
        let r = row(&pool, id).await;
        assert!(
            r.sent_at.is_none() && r.card.get("failed").is_none(),
            "{status}"
        );
        server.verify().await;
    }
}

/// A console Jira channel: settings and saved secrets build a channel
/// whose request carries the decrypted token.
#[sqlx::test(migrations = "./migrations")]
async fn console_jira_channel_builds(pool: PgPool) {
    use crate::notify::store;
    use base64::engine::general_purpose::STANDARD;
    let key = crate::secrets::SecretKey::parse(&STANDARD.encode([3u8; 32])).unwrap();
    let c = cfg("realms: [prod]\n");
    let new: store::NewChannel = serde_json::from_value(json!({
        "type": "jira", "name": "jira-ui", "min_severity": "high",
        "settings": {"url": "https://example.atlassian.net", "project": "SEC"},
        "secrets": {"username": "ops@example.com", "token": "ui-TOKEN"},
    }))
    .unwrap();
    store::create(&pool, &c, Some(&key), "alice", &new)
        .await
        .unwrap();
    let chans = store::load(&pool, &c, Some(&key)).await.unwrap();
    let ch = chans.list.iter().find(|x| x.name() == "jira-ui").unwrap();
    assert!(!ch.wants_digest());
    let Request::Http { url, auth, .. } =
        request(ch, &jira::render(&vuln_alert()), now(), &chans.secrets).unwrap()
    else {
        unreachable!()
    };
    assert_eq!(url, "https://example.atlassian.net/rest/api/2/issue");
    assert_eq!(
        auth,
        Some(HttpAuth::Basic("ops@example.com".into(), "ui-TOKEN".into()))
    );
}

/// Every channel type: a credentials, permission or missing-destination
/// answer blames the channel (the queue is held), never the alert.
#[test]
fn client_errors_blame_the_channel_or_the_alert() {
    use crate::notify::outbox::{blame, Blame};
    use reqwest::StatusCode;
    let every = [
        "{type: teams, name: a, webhook_env: X, min_severity: high}",
        "{type: slack, name: a, webhook_env: X, min_severity: high}",
        "{type: discord, name: a, webhook_env: X, min_severity: high}",
        "{type: mattermost, name: a, webhook_env: X, min_severity: high}",
        "{type: telegram, name: a, bot_token_env: X, chat_id: 1, min_severity: high}",
        "{type: pagerduty, name: a, routing_key_env: X, min_severity: high}",
        "{type: alertmanager, name: a, url: 'http://am', min_severity: high}",
        "{type: webhook, name: a, url_env: X, min_severity: high}",
        "{type: email, name: a, host: h, from: a@x.io, to: [b@x.io], min_severity: high}",
        "{type: jira, name: a, url: 'https://x', project: SEC, token_env: X, min_severity: high}",
    ];
    for yaml in every {
        let c = ch(yaml);
        for s in [401, 403, 404, 410] {
            let s = StatusCode::from_u16(s).unwrap();
            assert_eq!(
                blame(&c, s, &Value::Null),
                Blame::Channel,
                "{} {s}",
                c.type_name()
            );
        }
        // A plain 400 is the alert's, except for Jira (below).
        if c.type_name() != "jira" {
            let s = StatusCode::BAD_REQUEST;
            assert_eq!(
                blame(&c, s, &Value::Null),
                Blame::Alert,
                "{} 400",
                c.type_name()
            );
        }
        let s = StatusCode::PAYLOAD_TOO_LARGE;
        assert_eq!(
            blame(&c, s, &Value::Null),
            Blame::Alert,
            "{} 413",
            c.type_name()
        );
    }
    // Jira: a 400 is the alert's only when it names nothing but the fields
    // Heimdall fills from the alert; anything else is the channel's setup.
    let jira = ch(every[9]);
    let jira_400 = |body: Value| blame(&jira, StatusCode::BAD_REQUEST, &body);
    let errors = |e: Value| json!({ "errors": e });
    assert_eq!(
        jira_400(errors(json!({"description": "too long"}))),
        Blame::Alert
    );
    assert_eq!(
        jira_400(errors(json!({"summary": "too long", "description": "x"}))),
        Blame::Alert
    );
    for field in [
        "project",
        "issuetype",
        "labels",
        "components",
        "customfield_10010",
    ] {
        assert_eq!(
            jira_400(errors(json!({ field: "required" }))),
            Blame::Channel,
            "{field}"
        );
    }
    assert_eq!(
        jira_400(errors(
            json!({"description": "x", "components": "required"})
        )),
        Blame::Channel
    );
    assert_eq!(
        jira_400(json!({"errorMessages": ["no permission"], "errors": {}})),
        Blame::Channel
    );
    assert_eq!(jira_400(Value::Null), Blame::Channel);
    let tg = ch(every[4]);
    let tg_400 = |d: &str| {
        blame(
            &tg,
            StatusCode::BAD_REQUEST,
            &json!({"ok": false, "description": d}),
        )
    };
    assert_eq!(tg_400("Bad Request: chat not found"), Blame::Channel);
    assert_eq!(tg_400("Bad Request: can't parse entities"), Blame::Alert);
    let migrated = json!({"ok": false, "description": "Bad Request: group chat was upgraded to a supergroup chat",
                          "parameters": {"migrate_to_chat_id": -1001234}});
    assert_eq!(
        blame(&tg, StatusCode::BAD_REQUEST, &migrated),
        Blame::Channel
    );
}

/// A deleted Slack webhook (404) holds the queue; nothing is discarded.
#[sqlx::test(migrations = "./migrations")]
async fn deleted_webhook_keeps_alerts_queued(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404).set_body_string("no_service"))
        .mount(&server)
        .await;
    std::env::set_var(
        "CH_SLACK_GONE",
        format!("{}/services/T/B/gone", server.uri()),
    );
    let c = cfg("realms: [prod]\nchannels:\n  - {type: slack, name: s, webhook_env: CH_SLACK_GONE, min_severity: high}\n");
    let id = queue(&pool, "s", "slack", &slack::render(&vuln_alert())).await;
    let r = drain(&pool, &c).await;
    assert_eq!((r.retry, r.failed), (1, 0));
    assert!(row(&pool, id).await.sent_at.is_none());
}

/// A wrong project key or issue type (Jira answers 400) holds the queue.
#[sqlx::test(migrations = "./migrations")]
async fn jira_bad_request_keeps_the_issue_queued(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errors": {"project": "valid project is required"}})),
        )
        .mount(&server)
        .await;
    std::env::set_var("CH_JIRA_400", "t");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: jira, name: j, url: '{}', project: NOPE, \
         token_env: CH_JIRA_400, min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(&pool, "j", "jira", &render(&c.channels[0], &vuln_alert())).await;
    let r = drain(&pool, &c).await;
    assert_eq!((r.retry, r.failed), (1, 0));
    let r = row(&pool, id).await;
    assert!(r.sent_at.is_none() && r.card.get("failed").is_none());
}

/// A Jira 400 the issue itself caused (not a channel setting) drops that
/// issue and the queue moves on, so one bad alert can't block the channel.
#[sqlx::test(migrations = "./migrations")]
async fn jira_issue_rejected_for_its_own_content_moves_on(pool: PgPool) {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(json!({"errors": {"description": "The entered text is too long."}})),
        )
        .mount(&server)
        .await;
    std::env::set_var("CH_JIRA_LONG", "t");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: jira, name: j, url: '{}', project: SEC, \
         token_env: CH_JIRA_LONG, min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(&pool, "j", "jira", &render(&c.channels[0], &vuln_alert())).await;
    assert_eq!(drain(&pool, &c).await.failed, 1);
    assert_eq!(row(&pool, id).await.card["failed"], json!(true));
}

/// Queuing gives each Jira issue a random label (stored with the row, never
/// with a secret); a retry finds the issue an earlier timed-out attempt
/// created, in the channel's project, and does not create another.
#[sqlx::test(migrations = "./migrations")]
async fn jira_retry_does_not_create_a_second_issue(pool: PgPool) {
    let server = MockServer::start().await;
    std::env::set_var("CH_JIRA_DEDUPE", "dedupe-TOKEN");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: jira, name: j, url: '{}', project: sec, \
         token_env: CH_JIRA_DEDUPE, min_severity: high}}\n",
        server.uri()
    ));
    let enqueue = || async {
        let mut conn = pool.acquire().await.unwrap();
        let card = render(&c.channels[0], &vuln_alert());
        crate::notify::outbox::push(&mut conn, "alert|x", &card, &c.channels[0])
            .await
            .unwrap()
    };
    let label_of = |card: &Value| jira_attempt_label(card).map(str::to_string);
    let first = enqueue().await;
    let card = row(&pool, first).await.card;
    let label = label_of(&card).expect("queued with an attempt label");
    assert!(!card.to_string().contains("TOKEN"), "{card}");
    sqlx::query("UPDATE outbox SET next_attempt_at = '2000-01-01'")
        .execute(&pool)
        .await
        .unwrap();
    Mock::given(method("POST"))
        .and(path("/rest/api/2/issue"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"key": "SEC-1"})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    let got: Value = serde_json::from_slice(&requests(&server).await[0].body).unwrap();
    assert!(
        got["fields"]["labels"]
            .as_array()
            .unwrap()
            .contains(&json!(label)),
        "{got}"
    );
    assert_eq!(got["fields"]["project"], json!({"key": "SEC"}));

    // A second row whose earlier attempt timed out after Jira created it.
    let second = enqueue().await;
    let second_label = label_of(&row(&pool, second).await.card).unwrap();
    assert_ne!(second_label, label, "labels are unique per queued issue");
    sqlx::query("UPDATE outbox SET attempts = 1, next_attempt_at = '2000-01-01' WHERE id = $1")
        .bind(second)
        .execute(&pool)
        .await
        .unwrap();
    Mock::given(method("GET"))
        .and(path("/rest/api/2/search/jql"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"issues": [{"key": "SEC-2"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(drain(&pool, &c).await.sent, 1);
    assert!(row(&pool, second).await.sent_at.is_some());
    let reqs = requests(&server).await;
    assert_eq!(
        reqs.iter().filter(|r| r.method.as_str() == "POST").count(),
        1,
        "the retry created a second issue"
    );
    let search = reqs.iter().find(|r| r.method.as_str() == "GET").unwrap();
    let jql: String = search
        .url
        .query_pairs()
        .find(|(k, _)| k == "jql")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(jql, format!("labels = \"{second_label}\""));
}

#[test]
fn mattermost_notification_text_is_plain() {
    let mut a = vuln_alert();
    a.title = "Critical in my_pkg [prod] @all".to_string();
    let att = &mattermost::render(&a)["attachments"][0];
    // Notifications are plain text; the title may render Markdown, so it
    // stays escaped.
    assert_eq!(att["fallback"], "Critical in my_pkg [prod] @\u{2060}all");
    assert_eq!(
        att["title"],
        mattermost::escape("Critical in my_pkg [prod] @all")
    );
}

#[test]
fn jira_escapes_block_markers() {
    let esc = jira::escape_block_markers;
    assert_eq!(esc("h1. URGENT"), r"\h1. URGENT");
    assert_eq!(esc("ok\n  bq. quote"), "ok\n  \\bq. quote");
    assert_eq!(esc("h1 plain"), "h1 plain");
    assert_eq!(esc("x\rh1. PWNED"), "x\n\\h1. PWNED");
    // Mid-line text (a realm in `*Realm:* …`) is left alone.
    assert_eq!(jira::escape("h1.prod"), "h1.prod");
    let mut a = vuln_alert();
    a.summary = Some("h1. URGENT".to_string());
    let d = jira::render(&a)["fields"]["description"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(d.contains("\n\\h1. URGENT"), "{d}");
}

#[test]
fn jira_url_and_project_are_validated() {
    let bad = |yaml: &str| {
        let c: HeimdallConfig = serde_saphyr::from_str(yaml).unwrap();
        format!("{:#}", c.validate().unwrap_err())
    };
    let e = bad("realms: [prod]\nchannels:\n  - {type: jira, name: j, url: 'https://x/?a=1', project: SEC, token_env: T, min_severity: high}\n");
    assert!(e.contains("query"), "{e}");
    for p in ["' SEC'", "S", "1SEC", "SE-C"] {
        let e = bad(&format!("realms: [prod]\nchannels:\n  - {{type: jira, name: j, url: 'https://x', project: {p}, token_env: T, min_severity: high}}\n"));
        assert!(e.contains("project key"), "{p}: {e}");
    }
}

/// Escaping can't push the Mattermost title past its 250 characters.
#[test]
fn mattermost_title_stays_within_its_limit() {
    let mut a = vuln_alert();
    a.title = "snake_case_name ".repeat(20);
    let att = &mattermost::render(&a)["attachments"][0];
    assert!(
        att["title"].as_str().unwrap().chars().count() <= 250,
        "{att}"
    );
}
