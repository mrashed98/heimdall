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
    // The token never reaches the stored row.
    assert!(!row(&pool, id).await.card.to_string().contains("TOKEN"));
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
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    std::env::set_var("CH_JIRA_EXPIRED", "old");
    let c = cfg(&format!(
        "realms: [prod]\nchannels:\n  - {{type: jira, name: j, url: '{}', project: SEC, \
         token_env: CH_JIRA_EXPIRED, min_severity: high}}\n",
        server.uri()
    ));
    let id = queue(&pool, "j", "jira", &render(&c.channels[0], &vuln_alert())).await;
    let r = drain(&pool, &c).await;
    assert_eq!((r.retry, r.failed), (1, 0));
    let r = row(&pool, id).await;
    assert!(r.sent_at.is_none());
    assert!(r.card.get("failed").is_none());
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
