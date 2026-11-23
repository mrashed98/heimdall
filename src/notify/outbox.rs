//! The outbox: payloads queued in the database, one row per alert and
//! channel, and sent one at a time. Queued rows survive restarts; a sent row
//! is never sent again.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use reqwest::header::{CONTENT_TYPE, RETRY_AFTER};
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::{PgConnection, PgPool};

use super::alert::Alert;
use super::channels::email::{MailError, Mailer, SmtpMailer};
use super::channels::{self, HttpAuth, Request, Secrets};
use super::store::Channels;
use crate::config::{ChannelConfig, HeimdallConfig};

/// First retry delay; doubled per failed attempt.
const BACKOFF_BASE_SECS: i64 = 30;
/// Longest delay the backoff grows to.
const BACKOFF_CAP_SECS: i64 = 3600;
/// A webhook that does not answer in this time counts as a network error.
const SEND_TIMEOUT_SECS: u64 = 30;

/// What one `drain_once` did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DrainResult {
    pub sent: usize,
    /// Throttled, server error or network error: retried later.
    pub retry: usize,
    /// Rejected by the channel (a 4xx other than 429, a permanent SMTP
    /// error): marked sent with `card.failed = true`. The scheduler adds it
    /// to `heimdall_notify_failures_total` (and, for Teams,
    /// `heimdall_teams_failures_total`).
    pub failed: usize,
    /// The type of the channel of the row handled, if any.
    pub channel_type: Option<&'static str>,
}

/// Queue one payload for one channel.
pub(crate) async fn push(
    tx: &mut PgConnection,
    group_key: &str,
    card: &Value,
    channel: &ChannelConfig,
) -> anyhow::Result<i64> {
    let id = sqlx::query_scalar(
        "INSERT INTO outbox (group_key, card, route, channel_type) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(group_key)
    .bind(card)
    .bind(channel.name())
    .bind(channel.type_name())
    .fetch_one(&mut *tx)
    .await?;
    Ok(id)
}

/// How messages leave: HTTP for the webhook types, a mailer for email.
pub struct Delivery<'a> {
    pub http: &'a reqwest::Client,
    pub mailer: &'a dyn Mailer,
}

/// Send at most one due payload (oldest first) with the real SMTP mailer;
/// see `drain_with`.
pub async fn drain_once(
    pool: &PgPool,
    http: &reqwest::Client,
    cfg: &HeimdallConfig,
    chans: &Channels,
    now: DateTime<Utc>,
) -> anyhow::Result<DrainResult> {
    let mailer = SmtpMailer {
        secrets: &chans.secrets,
    };
    let d = Delivery {
        http,
        mailer: &mailer,
    };
    drain_with(pool, &d, cfg, chans, now).await
}

/// Send at most one due payload (oldest first); the caller loops every 2 s,
/// which paces the channels. Rows of a channel whose secret variables are
/// unset (or a UI channel whose secrets can't be read) stay queued untouched
/// until they are set, as do rows queued for a
/// channel that has since changed type.
///
/// The row is locked `FOR UPDATE SKIP LOCKED` for the whole send, so a second
/// drainer picks another row instead of sending this one twice.
pub async fn drain_with(
    pool: &PgPool,
    d: &Delivery<'_>,
    _cfg: &HeimdallConfig,
    chans: &Channels,
    now: DateTime<Utc>,
) -> anyhow::Result<DrainResult> {
    for (route, kind) in orphaned(pool, chans).await? {
        super::warn_once(
            &format!("orphan|{route}|{kind}"),
            &format!(
                "outbox has unsent {kind} alerts for channel `{route}`, which is no longer \
                 configured as a {kind} channel; they stay queued (see the alert channels \
                 guide to clear them)"
            ),
        );
    }
    let mut ready: Vec<&ChannelConfig> = Vec::new();
    for ch in &chans.list {
        match channels::missing_env(ch, &chans.secrets) {
            None => ready.push(ch),
            Some(var) => super::warn_once(
                &format!("webhook|{}", ch.name()),
                &format!(
                    "{} channel {}: {var} is not set; its alerts stay queued",
                    ch.type_name(),
                    ch.name()
                ),
            ),
        }
    }
    let mut result = DrainResult::default();
    if ready.is_empty() {
        return Ok(result);
    }
    let names: Vec<&str> = ready.iter().map(|c| c.name()).collect();
    let types: Vec<&str> = ready.iter().map(|c| c.type_name()).collect();

    let mut tx = pool.begin().await?;
    let row: Option<(i64, String, Value, i32)> = sqlx::query_as(
        "SELECT id, route, card, attempts FROM outbox \
         WHERE sent_at IS NULL AND next_attempt_at <= $1 \
           AND (route, channel_type) IN (SELECT * FROM unnest($2::text[], $3::text[])) \
         ORDER BY id LIMIT 1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(now)
    .bind(&names)
    .bind(&types)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, route, card, attempts)) = row else {
        return Ok(result);
    };
    let Some(ch) = ready.iter().copied().find(|c| c.name() == route) else {
        return Ok(result);
    };
    let kind = ch.type_name();
    result.channel_type = Some(kind);

    match attempt(d, ch, &card, now, &chans.secrets).await {
        Outcome::Sent => {
            sqlx::query("UPDATE outbox SET sent_at = $2 WHERE id = $1")
                .bind(id)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            result.sent = 1;
        }
        Outcome::Retry {
            retry_after_secs,
            why,
        } => {
            let next = now + backoff(attempts, retry_after_secs);
            tracing::warn!(route = %route, channel_type = kind, outbox_id = id, retry_at = %next,
                           "{kind} send failed: {why}");
            record_retry(&mut tx, id, next, now, &why).await?;
            result.retry = 1;
        }
        Outcome::Hold(why) => {
            // The channel itself is broken (SMTP login refused): back this row
            // off and hold every other queued row of the channel until then,
            // instead of burning through (or discarding) the backlog.
            let next = now + backoff(attempts, None);
            tracing::warn!(route = %route, channel_type = kind, outbox_id = id, retry_at = %next,
                           "{kind} channel {route} is failing; holding its queue: {why}");
            record_retry(&mut tx, id, next, now, &why).await?;
            sqlx::query(
                "UPDATE outbox SET next_attempt_at = GREATEST(next_attempt_at, $2) \
                 WHERE route = $1 AND channel_type = $3 AND sent_at IS NULL",
            )
            .bind(&route)
            .bind(next)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
            result.retry = 1;
        }
        Outcome::Rejected(why) => {
            // Sending the same payload again would be rejected again.
            tracing::error!(route = %route, channel_type = kind, outbox_id = id,
                            "{kind} rejected the alert; giving up: {why}");
            sqlx::query(
                "UPDATE outbox SET sent_at = $2, card = jsonb_set(card, '{failed}', 'true'), \
                 last_error_at = $2, last_error = $3 WHERE id = $1",
            )
            .bind(id)
            .bind(now)
            .bind(&why)
            .execute(&mut *tx)
            .await?;
            result.failed = 1;
        }
    }
    tx.commit().await?;
    Ok(result)
}

/// Back row `id` off until `next` and record why it failed.
async fn record_retry(
    tx: &mut PgConnection,
    id: i64,
    next: DateTime<Utc>,
    now: DateTime<Utc>,
    why: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = $2, \
         last_error_at = $3, last_error = $4 WHERE id = $1",
    )
    .bind(id)
    .bind(next)
    .bind(now)
    .bind(why)
    .execute(tx)
    .await?;
    Ok(())
}

/// Build and send `payload` to `ch`. Every reason in the outcome is
/// redacted: the request's `redact` list and every secret value `ch` uses
/// are replaced with `[redacted]`, so it is safe to log and to store.
async fn attempt(
    d: &Delivery<'_>,
    ch: &ChannelConfig,
    payload: &Value,
    now: DateTime<Utc>,
    secrets: &Secrets,
) -> Outcome {
    let mut hide = channels::secret_values(ch, secrets);
    let outcome = match channels::request(ch, payload, now, secrets) {
        Ok(req) => {
            if let Request::Http { redact, .. } = &req {
                hide.extend(redact.iter().cloned());
            }
            send(d, ch, req).await
        }
        Err(e) => Outcome::Rejected(format!("cannot build the request: {e:#}")),
    };
    // Longest first, so a URL goes before a token inside it.
    hide.sort_by_key(|s| std::cmp::Reverse(s.len()));
    match outcome {
        Outcome::Sent => Outcome::Sent,
        Outcome::Retry {
            retry_after_secs,
            why,
        } => Outcome::Retry {
            retry_after_secs,
            why: scrub(why, &hide),
        },
        Outcome::Hold(why) => Outcome::Hold(scrub(why, &hide)),
        Outcome::Rejected(why) => Outcome::Rejected(scrub(why, &hide)),
    }
}

/// Send a fixed test alert to `ch` now, not through the outbox. Any outcome
/// but sent is an error, with secrets redacted.
pub async fn send_now(
    d: &Delivery<'_>,
    ch: &ChannelConfig,
    secrets: &Secrets,
    now: DateTime<Utc>,
) -> Result<(), String> {
    let payload = channels::render(ch, &Alert::test());
    match attempt(d, ch, &payload, now, secrets).await {
        Outcome::Sent => Ok(()),
        Outcome::Retry { why, .. } | Outcome::Hold(why) | Outcome::Rejected(why) => Err(why),
    }
}

/// The delivery state of one `(route, channel_type)` in the outbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Health {
    /// Unsent rows.
    pub queued: i64,
    /// The latest delivered row (rejected rows do not count).
    pub last_sent_at: Option<DateTime<Utc>>,
    /// The `last_error` of the oldest unsent row, if it has one.
    pub failing: Option<String>,
}

/// One `health` row: route, channel type, then the `Health` fields.
type HealthRow = (String, String, i64, Option<DateTime<Utc>>, Option<String>);

/// Health of every `(route, channel_type)` that has outbox rows.
pub async fn health(pool: &PgPool) -> anyhow::Result<HashMap<(String, String), Health>> {
    let rows: Vec<HealthRow> = sqlx::query_as(
        "SELECT route, channel_type, \
               count(*) FILTER (WHERE sent_at IS NULL), \
               max(sent_at) FILTER (WHERE card->>'failed' IS NULL), \
               (array_agg(last_error ORDER BY id) FILTER (WHERE sent_at IS NULL))[1] \
             FROM outbox GROUP BY route, channel_type",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(route, kind, queued, last_sent_at, failing)| {
            (
                (route, kind),
                Health {
                    queued,
                    last_sent_at,
                    failing,
                },
            )
        })
        .collect())
}

/// `(route, channel_type)` of unsent rows no configured channel matches
/// (removed, renamed, or changed type). They are never sent.
pub async fn orphaned(pool: &PgPool, chans: &Channels) -> anyhow::Result<Vec<(String, String)>> {
    let names: Vec<&str> = chans.list.iter().map(|c| c.name()).collect();
    let types: Vec<&str> = chans.list.iter().map(|c| c.type_name()).collect();
    let rows = sqlx::query_as(
        "SELECT DISTINCT route, channel_type FROM outbox \
         WHERE sent_at IS NULL \
           AND (route, channel_type) NOT IN (SELECT * FROM unnest($1::text[], $2::text[])) \
         ORDER BY 1, 2",
    )
    .bind(&names)
    .bind(&types)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Sent,
    Retry {
        retry_after_secs: Option<i64>,
        why: String,
    },
    /// Retry, and hold the channel's other queued rows as long.
    Hold(String),
    Rejected(String),
}

async fn send(d: &Delivery<'_>, ch: &ChannelConfig, req: Request) -> Outcome {
    match req {
        Request::Http {
            url,
            body,
            headers,
            auth,
            redact,
        } => send_http(d.http, &url, body, &headers, auth.as_ref(), &redact).await,
        Request::Email(msg) => {
            let ChannelConfig::Email(c) = ch else {
                return Outcome::Rejected("an email for a non-email channel".to_string());
            };
            match d.mailer.send(c, *msg).await {
                Ok(()) => Outcome::Sent,
                Err(MailError::Transient(why)) => Outcome::Retry {
                    retry_after_secs: None,
                    why,
                },
                Err(MailError::Permanent(why)) => Outcome::Rejected(why),
                Err(MailError::Auth(why)) => Outcome::Hold(why),
            }
        }
    }
}

/// Replace every secret in `s` with `[redacted]`.
fn scrub(mut s: String, secrets: &[String]) -> String {
    for secret in secrets.iter().filter(|x| !x.is_empty()) {
        s = s.replace(secret.as_str(), "[redacted]");
    }
    s
}

async fn send_http(
    http: &reqwest::Client,
    url: &str,
    body: Vec<u8>,
    headers: &[(&'static str, String)],
    auth: Option<&HttpAuth>,
    redact: &[String],
) -> Outcome {
    let mut rb = http
        .post(url)
        .timeout(std::time::Duration::from_secs(SEND_TIMEOUT_SECS))
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    for (k, v) in headers {
        rb = rb.header(*k, v);
    }
    rb = match auth {
        Some(HttpAuth::Basic(u, p)) => rb.basic_auth(u, Some(p)),
        Some(HttpAuth::Bearer(t)) => rb.bearer_auth(t),
        None => rb,
    };
    let resp = match rb.send().await {
        Ok(r) => r,
        Err(e) => {
            // Never the URL: a webhook URL is its password (Teams `sig=`,
            // Slack and Discord tokens), and Telegram's token is in the path.
            return Outcome::Retry {
                retry_after_secs: None,
                why: scrub(format!("{}", e.without_url()), redact),
            };
        }
    };
    let status = resp.status();
    if status.is_success() {
        return Outcome::Sent;
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        // Retry-After in seconds, at most the backoff cap so a huge value
        // can neither overflow the date nor park the row for days. The
        // HTTP-date form, negatives and garbage are ignored. Without the
        // header, a 429 body's `retry_after` (Discord) or
        // `parameters.retry_after` (Telegram) is used.
        let header = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok());
        let retry_after = match header {
            Some(s) => Some(s),
            None if status == StatusCode::TOO_MANY_REQUESTS => {
                let body: Value = resp.json().await.unwrap_or(Value::Null);
                body["retry_after"]
                    .as_f64()
                    .or(body["parameters"]["retry_after"].as_f64())
                    .filter(|s| s.is_finite() && *s >= 0.0)
                    .map(|s| s.ceil().min(BACKOFF_CAP_SECS as f64) as u64)
            }
            None => None,
        };
        return Outcome::Retry {
            retry_after_secs: retry_after.map(|secs| secs.min(BACKOFF_CAP_SECS as u64) as i64),
            why: format!("{status}"),
        };
    }
    Outcome::Rejected(format!("{status}"))
}

/// The delay before the next attempt: 30 s doubled per earlier attempt,
/// capped at 1 h, or the server's Retry-After when that is longer (it is
/// already clamped to 1 h).
fn backoff(attempts: i32, retry_after_secs: Option<i64>) -> Duration {
    // 2^7 x 30 s already passes the cap; clamping keeps the shift small.
    let exp = attempts.clamp(0, 7) as u32;
    let ours = (BACKOFF_BASE_SECS << exp).min(BACKOFF_CAP_SECS);
    Duration::seconds(ours.max(retry_after_secs.unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_an_hour_and_honours_retry_after() {
        assert_eq!(backoff(0, None), Duration::seconds(30));
        assert_eq!(backoff(3, None), Duration::seconds(240));
        assert_eq!(backoff(20, None), Duration::seconds(3600));
        assert_eq!(backoff(0, Some(120)), Duration::seconds(120));
        assert_eq!(backoff(4, Some(120)), Duration::seconds(480));
    }

    async fn post(url: &str, redact: &[String]) -> Outcome {
        send_http(
            &reqwest::Client::new(),
            url,
            b"{}".to_vec(),
            &[],
            None,
            redact,
        )
        .await
    }

    #[tokio::test]
    async fn send_error_does_not_leak_the_webhook_secret() {
        // A Teams Workflows URL carries its credential in `sig=`. Port 1 on
        // localhost refuses the connection, so the send fails at once.
        let url = "http://127.0.0.1:1/workflows/abc/triggers/manual/paths/invoke?sig=SECRET";
        let out = post(url, &[]).await;
        let Outcome::Retry { why, .. } = out else {
            panic!("a refused connection is retried");
        };
        assert!(!why.contains("SECRET"), "{why}");
        assert!(!why.contains("sig="), "{why}");
    }

    #[tokio::test]
    async fn send_error_does_not_leak_the_telegram_token() {
        let token = "123456:AAH-telegram-SECRET".to_string();
        let url = format!("http://127.0.0.1:1/bot{token}/sendMessage");
        let Outcome::Retry { why, .. } = post(&url, std::slice::from_ref(&token)).await else {
            panic!("a refused connection is retried");
        };
        assert!(!why.contains("SECRET"), "{why}");
        assert_eq!(scrub(format!("x {token} y"), &[token]), "x [redacted] y");
    }
}
