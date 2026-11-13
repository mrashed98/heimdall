//! The outbox: cards queued in the database and sent to Teams one at a time.
//! Queued rows survive restarts; a sent row is never sent again.

use chrono::{DateTime, Duration, Utc};
use reqwest::header::RETRY_AFTER;
use reqwest::StatusCode;
use serde_json::Value;
use sqlx::{PgConnection, PgPool};

use crate::config::HeimdallConfig;

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
    /// Rejected by Teams (a 4xx other than 429): marked sent with
    /// `card.failed = true`. The scheduler adds it to
    /// `heimdall_teams_failures_total`.
    pub failed: usize,
}

/// Queue one card for one route.
pub(crate) async fn push(
    tx: &mut PgConnection,
    group_key: &str,
    card: &Value,
    route: &str,
) -> anyhow::Result<i64> {
    let id = sqlx::query_scalar(
        "INSERT INTO outbox (group_key, card, route) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(group_key)
    .bind(card)
    .bind(route)
    .fetch_one(&mut *tx)
    .await?;
    Ok(id)
}

/// Send at most one due card (oldest first); the caller loops every 2 s,
/// which paces Teams. Rows of a route whose webhook variable is unset stay
/// queued untouched until it is set.
///
/// The row is locked `FOR UPDATE SKIP LOCKED` for the whole send, so a second
/// drainer picks another row instead of sending this one twice.
pub async fn drain_once(
    pool: &PgPool,
    http: &reqwest::Client,
    cfg: &HeimdallConfig,
    now: DateTime<Utc>,
) -> anyhow::Result<DrainResult> {
    let mut webhooks: Vec<(String, String)> = Vec::new();
    for route in &cfg.teams {
        match std::env::var(&route.webhook_env) {
            Ok(url) if !url.is_empty() => webhooks.push((route.name.clone(), url)),
            _ => super::warn_once(
                &format!("webhook|{}", route.name),
                &format!(
                    "teams route {}: {} is not set; its cards stay queued",
                    route.name, route.webhook_env
                ),
            ),
        }
    }
    let mut result = DrainResult::default();
    if webhooks.is_empty() {
        return Ok(result);
    }
    let names: Vec<&str> = webhooks.iter().map(|(n, _)| n.as_str()).collect();

    let mut tx = pool.begin().await?;
    let row: Option<(i64, String, Value, i32)> = sqlx::query_as(
        "SELECT id, route, card, attempts FROM outbox \
         WHERE sent_at IS NULL AND next_attempt_at <= $1 AND route = ANY($2) \
         ORDER BY id LIMIT 1 \
         FOR UPDATE SKIP LOCKED",
    )
    .bind(now)
    .bind(&names)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((id, route, card, attempts)) = row else {
        return Ok(result);
    };
    let url = webhooks
        .iter()
        .find(|(n, _)| *n == route)
        .map(|(_, u)| u.as_str())
        .unwrap_or_default();

    match send(http, url, &card).await {
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
            tracing::warn!(route = %route, outbox_id = id, retry_at = %next, "teams send failed: {why}");
            sqlx::query(
                "UPDATE outbox SET attempts = attempts + 1, next_attempt_at = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(next)
            .execute(&mut *tx)
            .await?;
            result.retry = 1;
        }
        Outcome::Rejected(status) => {
            // Sending the same card again would be rejected again.
            tracing::error!(route = %route, outbox_id = id, status = %status, "teams rejected the card; giving up");
            sqlx::query(
                "UPDATE outbox SET sent_at = $2, card = jsonb_set(card, '{failed}', 'true') \
                 WHERE id = $1",
            )
            .bind(id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            result.failed = 1;
        }
    }
    tx.commit().await?;
    Ok(result)
}

enum Outcome {
    Sent,
    Retry {
        retry_after_secs: Option<i64>,
        why: String,
    },
    Rejected(StatusCode),
}

async fn send(http: &reqwest::Client, url: &str, card: &Value) -> Outcome {
    let resp = http
        .post(url)
        .timeout(std::time::Duration::from_secs(SEND_TIMEOUT_SECS))
        .json(card)
        .send()
        .await;
    let resp = match resp {
        Ok(r) => r,
        Err(e) => {
            return Outcome::Retry {
                retry_after_secs: None,
                why: format!("{e}"),
            }
        }
    };
    let status = resp.status();
    if status.is_success() {
        return Outcome::Sent;
    }
    if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        // Retry-After in seconds, at most the backoff cap so a huge value
        // can neither overflow the date nor park the card for days. The
        // HTTP-date form, negatives and garbage are ignored.
        let retry_after_secs = resp
            .headers()
            .get(RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .map(|secs| secs.min(BACKOFF_CAP_SECS as u64) as i64);
        return Outcome::Retry {
            retry_after_secs,
            why: format!("{status}"),
        };
    }
    Outcome::Rejected(status)
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
}
