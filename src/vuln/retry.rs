//! One small retry helper shared by the OSV and NVD clients and the watchers.

use std::time::Duration;

use anyhow::anyhow;
use reqwest::{header::RETRY_AFTER, RequestBuilder, Response, StatusCode};

/// Total tries per request (the first one plus three retries).
const MAX_ATTEMPTS: u32 = 4;
/// First backoff; doubles each retry (0.5 s, 1 s, 2 s).
const BASE_DELAY: Duration = Duration::from_millis(500);
/// A server asking for longer than this is not waited for.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60);

/// Send the request built by `build`, retrying 429, 5xx and network errors with
/// exponential backoff (a `Retry-After` in seconds wins). `build` is a closure
/// because a `RequestBuilder` is consumed by `send`. Any other non-2xx status
/// is an error at once. The returned response has a success status, or is a
/// 304 Not Modified (only possible when the caller sent a validator such as
/// `If-None-Match`, as the watchers do).
pub async fn send(what: &str, build: impl Fn() -> RequestBuilder) -> anyhow::Result<Response> {
    let mut attempt = 0;
    loop {
        attempt += 1;
        let last = attempt == MAX_ATTEMPTS;
        let backoff = BASE_DELAY * 2u32.pow(attempt - 1);
        match build().send().await {
            Ok(resp) if resp.status().is_success() || resp.status() == StatusCode::NOT_MODIFIED => {
                return Ok(resp)
            }
            Ok(resp) => {
                let status = resp.status();
                if last || !retryable(status) {
                    return Err(anyhow!("{what}: HTTP {status}"));
                }
                tokio::time::sleep(retry_after(&resp).unwrap_or(backoff)).await;
            }
            Err(e) => {
                if last {
                    return Err(request_failed(what, e));
                }
                tokio::time::sleep(backoff).await;
            }
        }
    }
}

/// The error for a request that could not be sent. reqwest puts the full
/// URL in its errors, and a URL can carry a credential (a Teams webhook's
/// `sig=`), so it is dropped; `what` says which request it was.
pub fn request_failed(what: &str, e: reqwest::Error) -> anyhow::Error {
    anyhow::Error::new(e.without_url()).context(format!("{what}: request failed"))
}

fn retryable(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Only the delta-seconds form; an HTTP-date falls back to the backoff.
fn retry_after(resp: &Response) -> Option<Duration> {
    let secs: u64 = resp
        .headers()
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(secs).min(MAX_RETRY_AFTER))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_error_does_not_leak_the_url() {
        let url = "http://127.0.0.1:1/hook?sig=SECRET";
        let e = reqwest::Client::new().get(url).send().await.unwrap_err();
        let msg = format!("{:#}", request_failed("teams webhook", e));
        assert!(!msg.contains("SECRET"), "{msg}");
        assert!(msg.contains("teams webhook"), "{msg}");
    }
}
