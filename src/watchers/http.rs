//! HTTP helpers shared by the sources.

use anyhow::Context;
use reqwest::header::{ETAG, IF_NONE_MATCH, USER_AGENT};
use reqwest::{Client, Response, StatusCode};
use url::Url;

use super::UA;
use crate::vuln::retry;

/// `base` plus `path`, keeping any path `base` already has (a chart repo URL
/// such as `https://x/charts` must not lose `charts`, as `Url::join` would).
pub(super) fn endpoint(base: &Url, path: &str) -> anyhow::Result<Url> {
    let s = format!("{}/{}", base.as_str().trim_end_matches('/'), path);
    Url::parse(&s).with_context(|| format!("bad url {s}"))
}

/// GET through the shared retry helper, with `If-None-Match` when we hold an
/// ETag and a Bearer token when given. `Ok(None)` means 304 Not Modified.
pub(super) async fn get(
    http: &Client,
    what: &str,
    url: Url,
    etag: Option<&str>,
    bearer: Option<&str>,
) -> anyhow::Result<Option<Response>> {
    let resp = retry::send(what, || {
        let mut req = http.get(url.clone()).header(USER_AGENT, UA);
        if let Some(e) = etag {
            req = req.header(IF_NONE_MATCH, e);
        }
        if let Some(t) = bearer {
            req = req.bearer_auth(t);
        }
        req
    })
    .await?;
    if resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(None);
    }
    Ok(Some(resp))
}

pub(super) fn etag_of(resp: &Response) -> Option<String> {
    resp.headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// True when `err` came from a 404. The retry helper reports every non-2xx
/// status as `"{what}: HTTP 404 Not Found"`, so the text is all there is to
/// match on. Used where a missing page is an answer, not a failure.
pub(super) fn is_not_found(err: &anyhow::Error) -> bool {
    err.to_string().contains("HTTP 404")
}

/// True when `err` is a 403 or 429, which is how GitHub answers an exhausted
/// rate limit. Only meaningful for an error from a GitHub request: other
/// services use 403 for "denied".
pub(super) fn is_rate_limited(err: &anyhow::Error) -> bool {
    let text = err.to_string();
    text.contains("HTTP 403") || text.contains("HTTP 429")
}
