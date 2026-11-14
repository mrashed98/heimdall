//! Go module proxy: `GET {proxy}/{escaped module}/@v/list`.
//!
//! A new Go major is a new module path (`.../v2`), so `@v/list` of the
//! module we run never shows it; `fetch_next_major` asks for the next one.

use anyhow::{bail, Context};
use reqwest::header::USER_AGENT;
use reqwest::{Client, StatusCode};
use url::Url;

use super::http::{endpoint, etag_of, get};
use super::UA;
use super::{Fetched, ReleaseInfo};
use crate::vuln::retry;

/// The proxy's case encoding: every uppercase letter becomes `!` plus its
/// lowercase form, so `BurntSushi` is `!burnt!sushi`.
pub fn escape(module: &str) -> String {
    let mut out = String::with_capacity(module.len() + 4);
    for c in module.chars() {
        if c.is_ascii_uppercase() {
            out.push('!');
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Every tagged version of `module` (one per line in the response). The list
/// has no dates.
pub async fn fetch(
    http: &Client,
    base: &Url,
    module: &str,
    etag: Option<&str>,
) -> anyhow::Result<Fetched> {
    let url = endpoint(base, &format!("{}/@v/list", escape(module)))?;
    let what = format!("go proxy {module}");
    let Some(resp) = get(http, &what, url, etag, None).await? else {
        return Ok(Fetched::not_modified(etag));
    };
    let new_etag = etag_of(&resp);
    let text = resp.text().await.with_context(|| format!("{what}: body"))?;
    Ok(Fetched {
        releases: versions(&text),
        etag: new_etag,
        not_modified: false,
    })
}

/// The module path of the next major: `x/y` -> `x/y/v2`, `x/y/v3` -> `x/y/v4`.
/// v0 and v1 have no suffix, so both count as major 1.
pub fn next_major_module(module: &str) -> String {
    let current = module.rsplit_once('/').and_then(|(prefix, last)| {
        let n: u64 = last.strip_prefix('v')?.parse().ok()?;
        (n >= 2).then_some((prefix, n))
    });
    match current {
        Some((prefix, n)) => format!("{prefix}/v{}", n + 1),
        None => format!("{module}/v2"),
    }
}

/// Versions of the next major module of `module`; empty when the proxy has
/// none (404 or 410).
pub async fn fetch_next_major(
    http: &Client,
    base: &Url,
    module: &str,
) -> anyhow::Result<Vec<ReleaseInfo>> {
    let next = next_major_module(module);
    let url = endpoint(base, &format!("{}/@v/list", escape(&next)))?;
    // Not through the retry helper: 404/410 is the usual, expected answer
    // and must not be an error.
    let resp = http
        .get(url)
        .header(USER_AGENT, UA)
        .send()
        .await
        .map_err(|e| retry::request_failed(&format!("go proxy {next}"), e))?;
    match resp.status() {
        StatusCode::NOT_FOUND | StatusCode::GONE => return Ok(Vec::new()),
        s if !s.is_success() => bail!("go proxy {next}: HTTP {s}"),
        _ => {}
    }
    let text = resp
        .text()
        .await
        .with_context(|| format!("go proxy {next}: body"))?;
    Ok(versions(&text))
}

fn versions(text: &str) -> Vec<ReleaseInfo> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|v| ReleaseInfo {
            version: v.to_string(),
            published_at: None,
        })
        .collect()
}
