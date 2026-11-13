//! Go module proxy: `GET {proxy}/{escaped module}/@v/list`.

use anyhow::Context;
use reqwest::Client;
use url::Url;

use super::http::{endpoint, etag_of, get};
use super::{Fetched, ReleaseInfo};

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
    let releases = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|v| ReleaseInfo {
            version: v.to_string(),
            published_at: None,
        })
        .collect();
    Ok(Fetched {
        releases,
        etag: new_etag,
        not_modified: false,
    })
}
