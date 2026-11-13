//! GitHub Releases: `GET /repos/{repo}/releases?per_page=30`.

use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{endpoint, etag_of, get, Fetched, ReleaseInfo};

#[derive(Deserialize)]
struct GhRelease {
    tag_name: String,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    published_at: Option<DateTime<Utc>>,
}

/// The latest 30 releases of `repo` (`owner/name`), without drafts and
/// pre-releases. Versions are the raw tag names. `token` (from
/// `GITHUB_TOKEN`) raises the rate limit to 5,000 requests an hour; `etag`
/// makes an unchanged list a cheap 304.
pub async fn fetch(
    http: &Client,
    base: &Url,
    repo: &str,
    token: Option<&str>,
    etag: Option<&str>,
) -> anyhow::Result<Fetched> {
    let url = endpoint(base, &format!("repos/{repo}/releases?per_page=30"))?;
    let what = format!("github {repo}");
    let Some(resp) = get(http, &what, url, etag, token).await? else {
        return Ok(Fetched::not_modified(etag));
    };
    let new_etag = etag_of(&resp);
    let list: Vec<GhRelease> = resp.json().await.with_context(|| format!("{what}: body"))?;
    let releases = list
        .into_iter()
        .filter(|r| !r.draft && !r.prerelease)
        .map(|r| ReleaseInfo {
            version: r.tag_name,
            published_at: r.published_at,
        })
        .collect();
    Ok(Fetched {
        releases,
        etag: new_etag,
        not_modified: false,
    })
}
