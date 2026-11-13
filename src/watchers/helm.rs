//! Helm chart repositories: `GET {repo}/index.yaml`. OCI charts are read with
//! `oci::tags` instead (see `watchers::fetch_target`).

use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{endpoint, etag_of, get, Fetched, ReleaseInfo};

#[derive(Deserialize)]
struct Index {
    #[serde(default)]
    entries: HashMap<String, Vec<Entry>>,
}

#[derive(Deserialize)]
struct Entry {
    version: String,
    /// Kept as text: one odd date must not fail the whole index.
    created: Option<String>,
}

/// Every version of `chart` listed in the repository index at `repo_url`.
pub async fn fetch_index(
    http: &Client,
    repo_url: &Url,
    chart: &str,
    etag: Option<&str>,
) -> anyhow::Result<Fetched> {
    let url = endpoint(repo_url, "index.yaml")?;
    let what = format!("helm {repo_url} {chart}");
    let Some(resp) = get(http, &what, url, etag, None).await? else {
        return Ok(Fetched::not_modified(etag));
    };
    let new_etag = etag_of(&resp);
    let text = resp.text().await.with_context(|| format!("{what}: body"))?;
    let mut index: Index =
        serde_yaml::from_str(&text).with_context(|| format!("{what}: index.yaml"))?;
    let releases = index
        .entries
        .remove(chart)
        .unwrap_or_default()
        .into_iter()
        .map(|e| ReleaseInfo {
            version: e.version,
            published_at: e
                .created
                .and_then(|c| DateTime::parse_from_rfc3339(&c).ok())
                .map(|c| c.with_timezone(&Utc)),
        })
        .collect();
    Ok(Fetched {
        releases,
        etag: new_etag,
        not_modified: false,
    })
}
