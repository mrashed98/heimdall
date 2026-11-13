//! npm registry: `GET {registry}/{name}` -> `versions` and `time`.

use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::de::IgnoredAny;
use serde::Deserialize;
use url::Url;

use super::http::{endpoint, etag_of, get};
use super::{Fetched, ReleaseInfo};

/// Only the two fields we read. `IgnoredAny` skips each version's manifest
/// without keeping it in memory: packuments can be many megabytes.
#[derive(Deserialize)]
struct Packument {
    #[serde(default)]
    versions: HashMap<String, IgnoredAny>,
    /// `{version: publish time}`, plus `created` and `modified`.
    #[serde(default)]
    time: HashMap<String, String>,
}

/// Every published version of `name` (`left-pad` or `@scope/pkg`) with its
/// publish time.
pub async fn fetch(
    http: &Client,
    base: &Url,
    name: &str,
    etag: Option<&str>,
) -> anyhow::Result<Fetched> {
    // The registry wants the scope's slash encoded: `@vue%2fcore`.
    let url = endpoint(base, &name.replace('/', "%2f"))?;
    let what = format!("npm {name}");
    let Some(resp) = get(http, &what, url, etag, None).await? else {
        return Ok(Fetched::not_modified(etag));
    };
    let new_etag = etag_of(&resp);
    let doc: Packument = resp.json().await.with_context(|| format!("{what}: body"))?;
    let releases = doc
        .versions
        .into_keys()
        .map(|version| ReleaseInfo {
            published_at: doc
                .time
                .get(&version)
                .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.with_timezone(&Utc)),
            version,
        })
        .collect();
    Ok(Fetched {
        releases,
        etag: new_etag,
        not_modified: false,
    })
}
