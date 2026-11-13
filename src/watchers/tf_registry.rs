//! Terraform / OpenTofu registry (same protocol):
//! `GET /v1/providers/{ns}/{name}/versions` or
//! `GET /v1/modules/{ns}/{name}/{provider}/versions`.

use anyhow::{bail, Context};
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::http::{endpoint, etag_of, get};
use super::{Fetched, ReleaseInfo};
use crate::config::TfKind;

/// Providers answer `{versions: [..]}`, modules `{modules: [{versions: [..]}]}`.
#[derive(Deserialize)]
struct Body {
    #[serde(default)]
    versions: Vec<Version>,
    #[serde(default)]
    modules: Vec<Module>,
}

#[derive(Deserialize)]
struct Module {
    #[serde(default)]
    versions: Vec<Version>,
}

#[derive(Deserialize)]
struct Version {
    version: String,
}

/// Every version of a provider (`source` = `ns/name`) or module
/// (`ns/name/provider`). The registry gives no dates.
pub async fn fetch(
    http: &Client,
    base: &Url,
    kind: TfKind,
    source: &str,
    etag: Option<&str>,
) -> anyhow::Result<Fetched> {
    let segments = source.split('/').filter(|s| !s.is_empty()).count();
    let path = match (kind, segments) {
        (TfKind::Provider, 2) => format!("v1/providers/{source}/versions"),
        (TfKind::Module, 3) => format!("v1/modules/{source}/versions"),
        _ => bail!("tf registry: bad {kind:?} source {source}"),
    };
    let url = endpoint(base, &path)?;
    let what = format!("tf registry {source}");
    let Some(resp) = get(http, &what, url, etag, None).await? else {
        return Ok(Fetched::not_modified(etag));
    };
    let new_etag = etag_of(&resp);
    let body: Body = resp.json().await.with_context(|| format!("{what}: body"))?;
    let versions = body
        .versions
        .into_iter()
        .chain(body.modules.into_iter().flat_map(|m| m.versions));
    let releases = versions
        .map(|v| ReleaseInfo {
            version: v.version,
            published_at: None,
        })
        .collect();
    Ok(Fetched {
        releases,
        etag: new_etag,
        not_modified: false,
    })
}
