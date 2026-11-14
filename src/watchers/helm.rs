//! Helm chart repositories: `GET {repo}/index.yaml`. OCI charts are read with
//! `oci::tags` instead (see `watchers::fetch_target`).

use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::http::{endpoint, etag_of, get};
use super::{Fetched, ReleaseInfo};

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

/// Public chart indexes are large (bitnami ~27 MB, ~1M YAML nodes), past
/// serde-saphyr's default 250k-node budget, so allow more here. The YAML
/// is untrusted; the budget stays finite to bound CPU and memory.
// ponytail: fixed caps; make them configurable if a real index outgrows them.
fn parse_index(text: &str) -> Result<Index, serde_saphyr::Error> {
    let options = serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_nodes: 5_000_000,
            max_events: 20_000_000,
        },
    };
    serde_saphyr::from_str_with_options(text, options)
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
    let mut index: Index = parse_index(&text).with_context(|| format!("{what}: index.yaml"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic index with more nodes than serde-saphyr's default budget,
    /// shaped like a big public repository.
    #[test]
    fn parses_an_index_past_the_default_node_budget() {
        let mut y = String::from("apiVersion: v1\nentries:\n");
        for c in 0..300 {
            y.push_str(&format!("  chart{c}:\n"));
            for v in 0..120 {
                y.push_str(&format!(
                    "  - version: 1.{v}.0\n    created: \"2026-01-01T00:00:00Z\"\n    urls: [a, b]\n    keywords: [x, y, z]\n    maintainers:\n    - name: m\n      email: e\n"
                ));
            }
        }
        assert!(
            serde_saphyr::from_str::<Index>(&y).is_err(),
            "default budget should be too small"
        );
        let index = parse_index(&y).unwrap();
        assert_eq!(index.entries.len(), 300);
        assert_eq!(index.entries["chart7"].len(), 120);
    }
}
