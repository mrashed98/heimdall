//! endoflife.date, API v1: `GET /api/v1/products/{product}`.
//!
//! v1 is the current API (the older `/api/{product}.json` is the legacy
//! format). Each release cycle carries its end-of-life date and latest version.

use anyhow::Context;
use chrono::NaiveDate;
use reqwest::Client;
use serde::Deserialize;
use url::Url;

use super::{endpoint, get};

/// One release cycle (`16` for PostgreSQL, `1.31` for Kubernetes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cycle {
    pub cycle: String,
    /// The newest version in the cycle.
    pub latest: Option<String>,
    pub latest_date: Option<NaiveDate>,
    /// End of support; None when not announced.
    pub eol: Option<NaiveDate>,
}

#[derive(Deserialize)]
struct Body {
    result: Product,
}

#[derive(Deserialize)]
struct Product {
    #[serde(default)]
    releases: Vec<Release>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Release {
    name: String,
    eol_from: Option<NaiveDate>,
    latest: Option<Latest>,
}

#[derive(Deserialize)]
struct Latest {
    name: String,
    date: Option<NaiveDate>,
}

/// All cycles of `product`, newest first as the API lists them. No ETag: the
/// end-of-life check needs the cycles on every run.
pub async fn fetch(http: &Client, base: &Url, product: &str) -> anyhow::Result<Vec<Cycle>> {
    let url = endpoint(base, &format!("api/v1/products/{product}"))?;
    let what = format!("endoflife {product}");
    let resp = get(http, &what, url, None, None)
        .await?
        .with_context(|| format!("{what}: unexpected 304"))?;
    let body: Body = resp.json().await.with_context(|| format!("{what}: body"))?;
    Ok(body
        .result
        .releases
        .into_iter()
        .map(|r| Cycle {
            cycle: r.name,
            latest: r.latest.as_ref().map(|l| l.name.clone()),
            latest_date: r.latest.and_then(|l| l.date),
            eol: r.eol_from,
        })
        .collect())
}
