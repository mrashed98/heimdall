//! OCI distribution registries: `GET /v2/{repository}/tags/list`, with the
//! bearer-token handshake (Docker Hub answers 401 and names `auth.docker.io`)
//! and `Link`-header paging.

use std::collections::HashMap;

use anyhow::{bail, Context};
use reqwest::header::{ACCEPT, IF_NONE_MATCH, LINK, USER_AGENT, WWW_AUTHENTICATE};
use reqwest::{Client, Response, StatusCode};
use serde::Deserialize;
use url::Url;

use super::http::{endpoint, etag_of, get, is_not_found};
use super::{Fetched, ReleaseInfo, UA};
use crate::config::RegistryCred;
use crate::vuln::retry;

/// Docker Hub's library images have thousands of tags; stop after this many pages.
const MAX_PAGES: usize = 20;

#[derive(Deserialize)]
struct TagList {
    #[serde(default)]
    tags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Token {
    token: Option<String>,
    access_token: Option<String>,
}

/// Every tag of `repository` (`library/postgres`) on the registry at `base`.
/// `creds` names an env var holding `username:password`, sent only to the
/// token service; without it the token is anonymous.
pub async fn tags(
    http: &Client,
    base: &Url,
    repository: &str,
    creds: Option<&RegistryCred>,
    etag: Option<&str>,
) -> anyhow::Result<Fetched> {
    let what = format!("oci {repository}");
    let url = endpoint(base, &format!("v2/{repository}/tags/list"))?;

    // A first, unauthenticated try (no retry wrapper: a 401 is expected here
    // and carries the challenge we need).
    let mut probe = http.get(url.clone()).header(USER_AGENT, UA);
    if let Some(e) = etag {
        probe = probe.header(IF_NONE_MATCH, e);
    }
    let mut resp = probe
        .send()
        .await
        .map_err(|e| retry::request_failed(&what, e))?;
    let mut token = None;
    if resp.status() == StatusCode::UNAUTHORIZED {
        token = Some(bearer_token(http, &resp, repository, creds).await?);
        match get(http, &what, url, etag, token.as_deref()).await? {
            Some(r) => resp = r,
            None => return Ok(Fetched::not_modified(etag)),
        }
    } else if resp.status() == StatusCode::NOT_MODIFIED {
        return Ok(Fetched::not_modified(etag));
    } else if !resp.status().is_success() {
        bail!("{what}: HTTP {}", resp.status());
    }

    // Page 1's ETag only vouches for page 1: a new tag on a later page would
    // hide behind a 304. So it is kept only when the list is a single page.
    let mut new_etag = etag_of(&resp);
    let mut tags = Vec::new();
    for page in 1.. {
        let next = next_link(&resp);
        if next.is_some() {
            new_etag = None;
        }
        let list: TagList = resp.json().await.with_context(|| format!("{what}: body"))?;
        tags.extend(list.tags.unwrap_or_default());
        let Some(next) = next else { break };
        if page == MAX_PAGES {
            tracing::warn!("{what}: stopped after {MAX_PAGES} pages of tags");
            break;
        }
        // The link is usually host-relative (`/v2/...?last=..`).
        let next_url = base
            .join(&next)
            .with_context(|| format!("{what}: bad link"))?;
        resp = get(http, &what, next_url, None, token.as_deref())
            .await?
            .with_context(|| format!("{what}: unexpected 304"))?;
    }
    let releases = tags
        .into_iter()
        .map(|t| ReleaseInfo {
            version: t,
            published_at: None,
        })
        .collect();
    Ok(Fetched {
        releases,
        etag: new_etag,
        not_modified: false,
    })
}

/// Manifest types we can read; an index (multi-arch image) lists manifests.
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.index.v1+json, \
    application/vnd.docker.distribution.manifest.list.v2+json, \
    application/vnd.oci.image.manifest.v1+json, \
    application/vnd.docker.distribution.manifest.v2+json";

#[derive(Deserialize)]
struct Descriptor {
    digest: String,
}

/// A manifest has a `config`; an index has `manifests` instead.
#[derive(Deserialize)]
struct Manifest {
    config: Option<Descriptor>,
    manifests: Option<Vec<Descriptor>>,
}

#[derive(Deserialize)]
struct ImageConfig {
    config: Option<ConfigSection>,
}

#[derive(Deserialize)]
struct ConfigSection {
    #[serde(rename = "Labels")]
    labels: Option<HashMap<String, String>>,
}

/// The value of image label `label` for `repository:tag`: manifest, then the
/// config blob it names, then the blob's `config.Labels`. `Ok(None)` when the
/// image, the blob or the label is not there.
pub async fn image_label(
    http: &Client,
    base: &Url,
    repository: &str,
    tag: &str,
    label: &str,
    creds: Option<&RegistryCred>,
) -> anyhow::Result<Option<String>> {
    let what = format!("oci {repository}:{tag}");
    let manifest_url = endpoint(base, &format!("v2/{repository}/manifests/{tag}"))?;

    // Same handshake as `tags`: an unauthenticated probe, whose 401 names the
    // token service. The token then serves the manifest and the blob.
    let probe = http
        .get(manifest_url.clone())
        .header(USER_AGENT, UA)
        .header(ACCEPT, MANIFEST_ACCEPT)
        .send()
        .await
        .map_err(|e| retry::request_failed(&what, e))?;
    let token = match probe.status() {
        StatusCode::UNAUTHORIZED => Some(bearer_token(http, &probe, repository, creds).await?),
        StatusCode::NOT_FOUND => return Ok(None),
        s if !s.is_success() => bail!("{what}: HTTP {s}"),
        _ => None,
    };

    let Some(mut manifest) = manifest_at(http, &what, manifest_url, token.as_deref()).await? else {
        return Ok(None);
    };
    // Any platform's manifest carries the same source label: take the first.
    if let Some(first) = manifest.manifests.as_ref().and_then(|m| m.first()) {
        let url = endpoint(base, &format!("v2/{repository}/manifests/{}", first.digest))?;
        match manifest_at(http, &what, url, token.as_deref()).await? {
            Some(m) => manifest = m,
            None => return Ok(None),
        }
    }
    let Some(config) = manifest.config else {
        return Ok(None);
    };
    let blob_url = endpoint(base, &format!("v2/{repository}/blobs/{}", config.digest))?;
    let resp = match retry::send(&what, || {
        let req = http.get(blob_url.clone()).header(USER_AGENT, UA);
        match token.as_deref() {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    })
    .await
    {
        Ok(r) => r,
        Err(e) if is_not_found(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let image: ImageConfig = resp
        .json()
        .await
        .with_context(|| format!("{what}: config"))?;
    Ok(image
        .config
        .and_then(|c| c.labels)
        .and_then(|mut l| l.remove(label)))
}

async fn manifest_at(
    http: &Client,
    what: &str,
    url: Url,
    token: Option<&str>,
) -> anyhow::Result<Option<Manifest>> {
    let sent = retry::send(what, || {
        let req = http
            .get(url.clone())
            .header(USER_AGENT, UA)
            .header(ACCEPT, MANIFEST_ACCEPT);
        match token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    })
    .await;
    match sent {
        Ok(resp) => Ok(Some(
            resp.json()
                .await
                .with_context(|| format!("{what}: manifest"))?,
        )),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Answer a `WWW-Authenticate: Bearer realm=..,service=..,scope=..` challenge.
async fn bearer_token(
    http: &Client,
    challenge: &Response,
    repository: &str,
    creds: Option<&RegistryCred>,
) -> anyhow::Result<String> {
    let header = challenge
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|h| h.to_str().ok())
        .context("registry 401 without a challenge")?;
    let Some(params) = header.strip_prefix("Bearer ") else {
        bail!("registry asks for unsupported auth: {header}");
    };
    let params = challenge_params(params);
    let param = |k: &str| params.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());
    let realm = param("realm").context("challenge without realm")?;
    let mut url = Url::parse(&realm).with_context(|| format!("bad token realm {realm}"))?;
    {
        let mut q = url.query_pairs_mut();
        if let Some(service) = param("service") {
            q.append_pair("service", &service);
        }
        let scope = param("scope").unwrap_or_else(|| format!("repository:{repository}:pull"));
        q.append_pair("scope", &scope);
    }
    let secret = creds.and_then(|c| std::env::var(&c.secret_env).ok());
    let resp = retry::send(&format!("token for {repository}"), || {
        let req = http.get(url.clone()).header(USER_AGENT, UA);
        match secret.as_deref().and_then(|s| s.split_once(':')) {
            Some((user, pass)) => req.basic_auth(user, Some(pass)),
            None => req,
        }
    })
    .await?;
    let t: Token = resp.json().await.context("token response")?;
    t.token
        .or(t.access_token)
        .context("token response without a token")
}

/// `realm="https://x",service="y",scope="a:b:pull,push"` -> name/value pairs.
/// Values are quoted and may contain commas, so this is a small scanner rather
/// than a split on `,`.
fn challenge_params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some((name, after)) = rest.split_once('=') {
        let name = name.trim_matches(|c: char| c == ',' || c.is_whitespace());
        let (value, tail) = match after.strip_prefix('"') {
            Some(q) => q.split_once('"').unwrap_or((q, "")),
            None => after.split_once(',').unwrap_or((after, "")),
        };
        out.push((name.to_string(), value.to_string()));
        rest = tail;
    }
    out
}

/// The `rel="next"` target of a `Link` header, if any.
fn next_link(resp: &Response) -> Option<String> {
    let link = resp.headers().get(LINK)?.to_str().ok()?;
    link.split(',')
        .find(|part| part.contains("rel=\"next\""))
        .and_then(|part| {
            let start = part.find('<')? + 1;
            let end = part.find('>')?;
            Some(part[start..end].to_string())
        })
}
