//! Finding and fetching a release's notes: GitHub Releases and Artifact Hub.

use std::collections::HashSet;

use anyhow::Context;
use reqwest::{Client, Response};
use serde::Deserialize;
use url::Url;

use super::super::http::{endpoint, get, is_not_found};
use super::super::{oci, registry_base, Endpoints, Origin, Planned};
use crate::config::HeimdallConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotesSource {
    GithubRepo(String),
    ArtifactHub { repo: String, chart: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notes {
    pub url: String,
    pub body: String,
}

pub fn github_repo(url: &str) -> Option<String> {
    let url = url.trim();
    let path = match url.strip_prefix("github:") {
        Some(rest) => rest,
        None => {
            let at = url.find("github.com")?;
            // `notgithub.com` must not match: the host starts after `/` or `@`.
            if at > 0 && !url[..at].ends_with(['/', '@']) {
                return None;
            }
            url[at + "github.com".len()..].trim_start_matches([':', '/'])
        }
    };
    let mut parts = path.split('/').filter(|p| !p.is_empty());
    let owner = parts.next()?;
    let repo = parts.next()?;
    let repo = repo.strip_suffix(".git").unwrap_or(repo);
    (!repo.is_empty()).then(|| format!("{owner}/{repo}"))
}

// ---- locating -------------------------------------------------------------

/// Where this target's release notes live, trying in order: the configured
/// repo (or GitHub watcher), the npm `repository.url`, a `github.com/` Go
/// module path, an image's `org.opencontainers.image.source` label, and
/// Artifact Hub for charts. Takes the whole `Planned` (not just the target)
/// because the origin holds the npm name, module path, image and chart repo.
pub(super) async fn locate(
    p: &Planned,
    http: &Client,
    ep: &Endpoints,
    cfg: &HeimdallConfig,
) -> anyhow::Result<Option<NotesSource>> {
    if let Some(repo) = &p.target.repo {
        return Ok(Some(NotesSource::GithubRepo(repo.clone())));
    }
    match &p.origin {
        Origin::Github { repo } => Ok(Some(NotesSource::GithubRepo(repo.clone()))),
        Origin::Npm { name } => {
            let url = endpoint(&ep.npm, &name.replace('/', "%2f"))?;
            let Some(resp) = get_or_404(http, &format!("npm {name}"), url, None).await? else {
                return Ok(None);
            };
            let doc: Packument = resp.json().await.context("npm packument")?;
            let url = match doc.repository {
                Some(Repository::Url(u)) => Some(u),
                Some(Repository::Object { url }) => url,
                None => None,
            };
            Ok(url
                .and_then(|u| github_repo(&u))
                .map(NotesSource::GithubRepo))
        }
        Origin::GoProxy { module } => Ok(module
            .strip_prefix("github.com/")
            .and_then(|rest| github_repo(&format!("github.com/{rest}")))
            .map(NotesSource::GithubRepo)),
        Origin::Oci { host, repository } => {
            // The tag we run is a version of the same image.
            let Some(tag) = &p.target.current else {
                return Ok(None);
            };
            let base = registry_base(ep, host)?;
            let creds = cfg.registries.iter().find(|r| &r.host == host);
            let label = oci::image_label(http, &base, repository, tag, SOURCE_LABEL, creds).await?;
            Ok(label
                .and_then(|l| github_repo(&l))
                .map(NotesSource::GithubRepo))
        }
        Origin::Helm { repo_url, chart } => artifact_hub_source(http, ep, repo_url, chart).await,
        Origin::Endoflife { .. } | Origin::Tf { .. } => Ok(None),
    }
}

/// The label an image's build sets to name its source repository.
const SOURCE_LABEL: &str = "org.opencontainers.image.source";

#[derive(Deserialize)]
struct Packument {
    repository: Option<Repository>,
}

/// npm accepts `"repository": "github:o/r"` as well as `{ "url": ... }`.
#[derive(Deserialize)]
#[serde(untagged)]
enum Repository {
    Url(String),
    Object { url: Option<String> },
}

/// Artifact Hub names a chart `{repo}/{chart}` where `repo` is whatever the
/// publisher called it, which the chart URL only hints at. Try the likely
/// names and keep the first whose package lists our chart repo as its source:
/// another publisher may have a chart of the same name under the same repo
/// name, and its notes would be the wrong ones.
async fn artifact_hub_source(
    http: &Client,
    ep: &Endpoints,
    repo_url: &str,
    chart: &str,
) -> anyhow::Result<Option<NotesSource>> {
    let mut candidates: Vec<String> = Vec::new();
    let trimmed = repo_url.trim_start_matches("oci://");
    let trimmed = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let mut parts = trimmed.trim_end_matches('/').split('/');
    if let Some(host) = parts.next() {
        // `prometheus-community.github.io` -> `prometheus-community`
        candidates.extend(host.split('.').next().map(str::to_string));
    }
    candidates.extend(parts.next_back().map(str::to_string));
    candidates.push(chart.to_string());

    let mut tried: HashSet<String> = HashSet::new();
    for repo in candidates {
        if repo.is_empty() || !tried.insert(repo.clone()) {
            continue;
        }
        let url = endpoint(
            &ep.artifacthub,
            &format!("api/v1/packages/helm/{repo}/{chart}"),
        )?;
        let what = format!("artifacthub {repo}/{chart}");
        let Some(resp) = get_or_404(http, &what, url, None).await? else {
            continue;
        };
        let pkg: HubPackage = resp.json().await.with_context(|| format!("{what}: body"))?;
        let hub_url = pkg.repository.and_then(|r| r.url).unwrap_or_default();
        if same_repo(&hub_url, repo_url) {
            return Ok(Some(NotesSource::ArtifactHub {
                repo,
                chart: chart.to_string(),
            }));
        }
    }
    Ok(None)
}

/// Two chart repo URLs are the same repo when they agree apart from the
/// scheme, case and trailing slashes. An empty URL matches nothing.
fn same_repo(a: &str, b: &str) -> bool {
    let norm = |u: &str| {
        let rest = u.split_once("://").map_or(u, |(_, rest)| rest);
        rest.trim_end_matches('/').to_lowercase()
    };
    !a.is_empty() && !b.is_empty() && norm(a) == norm(b)
}

/// GET where a 404 is an answer ("not there"), not a failure.
async fn get_or_404(
    http: &Client,
    what: &str,
    url: Url,
    bearer: Option<&str>,
) -> anyhow::Result<Option<Response>> {
    match get(http, what, url, None, bearer).await {
        Ok(resp) => Ok(resp),
        Err(e) if is_not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---- fetching -------------------------------------------------------------

#[derive(Deserialize)]
struct GhRelease {
    body: Option<String>,
    html_url: Option<String>,
}

#[derive(Deserialize)]
struct HubPackage {
    #[serde(default)]
    changes: Vec<HubChange>,
    repository: Option<HubRepository>,
}

#[derive(Deserialize)]
struct HubRepository {
    url: Option<String>,
}

#[derive(Deserialize)]
struct HubChange {
    kind: Option<String>,
    // A change without one must not fail the whole package (and so be retried
    // every run): it is skipped below.
    #[serde(default)]
    description: String,
}

/// The notes of one release, or None when the source has none. GitHub tags
/// are `v{version}` or plain `{version}`; both are tried, in that order (a
/// version that already starts with `v` is tried as it is first).
pub(super) async fn fetch(
    source: &NotesSource,
    version: &str,
    http: &Client,
    ep: &Endpoints,
) -> anyhow::Result<Option<Notes>> {
    match source {
        NotesSource::GithubRepo(repo) => {
            let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
            let tags = match version.strip_prefix('v') {
                Some(plain) => [version.to_string(), plain.to_string()],
                None => [format!("v{version}"), version.to_string()],
            };
            for tag in tags {
                let url = endpoint(&ep.github, &format!("repos/{repo}/releases/tags/{tag}"))?;
                let what = format!("github notes {repo}@{tag}");
                let Some(resp) = get_or_404(http, &what, url, token.as_deref()).await? else {
                    continue;
                };
                let rel: GhRelease = resp.json().await.with_context(|| format!("{what}: body"))?;
                let body = rel.body.unwrap_or_default();
                if body.trim().is_empty() {
                    return Ok(None);
                }
                let url = rel
                    .html_url
                    .unwrap_or_else(|| format!("https://github.com/{repo}/releases/tag/{tag}"));
                return Ok(Some(Notes { url, body }));
            }
            Ok(None)
        }
        NotesSource::ArtifactHub { repo, chart } => {
            let url = endpoint(
                &ep.artifacthub,
                &format!("api/v1/packages/helm/{repo}/{chart}/{version}"),
            )?;
            let what = format!("artifacthub {repo}/{chart}@{version}");
            let Some(resp) = get_or_404(http, &what, url, None).await? else {
                return Ok(None);
            };
            let pkg: HubPackage = resp.json().await.with_context(|| format!("{what}: body"))?;
            // One line per change, `fixed: ...`, so it reads like release notes.
            let body: String = pkg
                .changes
                .iter()
                .filter(|c| !c.description.trim().is_empty())
                .map(|c| match &c.kind {
                    Some(kind) => format!("{}: {}\n", kind.to_lowercase(), c.description),
                    None => format!("{}\n", c.description),
                })
                .collect();
            if body.trim().is_empty() {
                return Ok(None);
            }
            let url = format!("https://artifacthub.io/packages/helm/{repo}/{chart}/{version}");
            Ok(Some(Notes { url, body }))
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::watchers::notes::classify::{classify, NotesClass};
    use crate::watchers::notes::testutil::*;
    use crate::watchers::{Origin, WatchKind};

    #[test]
    fn github_repo_from_urls() {
        for url in [
            "git+https://github.com/vuejs/core.git",
            "https://github.com/vuejs/core",
            "git://github.com/vuejs/core.git",
            "git@github.com:vuejs/core.git",
            "github:vuejs/core",
            "https://github.com/vuejs/core/tree/main/packages/vue",
        ] {
            assert_eq!(github_repo(url).as_deref(), Some("vuejs/core"), "{url}");
        }
        assert_eq!(github_repo("https://gitlab.com/vuejs/core"), None);
        assert_eq!(github_repo("https://notgithub.com/a/b"), None);
    }

    // ---- locate and fetch -------------------------------------------------

    #[tokio::test]
    async fn locate_npm_repository_url() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/vue"))
            .respond_with(ResponseTemplate::new(200).set_body_string(fixture("npm_pkg_repo.json")))
            .mount(&server)
            .await;
        let p = planned(
            "pkg:npm/vue",
            WatchKind::Npm,
            Origin::Npm {
                name: "vue".to_string(),
            },
        );
        let got = locate(&p, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(got, Some(NotesSource::GithubRepo("vuejs/core".to_string())));
    }

    #[tokio::test]
    async fn locate_go_module_and_configured_repo() {
        let server = MockServer::start().await;
        let go = planned(
            "pkg:golang/github.com/gin-gonic/gin",
            WatchKind::GoProxy,
            Origin::GoProxy {
                module: "github.com/gin-gonic/gin/v2".to_string(),
            },
        );
        let got = locate(&go, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::GithubRepo("gin-gonic/gin".to_string()))
        );

        // A configured repo wins over anything derived.
        let mut kube = planned(
            "kubernetes",
            WatchKind::Endoflife,
            Origin::Endoflife {
                product: "kubernetes".to_string(),
            },
        );
        kube.target.repo = Some("kubernetes/kubernetes".to_string());
        let got = locate(&kube, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::GithubRepo("kubernetes/kubernetes".to_string()))
        );
    }

    #[tokio::test]
    async fn locate_oci_source_label_through_config_blob() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/acme/widget/manifests/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": {"digest": "sha256:abc"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/acme/widget/blobs/sha256:abc"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "config": {"Labels": {
                    "org.opencontainers.image.source": "https://github.com/acme/widget"
                }}
            })))
            .mount(&server)
            .await;
        let p = planned(
            "ghcr.io/acme/widget",
            WatchKind::Oci,
            Origin::Oci {
                host: "ghcr.io".to_string(),
                repository: "acme/widget".to_string(),
            },
        );
        let got = locate(&p, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::GithubRepo("acme/widget".to_string()))
        );
    }

    #[tokio::test]
    async fn artifact_hub_chart_changes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/packages/helm/prometheus-community/kube-prometheus-stack",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "repository": {"url": "https://prometheus-community.github.io/helm-charts/"}
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/packages/helm/prometheus-community/kube-prometheus-stack/65.1.0",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(fixture("artifacthub_chart.json")),
            )
            .mount(&server)
            .await;
        let p = planned(
            "pkg:helm/kube-prometheus-stack",
            WatchKind::Helm,
            Origin::Helm {
                repo_url: "https://prometheus-community.github.io/helm-charts".to_string(),
                chart: "kube-prometheus-stack".to_string(),
            },
        );
        let ep = endpoints(&server);
        let source = locate(&p, &Client::new(), &ep, &cfg())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            source,
            NotesSource::ArtifactHub {
                repo: "prometheus-community".to_string(),
                chart: "kube-prometheus-stack".to_string()
            }
        );
        let notes = fetch(&source, "65.1.0", &Client::new(), &ep)
            .await
            .unwrap()
            .unwrap();
        assert!(notes.body.contains("fixed: Alertmanager config reload"));
        let c = classify(&notes.body, &ids(&["CVE-2026-1234"]));
        assert_eq!(c.class, NotesClass::CveAffecting);
    }

    #[tokio::test]
    async fn fetch_tries_v_prefix_then_plain() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/v1.2.3"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/1.2.3"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(fixture("gh_release_security.json")),
            )
            .expect(1)
            .mount(&server)
            .await;
        let source = NotesSource::GithubRepo("acme/widget".to_string());
        let notes = fetch(&source, "1.2.3", &Client::new(), &endpoints(&server))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            notes.url,
            "https://github.com/acme/widget/releases/tag/v1.2.3"
        );
        assert!(notes.body.contains("CVE-2026-1234"));
    }

    #[tokio::test]
    async fn fetch_missing_release_is_none() {
        let server = MockServer::start().await;
        let source = NotesSource::GithubRepo("acme/widget".to_string());
        // Unmocked paths answer 404 on both tags.
        let got = fetch(&source, "9.9.9", &Client::new(), &endpoints(&server))
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    // ---- run (database) ---------------------------------------------------

    #[tokio::test]
    async fn artifact_hub_rejects_same_named_chart_from_another_publisher() {
        let server = MockServer::start().await;
        // First candidate (`prometheus-community`) is someone else's repo.
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/packages/helm/prometheus-community/kube-prometheus-stack",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "repository": {"url": "https://other.example/charts"}
            })))
            .mount(&server)
            .await;
        // The second (`helm-charts`) is ours; scheme and trailing slash differ.
        Mock::given(method("GET"))
            .and(path(
                "/api/v1/packages/helm/helm-charts/kube-prometheus-stack",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "repository": {"url": "http://Prometheus-Community.github.io/helm-charts/"}
            })))
            .mount(&server)
            .await;
        let p = planned(
            "pkg:helm/kube-prometheus-stack",
            WatchKind::Helm,
            Origin::Helm {
                repo_url: "https://prometheus-community.github.io/helm-charts".to_string(),
                chart: "kube-prometheus-stack".to_string(),
            },
        );
        let got = locate(&p, &Client::new(), &endpoints(&server), &cfg())
            .await
            .unwrap();
        assert_eq!(
            got,
            Some(NotesSource::ArtifactHub {
                repo: "helm-charts".to_string(),
                chart: "kube-prometheus-stack".to_string()
            })
        );
    }

    #[tokio::test]
    async fn artifact_hub_change_without_description_is_skipped() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/packages/helm/r/c/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "changes": [{"kind": "added"}, {"kind": "fixed", "description": "a thing"}]
            })))
            .mount(&server)
            .await;
        let source = NotesSource::ArtifactHub {
            repo: "r".to_string(),
            chart: "c".to_string(),
        };
        let notes = fetch(&source, "1.0.0", &Client::new(), &endpoints(&server))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(notes.body, "fixed: a thing\n");
    }

    #[tokio::test]
    async fn fetch_does_not_double_the_v_prefix() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/v1.2.3"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(fixture("gh_release_security.json")),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widget/releases/tags/vv1.2.3"))
            .respond_with(ResponseTemplate::new(200))
            .expect(0)
            .mount(&server)
            .await;
        let source = NotesSource::GithubRepo("acme/widget".to_string());
        let notes = fetch(&source, "v1.2.3", &Client::new(), &endpoints(&server))
            .await
            .unwrap();
        assert!(notes.is_some());
        // Dropped mock verifies the `vv` path got no request.
        drop(server);
    }
}
