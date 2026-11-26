//! Sight for Docker: what a Docker host runs, read from the Docker Engine
//! API, as the same inventory Sight sends for a cluster.
//!
//! Each running container is a service named `<host>/<name>`, where the
//! name is the `heimdall.service` label, else `<project>-<service>` from
//! Compose, else the container name. Its image is a component, and the
//! host's OS is one too, under the service `<host>`. The inventory carries
//! the origin `docker:<engine ID>`: stable across renames and unique per
//! daemon, so ingesting it replaces this daemon's services only, and a realm
//! can hold a cluster and any number of Docker hosts. `<host>` is only for
//! display: the name Docker reports, or the configured one.
//!
//! Only GET requests are made: `/info`, `/containers/json` and
//! `/images/{id}/json`. A socket proxy that allows just those is enough.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::sight::{digest_of, distro_purl, image_item, item, PodImage, Services};
use crate::ingest::api::ClusterInventory;

/// The Docker host when none is configured.
pub const DEFAULT_HOST: &str = "unix:///var/run/docker.sock";
/// The longest any one API call may take.
const TIMEOUT: Duration = Duration::from_secs(30);
/// The largest response read from the Docker API.
const MAX_BODY: usize = 32 * 1024 * 1024;

/// The Docker API answered 404: the object (an image removed after its
/// container started) no longer exists.
#[derive(Debug)]
pub struct NotFound;

impl std::fmt::Display for NotFound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not found")
    }
}

impl std::error::Error for NotFound {}

/// One client for every HTTP Docker host: no proxy from the environment (a
/// socket proxy sits on a private network) and no redirects (only the
/// listed API paths are read).
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(TIMEOUT)
            .build()
            .expect("a plain HTTP client builds")
    })
}

/// Where the Docker Engine API is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerHost {
    /// `unix:///var/run/docker.sock`
    Unix(PathBuf),
    /// `tcp://proxy:2375` or `http://proxy:2375` (plain HTTP, such as a
    /// socket proxy on a private network).
    Http(String),
}

impl std::str::FromStr for DockerHost {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if let Some(path) = s.strip_prefix("unix://") {
            if path.is_empty() {
                return Err(format!("`{s}` has no socket path"));
            }
            return Ok(DockerHost::Unix(PathBuf::from(path)));
        }
        let rest = s
            .strip_prefix("tcp://")
            .or_else(|| s.strip_prefix("http://"))
            .ok_or_else(|| {
                format!("`{s}` must start with unix://, tcp:// or http:// (TLS is not supported)")
            })?;
        let base = format!("http://{}", rest.trim_end_matches('/'));
        reqwest::Url::parse(&base).map_err(|e| format!("`{s}`: {e}"))?;
        Ok(DockerHost::Http(base))
    }
}

impl DockerHost {
    /// GET `path` and parse the JSON body.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        // Paths are built here from fixed text and validated ids; anything
        // else (a space, a line break) could smuggle a second request.
        if !path.starts_with('/') || !path.bytes().all(|b| b.is_ascii_graphic()) {
            bail!("refusing an unexpected Docker API path");
        }
        let body = match self {
            DockerHost::Unix(sock) => tokio::time::timeout(TIMEOUT, unix_get(sock, path))
                .await
                .with_context(|| format!("GET {path} timed out"))??,
            DockerHost::Http(base) => {
                let mut resp = http_client()
                    .get(format!("{base}{path}"))
                    .send()
                    .await
                    .with_context(|| format!("GET {path}"))?;
                let status = resp.status();
                if status == reqwest::StatusCode::NOT_FOUND {
                    return Err(anyhow::Error::new(NotFound).context(format!("GET {path}")));
                }
                if !status.is_success() {
                    bail!("GET {path}: {status}");
                }
                let mut body = Vec::new();
                while let Some(chunk) = resp.chunk().await? {
                    if body.len() + chunk.len() > MAX_BODY {
                        bail!("GET {path}: reply larger than {MAX_BODY} bytes");
                    }
                    body.extend_from_slice(&chunk);
                }
                body
            }
        };
        serde_json::from_slice(&body).with_context(|| format!("GET {path}: not the expected JSON"))
    }
}

/// A plain HTTP/1.0 GET over a Unix socket. HTTP/1.0 keeps the reply
/// unchunked and ends it by closing the connection.
async fn unix_get(sock: &std::path::Path, path: &str) -> anyhow::Result<Vec<u8>> {
    let mut stream = tokio::net::UnixStream::connect(sock)
        .await
        .with_context(|| format!("connecting to {}", sock.display()))?;
    stream
        .write_all(format!("GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n").as_bytes())
        .await?;
    let mut raw = Vec::new();
    (&mut stream)
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut raw)
        .await?;
    if raw.len() > MAX_BODY {
        bail!("GET {path}: reply larger than {MAX_BODY} bytes");
    }
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("reply has no header end")?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let status = head.split_whitespace().nth(1).unwrap_or_default();
    if status == "404" {
        return Err(anyhow::Error::new(NotFound).context(format!("GET {path}")));
    }
    if status != "200" {
        bail!("GET {path}: HTTP {status}");
    }
    Ok(raw[split + 4..].to_vec())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Info {
    /// The engine's ID: stable across renames, unique per daemon.
    #[serde(rename = "ID", default)]
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub operating_system: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Container {
    #[serde(default)]
    pub names: Vec<String>,
    pub image: String,
    #[serde(rename = "ImageID")]
    pub image_id: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Image {
    #[serde(default)]
    pub repo_digests: Vec<String>,
    #[serde(default)]
    pub repo_tags: Vec<String>,
}

/// What was read from one Docker host.
pub struct HostObjects {
    pub info: Info,
    pub containers: Vec<Container>,
    /// By image id.
    pub images: HashMap<String, Image>,
}

/// Read the running containers and their images.
pub async fn collect(host: &DockerHost) -> anyhow::Result<HostObjects> {
    let info: Info = host.get("/info").await?;
    let containers: Vec<Container> = host.get("/containers/json").await?;
    let mut images = HashMap::new();
    for c in &containers {
        if images.contains_key(&c.image_id) {
            continue;
        }
        if digest_of(&c.image_id).as_deref() != Some(c.image_id.as_str()) {
            bail!("container image id is not a sha256 digest");
        }
        // An image removed after its container started has no record left
        // (404); any other failure fails the scan rather than report the
        // host without its images' digests.
        match host
            .get::<Image>(&format!("/images/{}/json", c.image_id))
            .await
        {
            Ok(img) => {
                images.insert(c.image_id.clone(), img);
            }
            Err(e) if e.downcast_ref::<NotFound>().is_some() => {
                tracing::warn!(image = %c.image_id, "docker image no longer exists; reported without its digest")
            }
            Err(e) => return Err(e),
        }
    }
    Ok(HostObjects {
        info,
        containers,
        images,
    })
}

/// The origin a daemon's inventory carries: its engine ID (the reported
/// name only if the engine gives no ID).
pub fn origin(info: &Info) -> String {
    let id = if info.id.trim().is_empty() {
        &info.name
    } else {
        &info.id
    };
    format!("docker:{}", id.trim())
}

/// A container's service name, before the host prefix.
fn service_name(c: &Container) -> String {
    let label = |k: &str| c.labels.get(k).filter(|v| !v.trim().is_empty());
    if let Some(s) = label("heimdall.service") {
        return s.trim().to_string();
    }
    if let Some(s) = label("com.docker.compose.service") {
        // Two projects on one host may both have a `web`.
        return match label("com.docker.compose.project") {
            Some(p) => format!("{}-{}", p.trim(), s.trim()),
            None => s.trim().to_string(),
        };
    }
    c.names
        .first()
        .map(|n| n.trim_start_matches('/').to_string())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| c.image_id.chars().take(19).collect())
}

/// The image of `c` as Sight reports images: the reference with its tag,
/// and the manifest digest (pullable) when a registry digest of that same
/// repository is known, else the local image id (not pullable).
fn container_image(c: &Container, img: Option<&Image>) -> PodImage {
    let repo = |r: &str| {
        let no_digest = r.split('@').next().unwrap_or(r);
        match no_digest.rsplit_once(':') {
            Some((repo, tag)) if !tag.contains('/') => repo.to_string(),
            _ => no_digest.to_string(),
        }
    };
    let digests = img.map(|i| i.repo_digests.as_slice()).unwrap_or_default();
    let tags = img.map(|i| i.repo_tags.as_slice()).unwrap_or_default();
    // Started by id (`sha256:…` or a short hex prefix of it): no name in
    // `c.image`, so use a tag the image has, else its registry repository.
    let bare = c.image.trim_start_matches("sha256:");
    let by_id = !c.image.contains(['/', ':', '@'])
        && !bare.is_empty()
        && bare.bytes().all(|b| b.is_ascii_hexdigit())
        && c.image_id.trim_start_matches("sha256:").starts_with(bare)
        || digest_of(&c.image).is_some() && !c.image.contains('@');
    let reference = match (by_id, tags.first(), digests.first()) {
        (false, _, _) => c.image.clone(),
        (true, Some(tag), _) => tag.clone(),
        (true, None, Some(d)) => repo(d),
        (true, None, None) => c.image.clone(),
    };
    let want = repo(&reference);
    // Pinned by digest in the reference: that is the manifest digest.
    let pinned = c.image.split_once('@').and_then(|(_, d)| digest_of(d));
    let manifest = pinned.or_else(|| {
        digests
            .iter()
            .find(|d| repo(d) == want)
            .and_then(|d| digest_of(d))
    });
    match manifest {
        Some(digest) => PodImage {
            image: reference,
            digest,
            pullable: true,
        },
        None => PodImage {
            image: reference,
            digest: digest_of(&c.image_id).unwrap_or_else(|| c.image_id.clone()),
            pullable: false,
        },
    }
}

/// Pure: turn what was read from a Docker host into an inventory. `name`
/// overrides the host name Docker reports.
pub fn build_inventory(realm: &str, name: Option<&str>, objs: &HostObjects) -> ClusterInventory {
    let host = name.unwrap_or(&objs.info.name).to_string();
    let mut services = Services::default();
    for c in &objs.containers {
        let img = container_image(c, objs.images.get(&c.image_id));
        services.add(&format!("{host}/{}", service_name(c)), image_item(&img));
    }
    if let Some(purl) = distro_purl(&objs.info.operating_system) {
        services.add(&host, item(purl, None));
    }
    ClusterInventory {
        realm: realm.to_string(),
        services: services.finish(),
        origin: Some(origin(&objs.info)),
    }
}

/// Read a Docker host and return its inventory.
pub async fn scan(
    host: &DockerHost,
    realm: &str,
    name: Option<&str>,
) -> anyhow::Result<ClusterInventory> {
    let objs = collect(host).await?;
    Ok(build_inventory(realm, name, &objs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn objs(containers: Value, images: Value) -> HostObjects {
        HostObjects {
            info: serde_json::from_value(
                json!({"ID": "ENGINE-A", "Name": "vm1", "OperatingSystem": "Ubuntu 24.04.1 LTS"}),
            )
            .unwrap(),
            containers: serde_json::from_value(containers).unwrap(),
            images: serde_json::from_value(images).unwrap(),
        }
    }

    const D1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const D2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    const ID: &str = "sha256:9999999999999999999999999999999999999999999999999999999999999999";

    #[test]
    fn host_parses() {
        assert_eq!(
            DEFAULT_HOST.parse::<DockerHost>(),
            Ok(DockerHost::Unix("/var/run/docker.sock".into()))
        );
        assert_eq!(
            "tcp://proxy:2375".parse::<DockerHost>(),
            Ok(DockerHost::Http("http://proxy:2375".into()))
        );
        assert!("https://x".parse::<DockerHost>().is_err());
        assert!("unix://".parse::<DockerHost>().is_err());
    }

    #[test]
    fn containers_become_host_prefixed_services() {
        let o = objs(
            json!([
                {"Names": ["/shop-web-1"], "Image": "nginx:1.27", "ImageID": ID,
                 "Labels": {"com.docker.compose.service": "web"}},
                {"Names": ["/pg"], "Image": "ghcr.io/acme/db:16", "ImageID": D2,
                 "Labels": {"heimdall.service": "billing-db", "com.docker.compose.service": "db"}},
                {"Names": ["/local"], "Image": "mytool:dev", "ImageID": D1, "Labels": {}}
            ]),
            json!({
                ID: {"RepoDigests": [format!("nginx@{D1}")], "RepoTags": ["nginx:1.27"]},
                D2: {"RepoDigests": [format!("ghcr.io/acme/db@{D2}")], "RepoTags": []},
                D1: {"RepoDigests": [], "RepoTags": ["mytool:dev"]}
            }),
        );
        let inv = build_inventory("prod", None, &o);
        // The engine ID, not the name: stable across renames, unique per daemon.
        assert_eq!(inv.origin.as_deref(), Some("docker:ENGINE-A"));
        let names: Vec<&str> = inv.services.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["vm1", "vm1/billing-db", "vm1/local", "vm1/web"]);
        let get = |n: &str| &inv.services.iter().find(|s| s.name == n).unwrap().items[0];
        let web = get("vm1/web");
        assert_eq!(
            web.purl,
            "pkg:oci/nginx@sha256%3A1111111111111111111111111111111111111111111111111111111111111111\
             ?repository_url=docker.io/library/nginx&tag=1.27"
        );
        assert_eq!(web.via_image_digest.as_deref(), Some(D1));
        assert!(get("vm1/billing-db")
            .purl
            .contains("repository_url=ghcr.io/acme/db"));
        // Built locally: no registry digest, so it is never queued for a scan.
        assert_eq!(get("vm1/local").via_image_digest, None);
        assert_eq!(get("vm1").purl, "pkg:generic/ubuntu@24.04.1");
    }

    #[test]
    fn a_name_overrides_the_docker_host_name() {
        let o = objs(json!([]), json!({}));
        let inv = build_inventory("prod", Some("edge-1"), &o);
        assert_eq!(inv.origin.as_deref(), Some("docker:ENGINE-A"));
        assert_eq!(inv.services[0].name, "edge-1");
    }

    /// The whole client against a fake Docker API on a Unix socket.
    #[tokio::test]
    async fn scans_a_docker_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let replies: HashMap<String, Value> = HashMap::from([
            (
                "/info".to_string(),
                json!({"Name": "vm9", "OperatingSystem": "Debian GNU/Linux 12 (bookworm)"}),
            ),
            (
                "/containers/json".to_string(),
                json!([
                    {"Names": ["/app"], "Image": "redis:7", "ImageID": ID, "Labels": {}}
                ]),
            ),
            (
                format!("/images/{ID}/json"),
                json!({"RepoDigests": [format!("redis@{D1}")], "RepoTags": ["redis:7"]}),
            ),
        ]);
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let reply = match replies.get(&path) {
                    Some(v) => {
                        format!("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{v}")
                    }
                    None => "HTTP/1.0 404 Not Found\r\n\r\n{}".to_string(),
                };
                s.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let host: DockerHost = format!("unix://{}", sock.display()).parse().unwrap();
        let inv = scan(&host, "prod", None).await.unwrap();
        let names: Vec<&str> = inv.services.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["vm9", "vm9/app"]);
        assert_eq!(inv.services[0].items[0].purl, "pkg:generic/debian@12");
        assert_eq!(
            inv.services[1].items[0].via_image_digest.as_deref(),
            Some(D1)
        );
        let err = host.get::<Value>("/nope").await.unwrap_err();
        assert!(err.downcast_ref::<NotFound>().is_some(), "{err:#}");
    }

    #[test]
    fn compose_projects_get_their_own_services() {
        let c = |project: &str| {
            json!({"Names": [format!("/{project}-web-1")], "Image": "nginx:1.27", "ImageID": ID,
                   "Labels": {"com.docker.compose.service": "web", "com.docker.compose.project": project}})
        };
        let o = objs(
            json!([c("shop"), c("blog")]),
            json!({ ID: {"RepoDigests": [], "RepoTags": []} }),
        );
        let names: Vec<String> = build_inventory("prod", None, &o)
            .services
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(names, ["vm1", "vm1/blog-web", "vm1/shop-web"]);
    }

    #[test]
    fn image_references_and_digests() {
        let img = |digests: Value, tags: Value| -> Image {
            serde_json::from_value(json!({"RepoDigests": digests, "RepoTags": tags})).unwrap()
        };
        let ctr = |image: &str| -> Container {
            serde_json::from_value(json!({"Names": ["/x"], "Image": image, "ImageID": ID})).unwrap()
        };
        // Started by a short id: named after the image's registry repository.
        let i = img(json!([format!("redis@{D1}")]), json!([]));
        let p = container_image(&ctr("999999999999"), Some(&i));
        assert_eq!(
            (p.image.as_str(), p.digest.as_str(), p.pullable),
            ("redis", D1, true)
        );
        // Pinned by digest with no RepoDigests: the pin is the manifest.
        let p = container_image(
            &ctr(&format!("redis@{D2}")),
            Some(&img(json!([]), json!([]))),
        );
        assert_eq!((p.digest.as_str(), p.pullable), (D2, true));
        // Another repository's digest is never borrowed.
        let i = img(json!([format!("other/repo@{D1}")]), json!(["redis:7"]));
        let p = container_image(&ctr("redis:7"), Some(&i));
        assert_eq!((p.digest.as_str(), p.pullable), (ID, false));
    }

    #[test]
    fn hosts_with_one_name_have_different_origins() {
        let mut a = objs(json!([]), json!({}));
        let mut b = objs(json!([]), json!({}));
        a.info.id = "ENGINE-A".into();
        b.info.id = "ENGINE-B".into();
        assert_ne!(
            build_inventory("prod", None, &a).origin,
            build_inventory("prod", None, &b).origin
        );
    }

    /// A fake Docker API on a Unix socket answering `replies` by path (404
    /// for anything else, or `status` for an image path when set).
    async fn fake_docker(
        replies: HashMap<String, Value>,
        image_status: Option<&'static str>,
    ) -> (tempfile::TempDir, DockerHost) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("docker.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 4096];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = req
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let reply = match (replies.get(&path), image_status) {
                    (_, Some(st)) if path.starts_with("/images/") => {
                        format!("HTTP/1.0 {st}\r\n\r\n{{}}")
                    }
                    (Some(v), _) => format!("HTTP/1.0 200 OK\r\n\r\n{v}"),
                    (None, _) => "HTTP/1.0 404 Not Found\r\n\r\n{}".to_string(),
                };
                s.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let host = format!("unix://{}", sock.display()).parse().unwrap();
        (dir, host)
    }

    /// An image removed since its container started (404) is reported
    /// without its digest; any other inspect failure fails the scan.
    #[tokio::test]
    async fn image_inspect_errors_fail_the_scan_but_404_does_not() {
        let replies = HashMap::from([
            ("/info".to_string(), json!({"ID": "E", "Name": "vm9"})),
            (
                "/containers/json".to_string(),
                json!([{"Names": ["/app"], "Image": "redis:7", "ImageID": ID}]),
            ),
        ]);
        let (_d, gone) = fake_docker(replies.clone(), Some("404 Not Found")).await;
        let inv = scan(&gone, "prod", None).await.unwrap();
        assert_eq!(inv.services[0].items[0].via_image_digest, None);
        let (_d, broken) = fake_docker(replies, Some("500 Internal Server Error")).await;
        let err = scan(&broken, "prod", None).await.unwrap_err();
        assert!(format!("{err:#}").contains("500"), "{err:#}");
    }

    #[tokio::test]
    async fn paths_with_spaces_or_line_breaks_are_refused() {
        let (_d, host) = fake_docker(HashMap::new(), None).await;
        let err = host
            .get::<Value>("/info HTTP/1.0\r\nX: y")
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("unexpected"), "{err:#}");
    }
}
