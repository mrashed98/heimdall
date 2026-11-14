//! Sight: reads the cluster through the Kubernetes API (list only, never
//! Secrets, see ADR 0003) and turns it into a `ClusterInventory`.
//!
//! RBAC needed: `get,list` on pods, nodes, deployments, statefulsets,
//! daemonsets, replicasets and `applications.argoproj.io`. Nothing else.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::Context;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::core::v1::{Container, ContainerStatus, Node, Pod};
use k8s_openapi::apimachinery::pkg::version::Info;
use kube::api::{ApiResource, DynamicObject, GroupVersionKind, ListParams};
use kube::{Api, Client as KubeClient};
use regex::Regex;

use crate::client::Client;
use crate::ingest::api::{
    ingest_cluster_inner, ApiError, ClusterInventory, ClusterItem, ClusterOutcome, ClusterService,
};
use crate::AppState;

/// Everything Sight read from the cluster, untouched.
pub struct ClusterObjects {
    pub pods: Vec<Pod>,
    /// Deployments, StatefulSets and DaemonSets.
    pub workloads: Vec<DynamicObject>,
    pub nodes: Vec<Node>,
    pub argo_apps: Vec<DynamicObject>,
    pub server_version: Info,
}

const SERVICE_ANNOTATION: &str = "heimdall.io/service";
const NAME_LABEL: &str = "app.kubernetes.io/name";
const CHART_LABEL: &str = "helm.sh/chart";

/// List everything Sight needs, across all namespaces. Read-only; Secrets are
/// never requested. A cluster without the ArgoCD CRD (404) has no apps.
pub async fn collect(client: KubeClient) -> anyhow::Result<ClusterObjects> {
    let lp = ListParams::default();
    let pods = Api::<Pod>::all(client.clone())
        .list(&lp)
        .await
        .context("listing pods")?
        .items;
    let nodes = Api::<Node>::all(client.clone())
        .list(&lp)
        .await
        .context("listing nodes")?
        .items;

    let mut workloads = Vec::new();
    let resources = [
        ApiResource::erase::<Deployment>(&()),
        ApiResource::erase::<StatefulSet>(&()),
        ApiResource::erase::<DaemonSet>(&()),
    ];
    for res in resources {
        let api: Api<DynamicObject> = Api::all_with(client.clone(), &res);
        let list = api
            .list(&lp)
            .await
            .with_context(|| format!("listing {}", res.plural))?;
        // List items of built-in types carry no apiVersion/kind, so record
        // the kind here (the pods-to-workload join needs it).
        for mut obj in list.items {
            obj.types = Some(kube::api::TypeMeta {
                api_version: res.api_version.clone(),
                kind: res.kind.clone(),
            });
            workloads.push(obj);
        }
    }

    let argo = ApiResource::from_gvk(&GroupVersionKind::gvk(
        "argoproj.io",
        "v1alpha1",
        "Application",
    ));
    let argo_apps = match Api::<DynamicObject>::all_with(client.clone(), &argo)
        .list(&lp)
        .await
    {
        Ok(list) => list.items,
        // No ArgoCD installed: the CRD does not exist.
        Err(kube::Error::Api(status)) if status.code == 404 => Vec::new(),
        Err(e) => return Err(e).context("listing ArgoCD applications"),
    };

    let server_version = client
        .apiserver_version()
        .await
        .context("reading the server version")?;
    Ok(ClusterObjects {
        pods,
        workloads,
        nodes,
        argo_apps,
        server_version,
    })
}

/// Scan the cluster and ingest in-process (no `push`) or POST the same JSON
/// to a remote Bifröst (scout mode, `HEIMDALL_API_KEY` for auth).
pub async fn run(
    state: Option<&AppState>,
    realm: &str,
    push: Option<&str>,
) -> anyhow::Result<ClusterOutcome> {
    let kube = KubeClient::try_default()
        .await
        .context("connecting to the cluster")?;
    let objs = collect(kube).await?;
    let inv = build_inventory(realm, &objs);
    match (push, state) {
        (Some(url), _) => {
            let key = std::env::var("HEIMDALL_API_KEY").context("HEIMDALL_API_KEY is not set")?;
            let client = Client::new(url, key);
            let r: serde_json::Value = client.post_json("/api/v1/ingest/cluster", &inv).await?;
            let n = |k: &str| r[k].as_u64().unwrap_or(0) as usize;
            Ok(ClusterOutcome {
                services: n("services"),
                added: n("added"),
                removed: n("removed"),
            })
        }
        (None, Some(state)) => ingest_cluster_inner(state, &inv)
            .await
            .map_err(|e| match e {
                ApiError::BadRequest(m) => anyhow::anyhow!(m),
                ApiError::Internal(e) => e,
                other => anyhow::anyhow!("ingest failed: {other:?}"),
            }),
        (None, None) => anyhow::bail!("in-process ingest needs the application state"),
    }
}

/// Pure: turn what was read from the cluster into services and components.
pub fn build_inventory(realm: &str, objs: &ClusterObjects) -> ClusterInventory {
    let mut services = Services::default();

    // (kind, namespace, workload name) -> service name, as chosen by its pods,
    // so a workload's chart lands on the same service as its images.
    let mut workload_service: HashMap<(String, String, String), String> = HashMap::new();
    for pod in &objs.pods {
        let name = pod_service_name(pod);
        if let Some((kind, owner)) = pod_workload(pod) {
            let ns = pod.metadata.namespace.clone().unwrap_or_default();
            workload_service
                .entry((kind, ns, owner))
                .or_insert_with(|| name.clone());
        }
        for img in pod_images(pod) {
            services.add(&name, image_item(&img));
        }
    }

    for w in &objs.workloads {
        let Some(label) = w.metadata.labels.as_ref().and_then(|l| l.get(CHART_LABEL)) else {
            continue;
        };
        let Some((chart, version)) = split_chart_label(label) else {
            continue;
        };
        let kind = w.types.as_ref().map(|t| t.kind.clone()).unwrap_or_default();
        let wname = w.metadata.name.clone().unwrap_or_default();
        let ns = w.metadata.namespace.clone().unwrap_or_default();
        let service = workload_service
            .get(&(kind, ns, wname.clone()))
            .cloned()
            .unwrap_or_else(|| meta_service_name(&w.metadata).unwrap_or(wname));
        services.add(&service, item(format!("pkg:helm/{chart}@{version}"), None));
    }

    for app in &objs.argo_apps {
        let Some(name) = app.metadata.name.as_deref() else {
            continue;
        };
        let spec = &app.data["spec"];
        let mut sources: Vec<&serde_json::Value> = Vec::new();
        if spec["source"].is_object() {
            sources.push(&spec["source"]);
        }
        if let Some(many) = spec["sources"].as_array() {
            sources.extend(many);
        }
        for src in sources {
            let (Some(chart), Some(rev)) = (src["chart"].as_str(), src["targetRevision"].as_str())
            else {
                continue;
            };
            let mut purl = format!("pkg:helm/{chart}@{rev}");
            if let Some(repo) = src["repoURL"].as_str().filter(|r| !r.is_empty()) {
                purl.push_str(&format!("?repository_url={}", encode_qualifier(repo)));
            }
            services.add(name, item(purl, None));
        }
    }

    for purl in cluster_version_purls(&objs.server_version, &objs.nodes) {
        services.add("cluster", item(purl, None));
    }

    ClusterInventory {
        realm: realm.to_string(),
        services: services.finish(),
    }
}

/// Services by name with their items, de-duplicated by purl.
#[derive(Default)]
struct Services {
    by_name: BTreeMap<String, (Vec<ClusterItem>, HashSet<String>)>,
}

impl Services {
    fn add(&mut self, service: &str, it: ClusterItem) {
        let (items, seen) = self.by_name.entry(service.to_string()).or_default();
        if seen.insert(it.purl.clone()) {
            items.push(it);
        }
    }

    fn finish(self) -> Vec<ClusterService> {
        self.by_name
            .into_iter()
            .map(|(name, (items, _))| ClusterService { name, items })
            .collect()
    }
}

fn item(purl: String, via_image_digest: Option<String>) -> ClusterItem {
    ClusterItem {
        purl,
        cpes: Vec::new(),
        direct: true,
        via_image_digest,
    }
}

/// Annotation `heimdall.io/service`, then label `app.kubernetes.io/name`.
fn meta_service_name(
    meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> Option<String> {
    let from = |m: &Option<BTreeMap<String, String>>, key: &str| {
        m.as_ref()
            .and_then(|m| m.get(key))
            .filter(|v| !v.is_empty())
            .cloned()
    };
    from(&meta.annotations, SERVICE_ANNOTATION).or_else(|| from(&meta.labels, NAME_LABEL))
}

/// Annotation, label, owner workload name, pod name (in that order).
fn pod_service_name(pod: &Pod) -> String {
    meta_service_name(&pod.metadata)
        .or_else(|| pod_workload(pod).map(|(_, name)| name))
        .or_else(|| pod.metadata.name.clone())
        .unwrap_or_default()
}

/// The workload a pod belongs to, as (kind, name). A ReplicaSet maps to its
/// Deployment by dropping the `-<pod-template-hash>` suffix.
fn pod_workload(pod: &Pod) -> Option<(String, String)> {
    let owner = pod.metadata.owner_references.as_ref()?.first()?;
    if owner.kind == "Job" {
        // CronJob runs are named `<cronjob>-<timestamp>`; the service is the
        // CronJob, or every run would be a new service.
        let name = match owner.name.rsplit_once('-') {
            Some((base, n)) if !base.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) => base,
            _ => owner.name.as_str(),
        };
        return Some(("Job".to_string(), name.to_string()));
    }
    if owner.kind != "ReplicaSet" {
        return Some((owner.kind.clone(), owner.name.clone()));
    }
    let hash = pod
        .metadata
        .labels
        .as_ref()
        .and_then(|l| l.get("pod-template-hash"));
    let name = match hash.and_then(|h| owner.name.strip_suffix(&format!("-{h}"))) {
        Some(stripped) => stripped,
        // No usable hash label: drop the last `-segment`.
        None => owner
            .name
            .rsplit_once('-')
            .map_or(owner.name.as_str(), |(n, _)| n),
    };
    Some(("Deployment".to_string(), name.to_string()))
}

/// A container image as Sight reports it.
struct PodImage {
    /// The image field from the spec (it has the tag).
    image: String,
    digest: String,
    /// The digest names a manifest, so `repo@digest` can be pulled and
    /// scanned. A bare `sha256:...` imageID is the image's config id on some
    /// runtimes: nothing can be pulled by it.
    pullable: bool,
}

/// Every container image with a known digest, init containers included.
fn pod_images(pod: &Pod) -> Vec<PodImage> {
    let Some(spec) = &pod.spec else {
        return Vec::new();
    };
    let Some(status) = &pod.status else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let pairs: [(&[Container], &Option<Vec<ContainerStatus>>); 2] = [
        (
            spec.init_containers.as_deref().unwrap_or_default(),
            &status.init_container_statuses,
        ),
        (&spec.containers, &status.container_statuses),
    ];
    for (containers, statuses) in pairs {
        for st in statuses.as_deref().unwrap_or_default() {
            // The tag only exists in the spec's `image`, matched by name.
            let image = containers
                .iter()
                .find(|c| c.name == st.name)
                .and_then(|c| c.image.clone())
                .unwrap_or_else(|| st.image.clone());
            // `repo@sha256:...` (any prefix) is a manifest digest; so is a
            // digest pinned in the spec's image.
            let manifest = if st.image_id.contains('@') {
                digest_of(&st.image_id)
            } else {
                None
            };
            let found = match manifest.or_else(|| digest_of(&image)) {
                Some(d) => Some((d, true)),
                None => digest_of(&st.image_id).map(|d| (d, false)),
            };
            if let Some((digest, pullable)) = found {
                out.push(PodImage {
                    image,
                    digest,
                    pullable,
                });
            }
        }
    }
    out
}

/// `sha256:<64 hex>` anywhere in `s` (imageID comes in several shapes).
fn digest_of(s: &str) -> Option<String> {
    let start = s.find("sha256:")?;
    let hex = s.get(start + 7..start + 7 + 64)?;
    hex.bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| format!("sha256:{hex}"))
}

/// Split an image reference into (registry, repository path, tag).
/// Docker Hub short names become `docker.io/library/<name>`.
fn parse_image(image: &str) -> (String, String, Option<String>) {
    let no_digest = image.split('@').next().unwrap_or(image);
    let (registry, rest) = match no_digest.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            (first.to_string(), rest)
        }
        _ => ("docker.io".to_string(), no_digest),
    };
    // A colon in the last path segment is the tag (earlier ones are ports).
    let (repo, tag) = match rest.rsplit_once(':') {
        Some((repo, tag)) if !tag.contains('/') => (repo, Some(tag.to_string())),
        _ => (rest, None),
    };
    let registry = if registry == "index.docker.io" {
        "docker.io".to_string()
    } else {
        registry
    };
    let repo = if registry == "docker.io" && !repo.contains('/') {
        format!("library/{repo}")
    } else {
        repo.to_string()
    };
    (registry, repo, tag)
}

fn image_item(img: &PodImage) -> ClusterItem {
    let digest = &img.digest;
    let (registry, repo, tag) = parse_image(&img.image);
    let last = repo.rsplit('/').next().unwrap_or(&repo);
    // purl wants the `:` in the version encoded.
    let mut purl = format!(
        "pkg:oci/{last}@{}?repository_url={registry}/{repo}",
        digest.replace(':', "%3A")
    );
    if let Some(tag) = tag {
        purl.push_str(&format!("&tag={tag}"));
    }
    // Only a pullable digest is queued for scanning.
    item(purl, img.pullable.then(|| digest.clone()))
}

/// `kube-prometheus-stack-65.1.0` -> (`kube-prometheus-stack`, `65.1.0`).
/// Splits at the last `-` followed by a digit. Helm writes `+` as `_` in labels.
fn split_chart_label(label: &str) -> Option<(String, String)> {
    let bytes = label.as_bytes();
    let idx = (1..bytes.len())
        .rev()
        .find(|&i| bytes[i - 1] == b'-' && bytes[i].is_ascii_digit())?;
    let (name, version) = (&label[..idx - 1], &label[idx..]);
    (!name.is_empty()).then(|| (name.to_string(), version.replace('_', "+")))
}

/// Percent-encode a qualifier value, keeping `/` and `:` readable.
fn encode_qualifier(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~/:".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Kubernetes, k3s and node OS purls for the synthetic `cluster` service.
fn cluster_version_purls(version: &Info, nodes: &[Node]) -> Vec<String> {
    let mut out = Vec::new();
    let git = version.git_version.trim();
    if !git.is_empty() {
        let semver = git
            .trim_start_matches('v')
            .split(['+', '-'])
            .next()
            .unwrap_or_default();
        if !semver.is_empty() {
            out.push(format!("pkg:generic/kubernetes@{semver}"));
        }
        if git.contains("+k3s") {
            out.push(format!("pkg:generic/k3s@{git}"));
        }
    }
    let number = Regex::new(r"\d+(\.\d+)*").expect("static regex");
    for node in nodes {
        let Some(os) = node.status.as_ref().and_then(|s| s.node_info.as_ref()) else {
            continue;
        };
        let image = os.os_image.trim();
        let distro = if image.starts_with("Ubuntu") {
            "ubuntu"
        } else if image.starts_with("Debian") {
            "debian"
        } else {
            continue;
        };
        if let Some(m) = number.find(image) {
            out.push(format!("pkg:generic/{distro}@{}", m.as_str()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::api::{ClusterItem, ClusterService};

    fn items_of<T: serde::de::DeserializeOwned>(json: &str) -> Vec<T> {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        serde_json::from_value(v["items"].clone()).unwrap()
    }

    /// Like `collect`: list items have no kind, so it is set from the list.
    fn workloads() -> Vec<DynamicObject> {
        let v: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/k8s/deployments.json"))
                .unwrap();
        v["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| {
                let mut o: DynamicObject = serde_json::from_value(i["obj"].clone()).unwrap();
                o.types = Some(kube::api::TypeMeta {
                    api_version: "apps/v1".into(),
                    kind: i["kind"].as_str().unwrap().into(),
                });
                o
            })
            .collect()
    }

    fn fixture() -> ClusterObjects {
        ClusterObjects {
            pods: items_of(include_str!("../../tests/fixtures/k8s/pods.json")),
            workloads: workloads(),
            nodes: items_of(include_str!("../../tests/fixtures/k8s/nodes.json")),
            argo_apps: items_of(include_str!("../../tests/fixtures/k8s/argo_apps.json")),
            server_version: serde_json::from_str(include_str!(
                "../../tests/fixtures/k8s/version.json"
            ))
            .unwrap(),
        }
    }

    fn svc<'a>(inv: &'a ClusterInventory, name: &str) -> &'a ClusterService {
        inv.services
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("no service {name}"))
    }

    fn purls(s: &ClusterService) -> Vec<&str> {
        s.items.iter().map(|i| i.purl.as_str()).collect()
    }

    fn pod_json(extra_meta: &str) -> serde_json::Value {
        serde_json::from_str(&format!(
            r#"{{"metadata":{{"name":"p-1"{extra_meta}}},"spec":{{"containers":[]}}}}"#
        ))
        .unwrap()
    }

    #[test]
    fn service_name_precedence() {
        let inv = build_inventory("prod", &fixture());
        // annotation beats label and Deployment name
        assert!(inv.services.iter().any(|s| s.name == "web-annotated"));
        assert!(!inv.services.iter().any(|s| s.name == "web-label"));
        // label beats the StatefulSet name
        assert!(inv.services.iter().any(|s| s.name == "db"));
        // ReplicaSet api-gateway-5c8d7f9b6 -> Deployment api-gateway
        assert!(inv.services.iter().any(|s| s.name == "api-gateway"));
        // nothing else: the pod name
        assert!(inv.services.iter().any(|s| s.name == "standalone"));
    }

    #[test]
    fn statefulset_owner_and_pod_name_fallback() {
        let mut v = pod_json(
            r#","ownerReferences":[{"apiVersion":"apps/v1","kind":"StatefulSet","name":"kafka","uid":"u"}]"#,
        );
        v["spec"]["containers"] = serde_json::json!([{"name":"c","image":"kafka:3"}]);
        v["status"] = serde_json::json!({"containerStatuses":[{"name":"c","image":"kafka:3",
            "imageID":"docker.io/library/kafka@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "ready":true,"restartCount":0}]});
        let mut objs = fixture();
        objs.pods = vec![serde_json::from_value(v).unwrap()];
        let inv = build_inventory("prod", &objs);
        assert!(inv.services.iter().any(|s| s.name == "kafka"));
    }

    #[test]
    fn cronjob_pod_service_is_cronjob_name() {
        let mut v = pod_json(
            r#","ownerReferences":[{"apiVersion":"batch/v1","kind":"Job","name":"scan-images-29012345","uid":"u"}]"#,
        );
        v["spec"]["containers"] = serde_json::json!([{"name":"c","image":"x:1"}]);
        v["status"] = serde_json::json!({"containerStatuses":[{"name":"c","image":"x:1",
            "imageID":"docker.io/library/x@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "ready":true,"restartCount":0}]});
        let mut objs = fixture();
        objs.pods = vec![serde_json::from_value(v).unwrap()];
        let inv = build_inventory("prod", &objs);
        assert!(inv.services.iter().any(|s| s.name == "scan-images"));
    }

    #[test]
    fn image_digest_and_tag_extracted() {
        let inv = build_inventory("prod", &fixture());
        let db = svc(&inv, "db");
        let digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        let item = db
            .items
            .iter()
            .find(|i| i.purl.starts_with("pkg:oci/postgres@"))
            .expect("postgres image");
        assert_eq!(
            item.purl,
            format!(
                "pkg:oci/postgres@sha256%3A{}?repository_url=docker.io/library/postgres&tag=16.4-alpine",
                &digest[7..]
            )
        );
        assert_eq!(item.via_image_digest.as_deref(), Some(digest));
        assert!(item.direct);
        assert!(item.cpes.is_empty());
        // init container too, Docker Hub short name normalised
        assert!(purls(db).iter().any(|p| p.starts_with("pkg:oci/busybox@")
            && p.ends_with("?repository_url=docker.io/library/busybox&tag=1.36")));
    }

    #[test]
    fn bare_config_id_is_not_a_scannable_digest() {
        // Some runtimes report only the image's config id as imageID. It is
        // no manifest digest: `repo@<it>` cannot be pulled, so it must not
        // be queued for scanning.
        let mut v = pod_json("");
        v["spec"]["containers"] = serde_json::json!([{"name":"c","image":"ghcr.io/o/app:2"}]);
        v["status"] = serde_json::json!({"containerStatuses":[{"name":"c","image":"ghcr.io/o/app:2",
            "imageID":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "ready":true,"restartCount":0}]});
        let mut objs = fixture();
        objs.pods = vec![serde_json::from_value(v).unwrap()];
        let inv = build_inventory("prod", &objs);
        let item = svc(&inv, "p-1")
            .items
            .iter()
            .find(|i| i.purl.starts_with("pkg:oci/app@"))
            .expect("the image is still in the inventory");
        assert_eq!(item.via_image_digest, None);
    }

    #[test]
    fn image_without_tag_and_with_registry_port() {
        let inv = build_inventory("prod", &fixture());
        let api = svc(&inv, "api-gateway");
        assert_eq!(api.items.len(), 1);
        assert_eq!(
            api.items[0].purl,
            "pkg:oci/api@sha256%3A4444444444444444444444444444444444444444444444444444444444444444?repository_url=registry.example.com:5000/team/api"
        );
        let sa = svc(&inv, "standalone");
        assert!(sa.items[0]
            .purl
            .ends_with("?repository_url=docker.io/library/nginx"));
    }

    #[test]
    fn helm_chart_label_parsed() {
        let inv = build_inventory("prod", &fixture());
        // workload without pods: service named after the workload
        let mon = svc(&inv, "monitoring-operator");
        assert_eq!(purls(mon), vec!["pkg:helm/kube-prometheus-stack@65.1.0"]);
        // workload with pods: attached to the pods' service
        assert!(purls(svc(&inv, "web-annotated")).contains(&"pkg:helm/web@0.3.1"));
        assert!(purls(svc(&inv, "db")).contains(&"pkg:helm/postgresql@15.5.38"));
    }

    #[test]
    fn argo_application_chart() {
        let inv = build_inventory("prod", &fixture());
        let cm = svc(&inv, "cert-manager");
        assert_eq!(
            purls(cm),
            vec!["pkg:helm/cert-manager@v1.16.1?repository_url=https://charts.jetstack.io"]
        );
        // git-sourced apps have no chart
        assert!(!inv.services.iter().any(|s| s.name == "plain-git"));
    }

    #[test]
    fn k3s_version_yields_both() {
        let inv = build_inventory("prod", &fixture());
        let c = svc(&inv, "cluster");
        let p = purls(c);
        assert!(p.contains(&"pkg:generic/k3s@v1.31.4+k3s1"));
        assert!(p.contains(&"pkg:generic/kubernetes@1.31.4"));
    }

    #[test]
    fn plain_kubernetes_version() {
        let mut objs = fixture();
        objs.server_version.git_version = "v1.30.2".into();
        let inv = build_inventory("prod", &objs);
        let p = purls(svc(&inv, "cluster"));
        assert!(p.contains(&"pkg:generic/kubernetes@1.30.2"));
        assert!(!p.iter().any(|x| x.contains("k3s")));
    }

    #[test]
    fn ubuntu_node_os() {
        let inv = build_inventory("prod", &fixture());
        let p = purls(svc(&inv, "cluster"));
        // two Ubuntu nodes, one item
        assert_eq!(
            p.iter()
                .filter(|x| **x == "pkg:generic/ubuntu@24.04.1")
                .count(),
            1
        );
        assert!(p.contains(&"pkg:generic/debian@12"));
    }

    #[test]
    fn same_image_in_two_pods_one_item_per_service() {
        let inv = build_inventory("prod", &fixture());
        // two api-gateway pods run the same image
        assert_eq!(svc(&inv, "api-gateway").items.len(), 1);
        assert!(inv.services.iter().all(|s| {
            let mut seen = std::collections::HashSet::new();
            s.items
                .iter()
                .all(|i: &ClusterItem| seen.insert(i.purl.clone()))
        }));
    }

    #[test]
    fn image_purls_parse() {
        let inv = build_inventory("prod", &fixture());
        for s in &inv.services {
            for i in &s.items {
                assert!(
                    <packageurl::PackageUrl as std::str::FromStr>::from_str(&i.purl).is_ok(),
                    "{}",
                    i.purl
                );
            }
        }
    }
}
