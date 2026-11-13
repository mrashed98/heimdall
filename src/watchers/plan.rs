//! The target list: what the inventory and config say we watch.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::str::FromStr;

use packageurl::PackageUrl;

use super::{Origin, Planned, Running, WatchKind, WatchTarget};
use crate::config::HeimdallConfig;
use crate::inventory::store::EffectiveComponent;
use crate::version::{compare, parse_tag};

/// Inventory-derived targets (merged across realms, keeping the lowest
/// running version) followed by the configured ones.
pub(super) fn plan(cfg: &HeimdallConfig, running: &[Running]) -> Vec<Planned> {
    let mut derived: BTreeMap<String, Planned> = BTreeMap::new();
    for (realm, c) in running {
        let Some(p) = inventory_target(cfg, realm, c) else {
            continue;
        };
        match derived.get_mut(&p.target.name) {
            Some(existing) if !is_lower(&p, existing) => {}
            Some(existing) => *existing = p,
            None => {
                derived.insert(p.target.name.clone(), p);
            }
        }
    }
    let mut out: Vec<Planned> = derived.into_values().collect();

    for g in &cfg.watchers.github {
        let (current, realm) = lowest_generic(running, &g.inventory_name);
        out.push(Planned {
            target: WatchTarget {
                name: g.inventory_name.clone(),
                kind: WatchKind::Github,
                current,
                major_component: g.major_component,
                repo: Some(g.repo.clone()),
                name_key: Some(generic_key(&g.inventory_name)),
            },
            origin: Origin::Github {
                repo: g.repo.clone(),
            },
            realm,
            track_releases: true,
        });
    }
    for e in &cfg.watchers.endoflife {
        let (current, realm) = lowest_generic(running, &e.inventory_name);
        let shadowed = cfg
            .watchers
            .github
            .iter()
            .any(|g| g.inventory_name == e.inventory_name);
        out.push(Planned {
            target: WatchTarget {
                name: e.inventory_name.clone(),
                kind: WatchKind::Endoflife,
                current,
                major_component: e.major_component,
                repo: e.repo.clone(),
                name_key: Some(generic_key(&e.inventory_name)),
            },
            origin: Origin::Endoflife {
                product: e.product.clone(),
            },
            realm,
            track_releases: !shadowed,
        });
    }
    for t in &cfg.watchers.tf_registry {
        out.push(Planned {
            target: WatchTarget {
                name: format!("{}/{}", t.registry, t.source),
                kind: WatchKind::TfRegistry,
                current: Some(t.current.clone()),
                major_component: 0,
                repo: None,
                name_key: None,
            },
            origin: Origin::Tf {
                registry: t.registry.clone(),
                kind: t.kind,
                source: t.source.clone(),
            },
            // Configured with no realm: filed under the first realm.
            realm: cfg.realms.first().cloned(),
            track_releases: true,
        });
    }
    out
}

fn generic_key(inventory_name: &str) -> String {
    format!("pkg:generic/{inventory_name}")
}

/// The target a running component stands for, if it is watched: images not
/// from our own registries, charts, and direct Go/npm libraries.
fn inventory_target(cfg: &HeimdallConfig, realm: &str, c: &EffectiveComponent) -> Option<Planned> {
    let purl = PackageUrl::from_str(&c.purl).ok()?;
    // The parser percent-decodes qualifier values and the namespace.
    let qualifier = |k: &str| purl.qualifiers().get(k).map(|v| v.to_string());
    let joined = || match purl.namespace() {
        Some(ns) => format!("{ns}/{}", purl.name()),
        None => purl.name().to_string(),
    };
    let (kind, name, current, origin) = match purl.ty() {
        "oci" => {
            let (host, repository) = image_ref(&qualifier("repository_url")?)?;
            let name = format!("{host}/{repository}");
            if is_own(cfg, &name) {
                return None;
            }
            // Only tags we can read as a version can be compared.
            let tag = qualifier("tag").filter(|t| parse_tag(t).is_some())?;
            (WatchKind::Oci, name, tag, Origin::Oci { host, repository })
        }
        "helm" => {
            let origin = Origin::Helm {
                repo_url: qualifier("repository_url")?,
                chart: purl.name().to_string(),
            };
            (
                WatchKind::Helm,
                c.name_key.clone(),
                purl.version()?.to_string(),
                origin,
            )
        }
        "golang" if c.direct => {
            let origin = Origin::GoProxy { module: joined() };
            (
                WatchKind::GoProxy,
                c.name_key.clone(),
                purl.version()?.to_string(),
                origin,
            )
        }
        "npm" if c.direct => {
            let origin = Origin::Npm { name: joined() };
            (
                WatchKind::Npm,
                c.name_key.clone(),
                purl.version()?.to_string(),
                origin,
            )
        }
        _ => return None,
    };
    Some(Planned {
        target: WatchTarget {
            name,
            kind,
            current: Some(current),
            major_component: 0,
            repo: None,
            name_key: Some(c.name_key.clone()),
        },
        origin,
        realm: Some(realm.to_string()),
        track_releases: true,
    })
}

/// `(host, repository)` of an image reference, Docker Hub short names
/// expanded: `postgres` -> `("docker.io", "library/postgres")`.
pub(super) fn image_ref(reference: &str) -> Option<(String, String)> {
    let r = reference.trim().trim_start_matches("oci://");
    let r = r.split('@').next()?;
    let (host, rest) = match r.split_once('/') {
        Some((first, rest)) if first.contains(['.', ':']) || first == "localhost" => (first, rest),
        _ => ("docker.io", r),
    };
    let host = match host {
        "index.docker.io" | "registry-1.docker.io" => "docker.io",
        h => h,
    };
    // Drop a `:tag` on the last segment (a `:` before a `/` is a port).
    let mut repository = match rest.rsplit_once(':') {
        Some((before, after)) if !after.contains('/') => before.to_string(),
        _ => rest.to_string(),
    };
    if host == "docker.io" && !repository.contains('/') {
        repository = format!("library/{repository}");
    }
    (!repository.is_empty()).then(|| (host.to_string(), repository))
}

/// True when `image` (`host/repo`) is under one of `own_registries`, given
/// as a host or a host/org prefix.
fn is_own(cfg: &HeimdallConfig, image: &str) -> bool {
    cfg.own_registries.iter().any(|own| {
        let own = own.trim_end_matches('/');
        image == own || image.starts_with(&format!("{own}/"))
    })
}

/// True when `a` runs an older version than `b` (same target).
fn is_lower(a: &Planned, b: &Planned) -> bool {
    match (&a.target.current, &b.target.current) {
        (Some(x), Some(y)) => compare(a.target.kind.ecosystem(), x, y) == Some(Ordering::Less),
        _ => false,
    }
}

/// The lowest version of `pkg:generic/{inventory_name}` running in any realm,
/// and that realm.
fn lowest_generic(running: &[Running], inventory_name: &str) -> (Option<String>, Option<String>) {
    let key = generic_key(inventory_name);
    let mut best: Option<(String, String)> = None;
    for (realm, c) in running.iter().filter(|(_, c)| c.name_key == key) {
        let Some(v) = purl_version(&c.purl) else {
            continue;
        };
        let lower = best
            .as_ref()
            .is_none_or(|(b, _)| compare("generic", &v, b) == Some(Ordering::Less));
        if lower {
            best = Some((v, realm.clone()));
        }
    }
    match best {
        Some((v, r)) => (Some(v), Some(r)),
        None => (None, None),
    }
}

pub(super) fn purl_version(purl: &str) -> Option<String> {
    Some(PackageUrl::from_str(purl).ok()?.version()?.to_string())
}
