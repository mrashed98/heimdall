//! Helpers for package URLs (purls): identity keys and OSV package mapping.

use std::str::FromStr;

use anyhow::Context;
use packageurl::PackageUrl;

/// A package as OSV names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsvPackage {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

/// The purl without version, qualifiers and subpath, e.g. `pkg:npm/%40scope/lib`.
/// This is the identity used for oaths, direct flags and watcher matching.
/// We cut the string instead of re-rendering the parsed purl so the original
/// percent-encoding is kept exactly as written.
pub fn name_key(purl: &str) -> anyhow::Result<String> {
    PackageUrl::from_str(purl).with_context(|| format!("invalid purl {purl}"))?;
    let no_extras = purl.split(['?', '#']).next().unwrap_or(purl);
    // A version is introduced by the last '@' after the last '/'. Scoped npm
    // names carry '@' as %40, so they are not confused with a version.
    let last_slash = no_extras.rfind('/').unwrap_or(0);
    let key = match no_extras[last_slash..].find('@') {
        Some(at) => &no_extras[..last_slash + at],
        None => no_extras,
    };
    Ok(key.to_string())
}

/// Map a purl to the OSV ecosystem/name/version triple, or None when OSV has
/// no matching ecosystem (oci, generic, ...).
pub fn osv_package(purl: &str) -> Option<OsvPackage> {
    let p = PackageUrl::from_str(purl).ok()?;
    let version = p.version()?.to_string();
    // purl namespace is already percent-decoded by the parser.
    let joined = |ns: Option<&str>, name: &str| match ns {
        Some(ns) => format!("{ns}/{name}"),
        None => name.to_string(),
    };
    let (ecosystem, name) = match p.ty() {
        "golang" => ("Go".to_string(), joined(p.namespace(), p.name())),
        "npm" => ("npm".to_string(), joined(p.namespace(), p.name())),
        "pypi" => (
            "PyPI".to_string(),
            p.name().to_lowercase().replace('_', "-"),
        ),
        "cargo" => ("crates.io".to_string(), p.name().to_string()),
        "gem" => ("RubyGems".to_string(), p.name().to_string()),
        "nuget" => ("NuGet".to_string(), p.name().to_string()),
        "maven" => (
            "Maven".to_string(),
            format!("{}:{}", p.namespace()?, p.name()),
        ),
        "deb" => {
            let distro = p.qualifiers().get("distro").map(|d| d.as_ref());
            let ecosystem = deb_ecosystem(p.namespace()?, distro)?;
            // OSV tracks Debian/Ubuntu advisories by *source* package. SBOM
            // tools write it as `upstream=openssl` or `upstream=openssl (3.0.11)`.
            let name = match p.qualifiers().get("upstream").map(|u| u.as_ref()) {
                Some(up) => up.split(" (").next().unwrap_or(up).trim().to_string(),
                None => p.name().to_string(),
            };
            (ecosystem, name)
        }
        _ => return None,
    };
    Some(OsvPackage {
        ecosystem,
        name,
        version,
    })
}

/// `debian-12` -> `Debian:12`; `ubuntu-24.04` -> `Ubuntu:24.04:LTS`.
fn deb_ecosystem(namespace: &str, distro: Option<&str>) -> Option<String> {
    let release = distro.and_then(|d| d.split_once('-')).map(|(_, r)| r);
    match namespace {
        "debian" => Some(match release {
            Some(r) => format!("Debian:{r}"),
            None => "Debian".to_string(),
        }),
        "ubuntu" => {
            let r = release?;
            // LTS releases are the `.04` ones in even years (20.04, 22.04, 24.04).
            let (year, month) = r.split_once('.')?;
            let lts = month == "04" && year.parse::<u32>().ok()? % 2 == 0;
            Some(if lts {
                format!("Ubuntu:{r}:LTS")
            } else {
                format!("Ubuntu:{r}")
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn go_maps_to_osv() {
        let p = osv_package("pkg:golang/github.com/gin-gonic/gin@v1.9.0").unwrap();
        assert_eq!(
            (p.ecosystem.as_str(), p.name.as_str(), p.version.as_str()),
            ("Go", "github.com/gin-gonic/gin", "v1.9.0")
        );
    }
    #[test]
    fn scoped_npm_maps_to_osv() {
        let p = osv_package("pkg:npm/%40vue/core@3.4.0").unwrap();
        assert_eq!(
            (p.ecosystem.as_str(), p.name.as_str()),
            ("npm", "@vue/core")
        );
    }
    #[test]
    fn debian_uses_upstream_source_name_and_release() {
        let p = osv_package(
            "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&upstream=openssl&distro=debian-12",
        )
        .unwrap();
        assert_eq!(
            (p.ecosystem.as_str(), p.name.as_str(), p.version.as_str()),
            ("Debian:12", "openssl", "3.0.11-1~deb12u2")
        );
    }
    #[test]
    fn debian_upstream_with_parenthesised_version_is_stripped() {
        let p = osv_package(
            "pkg:deb/debian/libssl3@3.0.11-1~deb12u2?upstream=openssl%20(3.0.11)&distro=debian-12",
        )
        .unwrap();
        assert_eq!(p.name, "openssl");
    }
    #[test]
    fn ubuntu_lts_maps() {
        let p =
            osv_package("pkg:deb/ubuntu/libc6@2.39-0ubuntu8?upstream=glibc&distro=ubuntu-24.04")
                .unwrap();
        assert_eq!(
            (p.ecosystem.as_str(), p.name.as_str()),
            ("Ubuntu:24.04:LTS", "glibc")
        );
    }
    #[test]
    fn ubuntu_non_lts_has_no_suffix() {
        let p = osv_package("pkg:deb/ubuntu/libc6@2.39-0ubuntu8?distro=ubuntu-23.10").unwrap();
        assert_eq!(p.ecosystem, "Ubuntu:23.10");
    }
    #[test]
    fn oci_and_generic_are_not_osv() {
        assert!(osv_package(
            "pkg:oci/postgres@sha256:abc?repository_url=docker.io/library/postgres"
        )
        .is_none());
        assert!(osv_package("pkg:generic/kubernetes@1.31.2").is_none());
    }
    #[test]
    fn name_key_strips_version_and_qualifiers() {
        assert_eq!(
            name_key("pkg:npm/%40vue/core@3.4.0?foo=bar").unwrap(),
            "pkg:npm/%40vue/core"
        );
    }
    #[test]
    fn name_key_without_version_is_unchanged_and_garbage_errors() {
        assert_eq!(
            name_key("pkg:generic/kubernetes").unwrap(),
            "pkg:generic/kubernetes"
        );
        assert!(name_key("not a purl").is_err());
    }
}
