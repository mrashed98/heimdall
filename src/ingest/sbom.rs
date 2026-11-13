//! CycloneDX JSON parsing. Only the few fields Heimdall needs are modelled.

use anyhow::{bail, Context};
use serde::Deserialize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbomComponent {
    pub purl: String,
    pub cpes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedSbom {
    pub components: Vec<SbomComponent>,
    pub skipped_without_purl: usize,
    pub image_digest: Option<String>,
}

#[derive(Deserialize)]
struct Bom {
    #[serde(rename = "bomFormat")]
    bom_format: Option<String>,
    metadata: Option<Metadata>,
    #[serde(default)]
    components: Vec<Component>,
}

#[derive(Deserialize)]
struct Metadata {
    component: Option<MetaComponent>,
}

#[derive(Deserialize)]
struct MetaComponent {
    #[serde(rename = "type")]
    kind: Option<String>,
    name: Option<String>,
    version: Option<String>,
    purl: Option<String>,
}

#[derive(Deserialize)]
struct Component {
    purl: Option<String>,
    cpe: Option<String>,
    #[serde(default)]
    properties: Vec<Property>,
    #[serde(default)]
    components: Vec<Component>,
}

#[derive(Deserialize)]
struct Property {
    name: Option<String>,
    value: Option<String>,
}

pub fn parse(bytes: &[u8]) -> anyhow::Result<ParsedSbom> {
    let bom: Bom = serde_json::from_slice(bytes).context("not valid CycloneDX JSON")?;
    if bom.bom_format.as_deref() != Some("CycloneDX") {
        bail!("bomFormat is not CycloneDX");
    }

    let mut components: Vec<SbomComponent> = Vec::new();
    let mut skipped = 0;
    collect(&bom.components, &mut components, &mut skipped);

    let image_digest = bom
        .metadata
        .and_then(|m| m.component)
        .and_then(|c| container_digest(&c));

    Ok(ParsedSbom {
        components,
        skipped_without_purl: skipped,
        image_digest,
    })
}

/// Walk components depth-first. Components with the same purl are merged
/// (their cpes are combined, keeping first-seen order).
fn collect(list: &[Component], out: &mut Vec<SbomComponent>, skipped: &mut usize) {
    for c in list {
        match c.purl.as_deref().filter(|p| !p.is_empty()) {
            None => *skipped += 1,
            Some(purl) => {
                let cpes = component_cpes(c);
                match out.iter_mut().find(|e| e.purl == purl) {
                    Some(existing) => {
                        for cpe in cpes {
                            if !existing.cpes.contains(&cpe) {
                                existing.cpes.push(cpe);
                            }
                        }
                    }
                    None => out.push(SbomComponent {
                        purl: purl.to_string(),
                        cpes,
                    }),
                }
            }
        }
        collect(&c.components, out, skipped);
    }
}

fn component_cpes(c: &Component) -> Vec<String> {
    let mut cpes: Vec<String> = Vec::new();
    let from_props = c
        .properties
        .iter()
        .filter(|p| {
            p.name
                .as_deref()
                .is_some_and(|n| n.starts_with("syft:cpe23"))
        })
        .filter_map(|p| p.value.clone());
    for cpe in c.cpe.iter().cloned().chain(from_props) {
        if !cpe.is_empty() && !cpes.contains(&cpe) {
            cpes.push(cpe);
        }
    }
    cpes
}

/// A `sha256:...` digest from a container's version, or from an `@sha256:`
/// suffix in its name or purl.
fn container_digest(c: &MetaComponent) -> Option<String> {
    if c.kind.as_deref() != Some("container") {
        return None;
    }
    if let Some(v) = c.version.as_deref().filter(|v| v.starts_with("sha256:")) {
        return Some(v.to_string());
    }
    [c.name.as_deref(), c.purl.as_deref()]
        .into_iter()
        .flatten()
        .find_map(|s| {
            s.find("@sha256:").map(|i| {
                let digest = &s[i + 1..];
                // A purl may carry qualifiers after the digest.
                digest
                    .split(['?', '#'])
                    .next()
                    .unwrap_or(digest)
                    .to_string()
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_components_flattened_and_purlless_counted() {
        let s = parse(include_bytes!("../../tests/fixtures/sbom/nested.cdx.json")).unwrap();
        assert_eq!(s.components.len(), 3);
        assert_eq!(s.skipped_without_purl, 1);
    }

    #[test]
    fn invalid_json_is_error_not_empty() {
        assert!(parse(b"{not json").is_err());
        assert!(parse(br#"{"bomFormat":"SPDX"}"#).is_err());
    }

    #[test]
    fn go_service_has_components_and_cpes() {
        let s = parse(include_bytes!(
            "../../tests/fixtures/sbom/go-service.cdx.json"
        ))
        .unwrap();
        assert_eq!(s.components.len(), 5);
        assert_eq!(s.image_digest, None);
        let gin = &s.components[0];
        assert_eq!(gin.purl, "pkg:golang/github.com/gin-gonic/gin@v1.9.0");
        // cpe field and first syft:cpe23 are identical: deduplicated.
        assert_eq!(gin.cpes.len(), 2);
    }

    #[test]
    fn duplicate_purls_merge_cpes() {
        let json = br#"{"bomFormat":"CycloneDX","components":[
            {"purl":"pkg:npm/a@1","cpe":"cpe:x"},
            {"purl":"pkg:npm/a@1","properties":[{"name":"syft:cpe23","value":"cpe:y"},{"name":"syft:cpe23","value":"cpe:x"}]}
        ]}"#;
        let s = parse(json).unwrap();
        assert_eq!(s.components.len(), 1);
        assert_eq!(s.components[0].cpes, vec!["cpe:x", "cpe:y"]);
    }

    #[test]
    fn container_digest_from_version_name_or_purl() {
        let from = |meta: &str| {
            let json = format!(r#"{{"bomFormat":"CycloneDX","metadata":{{"component":{meta}}}}}"#);
            parse(json.as_bytes()).unwrap().image_digest
        };
        assert_eq!(
            from(r#"{"type":"container","name":"app","version":"sha256:abc"}"#).as_deref(),
            Some("sha256:abc")
        );
        assert_eq!(
            from(r#"{"type":"container","name":"reg/app@sha256:def"}"#).as_deref(),
            Some("sha256:def")
        );
        assert_eq!(
            from(r#"{"type":"container","name":"app","purl":"pkg:oci/app@sha256:fed?repository_url=r"}"#)
                .as_deref(),
            Some("sha256:fed")
        );
        assert_eq!(from(r#"{"type":"file","version":"sha256:abc"}"#), None);
    }
}
