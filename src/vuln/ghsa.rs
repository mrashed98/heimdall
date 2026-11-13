//! GitHub Advisory Database (GraphQL) fallback, used by the gate when OSV is
//! unreachable. Covers only the ecosystems GitHub tracks; the gate marks the
//! rest "unverified".

use std::cmp::Ordering;
use std::collections::HashSet;

use anyhow::{anyhow, Context};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use url::Url;

use crate::model::Severity;
use crate::purl::OsvPackage;
use crate::version;
use crate::vuln::retry;

/// Packages per GraphQL request (one aliased field each).
const BATCH_SIZE: usize = 50;
/// Pages (of 100 advisories) fetched per package before giving up.
const MAX_PAGES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhsaHit {
    /// GHSA id.
    pub id: String,
    pub severity: Severity,
    pub fixed: Option<String>,
}

#[derive(Clone)]
pub struct GhsaClient {
    pub base: Url,
    pub token: String,
    pub http: reqwest::Client,
}

#[derive(Deserialize)]
struct Response {
    data: Option<Map<String, Value>>,
    errors: Option<Vec<Value>>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Alias {
    #[serde(default)]
    nodes: Vec<Node>,
    #[serde(default)]
    page_info: PageInfo,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    #[serde(default)]
    has_next_page: bool,
    end_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Node {
    advisory: Advisory,
    vulnerable_version_range: String,
    first_patched_version: Option<Patched>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Advisory {
    ghsa_id: String,
    severity: String,
}

#[derive(Deserialize)]
struct Patched {
    identifier: String,
}

/// OSV ecosystem name -> GHSA `SecurityAdvisoryEcosystem` value.
fn ghsa_ecosystem(osv: &str) -> Option<&'static str> {
    Some(match osv {
        "Go" => "GO",
        "npm" => "NPM",
        "PyPI" => "PIP",
        "Maven" => "MAVEN",
        "crates.io" => "RUST",
        "RubyGems" => "RUBYGEMS",
        "NuGet" => "NUGET",
        "Packagist" => "COMPOSER",
        _ => return None,
    })
}

pub fn covers(pkg: &OsvPackage) -> bool {
    ghsa_ecosystem(&pkg.ecosystem).is_some()
}

impl GhsaClient {
    pub fn new(http: reqwest::Client, token: String) -> GhsaClient {
        GhsaClient {
            base: Url::parse("https://api.github.com/graphql").expect("static url"),
            token,
            http,
        }
    }

    /// One hit list per input package, in the same order. Uncovered
    /// ecosystems get an empty list (the caller decides they are unverified).
    /// Any GraphQL error or failed request is an `Err` for the whole call.
    pub async fn check(&self, pkgs: &[OsvPackage]) -> anyhow::Result<Vec<Vec<GhsaHit>>> {
        let mut out: Vec<Vec<GhsaHit>> = vec![Vec::new(); pkgs.len()];
        // Indices of covered packages, so results map back to input order.
        let covered: Vec<usize> = (0..pkgs.len()).filter(|&i| covers(&pkgs[i])).collect();
        for chunk in covered.chunks(BATCH_SIZE) {
            let batch: Vec<&OsvPackage> = chunk.iter().map(|&i| &pkgs[i]).collect();
            let hits = self.query_chunk(&batch).await?;
            for (&i, h) in chunk.iter().zip(hits) {
                out[i] = h;
            }
        }
        Ok(out)
    }

    async fn query_chunk(&self, chunk: &[&OsvPackage]) -> anyhow::Result<Vec<Vec<GhsaHit>>> {
        let mut nodes: Vec<Vec<Node>> = chunk.iter().map(|_| Vec::new()).collect();
        // Packages still to fetch, with the cursor for their next page.
        let mut pending: Vec<(usize, Option<String>)> =
            (0..chunk.len()).map(|i| (i, None)).collect();

        // The cap bounds a server that keeps saying "more"; running out of
        // pages is an error, never a silent truncation (the gate fails open
        // otherwise).
        for _ in 0..MAX_PAGES {
            if pending.is_empty() {
                break;
            }
            let data = self.post_page(chunk, &pending).await?;
            let mut next = Vec::new();
            for (k, (i, _)) in pending.iter().enumerate() {
                let alias: Alias = match data.get(&format!("q{k}")) {
                    Some(v) if !v.is_null() => serde_json::from_value(v.clone())
                        .with_context(|| format!("github advisory alias q{k}"))?,
                    // A covered package must always come back; absence is not
                    // "no vulnerabilities".
                    _ => return Err(anyhow!("github advisory response missing alias q{k}")),
                };
                nodes[*i].extend(alias.nodes);
                if alias.page_info.has_next_page {
                    let cursor = alias
                        .page_info
                        .end_cursor
                        .ok_or_else(|| anyhow!("github advisory hasNextPage without endCursor"))?;
                    next.push((*i, Some(cursor)));
                }
            }
            pending = next;
        }
        if !pending.is_empty() {
            return Err(anyhow!(
                "github advisory results exceed {MAX_PAGES} pages for a package"
            ));
        }
        Ok(chunk
            .iter()
            .zip(nodes)
            .map(|(p, n)| hits_for(p, n))
            .collect())
    }

    /// One request for the `pending` packages. Aliases are numbered by
    /// position in `pending`, not by package index.
    async fn post_page(
        &self,
        chunk: &[&OsvPackage],
        pending: &[(usize, Option<String>)],
    ) -> anyhow::Result<Map<String, Value>> {
        // Names and cursors travel as GraphQL variables, never spliced into
        // the query text, so no escaping or injection concerns.
        let mut decls = Vec::new();
        let mut fields = Vec::new();
        let mut vars = Map::new();
        for (k, (i, cursor)) in pending.iter().enumerate() {
            let p = chunk[*i];
            let eco = ghsa_ecosystem(&p.ecosystem).expect("covered package");
            decls.push(format!("$p{k}: String!, $a{k}: String"));
            fields.push(format!(
                "q{k}: securityVulnerabilities(ecosystem: {eco}, package: $p{k}, first: 100, after: $a{k}) \
                 {{ pageInfo {{ hasNextPage endCursor }} \
                 nodes {{ advisory {{ ghsaId severity }} \
                 vulnerableVersionRange firstPatchedVersion {{ identifier }} }} }}"
            ));
            vars.insert(format!("p{k}"), Value::String(p.name.clone()));
            if let Some(c) = cursor {
                vars.insert(format!("a{k}"), Value::String(c.clone()));
            }
        }
        let body = json!({
            "query": format!("query({}) {{ {} }}", decls.join(", "), fields.join(" ")),
            "variables": vars,
        });

        // Read-only query, so retrying the POST is safe.
        let resp = retry::send("github advisory query", || {
            self.http
                .post(self.base.clone())
                .bearer_auth(&self.token)
                .header("User-Agent", "heimdall")
                .json(&body)
        })
        .await?;
        let parsed: Response = resp.json().await.context("github advisory response")?;
        if let Some(errors) = parsed.errors.filter(|e| !e.is_empty()) {
            return Err(anyhow!("github advisory graphql errors: {errors:?}"));
        }
        parsed
            .data
            .ok_or_else(|| anyhow!("github advisory response has no data"))
    }
}

fn hits_for(pkg: &OsvPackage, nodes: Vec<Node>) -> Vec<GhsaHit> {
    let mut seen = HashSet::new();
    let mut hits = Vec::new();
    for n in nodes {
        if !in_range(&pkg.ecosystem, &pkg.version, &n.vulnerable_version_range) {
            continue;
        }
        if !seen.insert(n.advisory.ghsa_id.clone()) {
            continue;
        }
        hits.push(GhsaHit {
            id: n.advisory.ghsa_id,
            severity: severity(&n.advisory.severity),
            fixed: n.first_patched_version.map(|p| p.identifier),
        });
    }
    hits
}

fn severity(word: &str) -> Severity {
    match word {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MODERATE" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// GitHub range grammar: comma-separated clauses (`>= 1.0`, `< 2`, `= 1.5`),
/// all of which must hold. A clause we cannot evaluate counts as affected:
/// for a gate, a false alarm beats a missed vulnerability.
fn in_range(ecosystem: &str, version: &str, range: &str) -> bool {
    range
        .split(',')
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .all(|clause| clause_holds(ecosystem, version, clause))
}

fn clause_holds(ecosystem: &str, version: &str, clause: &str) -> bool {
    // Two-character operators first so `>=` is not read as `>`.
    let (op, bound) = ["<=", ">=", "<", ">", "="]
        .iter()
        .find_map(|op| clause.strip_prefix(op).map(|rest| (*op, rest.trim())))
        .unwrap_or(("", clause));
    let ord = if op.is_empty() || bound.is_empty() {
        None
    } else {
        version::compare(ecosystem, version, bound)
    };
    let Some(ord) = ord else {
        tracing::warn!(
            "ghsa: cannot compare {version:?} with clause {clause:?}; treating as affected"
        );
        return true;
    };
    match op {
        "<" => ord == Ordering::Less,
        "<=" => ord != Ordering::Greater,
        ">" => ord == Ordering::Greater,
        ">=" => ord != Ordering::Less,
        _ => ord == Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use wiremock::matchers::{body_partial_json, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn pkg(eco: &str, name: &str, version: &str) -> OsvPackage {
        OsvPackage {
            ecosystem: eco.into(),
            name: name.into(),
            version: version.into(),
        }
    }

    async fn client(status: u16, body: Value) -> (MockServer, GhsaClient) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .and(header("authorization", "Bearer tok"))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(&server)
            .await;
        let mut c = GhsaClient::new(reqwest::Client::new(), "tok".into());
        c.base = Url::parse(&format!("{}/graphql", server.uri())).unwrap();
        (server, c)
    }

    fn fixture() -> Value {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/ghsa/graphql_response.json"
        ))
        .unwrap()
    }

    #[test]
    fn debian_not_covered() {
        assert!(!covers(&pkg("Debian:12", "openssl", "3.0.1")));
    }

    #[test]
    fn npm_covered() {
        assert!(covers(&pkg("npm", "left-pad", "1.0.0")));
    }

    #[tokio::test]
    async fn check_filters_by_range() {
        let (_s, c) = client(200, fixture()).await;
        let pkgs = [
            pkg("Go", "github.com/gin-gonic/gin", "v1.9.0"),
            pkg("Go", "github.com/gin-gonic/gin", "v1.9.1"),
        ];
        let out = c.check(&pkgs).await.unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(
            out[0],
            vec![GhsaHit {
                id: "GHSA-3vp4-m3rf-835h".into(),
                severity: Severity::Medium,
                fixed: Some("1.9.1".into()),
            }]
        );
        assert!(out[1].is_empty());
    }

    #[tokio::test]
    async fn graphql_errors_are_err() {
        let (_s, c) = client(200, serde_json::json!({"errors": [{"message": "bad"}]})).await;
        assert!(c.check(&[pkg("npm", "x", "1.0.0")]).await.is_err());
    }

    #[tokio::test]
    async fn uncovered_ecosystem_gets_empty_slot() {
        let (_s, c) = client(200, serde_json::json!({"data": {}})).await;
        let out = c.check(&[pkg("Debian:12", "x", "1")]).await.unwrap();
        assert_eq!(out, vec![Vec::<GhsaHit>::new()]);
    }

    #[test]
    fn range_grammar() {
        assert!(in_range("npm", "1.5.0", ">= 1.0.0, < 2.0.0"));
        assert!(!in_range("npm", "2.0.0", ">= 1.0.0, < 2.0.0"));
        assert!(in_range("npm", "1.0.0", "<= 1.0.0"));
        assert!(in_range("npm", "1.2.3", "= 1.2.3"));
        assert!(in_range("Go", "v1.0.0", "< 1.0.1"));
        // Unparseable clause fails safe: affected.
        assert!(in_range("npm", "1.0.0", "~> nonsense"));
    }

    #[tokio::test]
    async fn paginates_when_has_next_page() {
        let server = MockServer::start().await;
        let node = |range: &str| {
            serde_json::json!({
                "advisory": {"ghsaId": "GHSA-old", "severity": "HIGH"},
                "vulnerableVersionRange": range,
                "firstPatchedVersion": null
            })
        };
        // Page 2 is matched first: it is the request carrying the cursor.
        Mock::given(method("POST"))
            .and(body_partial_json(
                serde_json::json!({"variables": {"a0": "cur1"}}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"q0": {
                    "pageInfo": {"hasNextPage": false, "endCursor": null},
                    "nodes": [node("< 2.0.0")]
                }}
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {"q0": {
                    "pageInfo": {"hasNextPage": true, "endCursor": "cur1"},
                    "nodes": [node("< 0.1.0")]
                }}
            })))
            .mount(&server)
            .await;
        let mut c = GhsaClient::new(reqwest::Client::new(), "tok".into());
        c.base = Url::parse(&format!("{}/graphql", server.uri())).unwrap();
        let out = c.check(&[pkg("npm", "x", "1.0.0")]).await.unwrap();
        assert_eq!(out[0].len(), 1);
        assert_eq!(out[0][0].id, "GHSA-old");
    }

    #[tokio::test]
    async fn missing_alias_is_err() {
        let (_s, c) = client(200, serde_json::json!({"data": {}})).await;
        assert!(c.check(&[pkg("npm", "x", "1.0.0")]).await.is_err());
        let (_s, c) = client(200, serde_json::json!({"data": {"q0": null}})).await;
        assert!(c.check(&[pkg("npm", "x", "1.0.0")]).await.is_err());
    }
}
