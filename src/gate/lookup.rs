//! Asking the advisory databases about an SBOM's components: OSV first,
//! the GitHub Advisory Database when OSV is down. Hits on one component
//! that describe one vulnerability are collapsed into one.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;

use crate::model::Severity;
use crate::purl::{name_key, osv_package, OsvPackage};
use crate::version;
use crate::vuln::collapse::{self, AliasInfo};
use crate::vuln::ghsa::{self, GhsaClient};
use crate::vuln::osv::{self, OsvClient, OsvHit};
use crate::vuln::severity;

/// OSV record downloads in flight at once.
const FETCH_CONCURRENCY: usize = 8;

/// A component the advisory databases can be asked about.
pub(super) struct Checked {
    pub(super) purl: String,
    pub(super) name_key: String,
    pub(super) pkg: OsvPackage,
}

/// One advisory hitting one component, before oaths are applied.
pub(super) struct Hit {
    pub(super) advisory: String,
    pub(super) severity: Severity,
    pub(super) purl: String,
    pub(super) name_key: String,
    pub(super) fixed: Option<String>,
    /// Ids an oath for this hit may be filed under (the advisory and aliases).
    pub(super) oath_ids: Vec<String>,
}

/// Unique purls that map to an OSV package. Others (oci, generic) have no
/// OSV ecosystem; the scheduled NVD matching covers them, not the gate.
pub(super) fn checkable(purls: &[String]) -> Vec<Checked> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for purl in purls {
        if !seen.insert(purl.as_str()) {
            continue;
        }
        let (Some(pkg), Ok(key)) = (osv_package(purl), name_key(purl)) else {
            continue;
        };
        out.push(Checked {
            purl: purl.clone(),
            name_key: key,
            pkg,
        });
    }
    out
}

/// The parts of a stored advisory row the gate can reuse.
#[derive(sqlx::FromRow)]
struct Stored {
    id: String,
    modified: DateTime<Utc>,
    severity: Severity,
    fixed: Value,
    has_nvd: bool,
    aliases: Vec<String>,
    cve_id: Option<String>,
}

/// Turn OSV's answer into hits. Records are fetched only when the stored row
/// is missing, older than OSV's `modified`, or lacks this component's fixed
/// versions. A hit is never dropped: when its record cannot be fetched in
/// time, the stored row's severity is used, and without a stored row the hit
/// is kept as unknown and its purl is reported unverified. Returns the hits
/// and the unverified purls; a database error is an `Err`.
pub(super) async fn osv_hits(
    pool: &PgPool,
    client: &OsvClient,
    checked: &[Checked],
    all: &[Vec<OsvHit>],
    budget: Duration,
) -> anyhow::Result<(Vec<Hit>, Vec<String>)> {
    let ids: Vec<String> = all
        .iter()
        .flatten()
        .map(|h| h.id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let stored: HashMap<String, Stored> = sqlx::query_as::<_, Stored>(
        "select id, modified, severity, fixed, scores ? 'nvd' as has_nvd, aliases, cve_id \
         from advisories where id = any($1)",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|s| (s.id.clone(), s))
    .collect();

    // (advisory, component) pairs, deduplicated, with what the stored row
    // can tell us without a fetch.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut pairs: Vec<Pair> = Vec::new();
    for (c, hits) in checked.iter().zip(all) {
        for hit in hits {
            if !seen.insert((hit.id.clone(), c.purl.clone())) {
                continue;
            }
            let reusable = stored
                .get(&hit.id)
                .filter(|s| s.modified >= hit.modified)
                .and_then(|s| Some((s.severity, stored_fixed(s, &c.name_key)?)));
            pairs.push(Pair { c, hit, reusable });
        }
    }
    let to_fetch: Vec<String> = pairs
        .iter()
        .filter(|p| p.reusable.is_none())
        .map(|p| p.hit.id.clone())
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let records = fetch_records(client, to_fetch, budget).await;

    let mut out = Vec::new();
    let mut unverified: Vec<String> = Vec::new();
    for Pair { c, hit, reusable } in pairs {
        let st = stored.get(&hit.id);
        let (sev, fixed_versions) = match (reusable, records.get(&hit.id)) {
            (Some(x), _) => x,
            (None, Some(rec)) => {
                let mut sev = severity::normalize(rec);
                // NVD may have raised it; a fresh OSV record must not lower it.
                if let Some(s) = st.filter(|s| s.has_nvd) {
                    sev = severity::merge(sev, s.severity);
                }
                (sev, osv::fixed_versions(rec, &c.pkg))
            }
            // The record could not be read: fall back on what is stored.
            (None, None) => match st {
                Some(s) => (s.severity, stored_fixed(s, &c.name_key).unwrap_or_default()),
                None => {
                    if !unverified.contains(&c.purl) {
                        unverified.push(c.purl.clone());
                    }
                    (Severity::Unknown, Vec::new())
                }
            },
        };
        let fixed_refs: Vec<&str> = fixed_versions.iter().map(String::as_str).collect();
        // An oath may be filed under any name of the advisory (a CVE, a GO- id).
        let mut oath_ids = vec![hit.id.clone()];
        let names = match records.get(&hit.id) {
            Some(rec) => osv::record_names(rec).ok(),
            None => st.map(|s| AliasInfo {
                id: s.id.clone(),
                aliases: s.aliases.clone(),
                cve_id: s.cve_id.clone(),
            }),
        };
        for name in names
            .into_iter()
            .flat_map(|n| n.aliases.into_iter().chain(n.cve_id))
        {
            if !oath_ids.contains(&name) {
                oath_ids.push(name);
            }
        }
        out.push(Hit {
            advisory: hit.id.clone(),
            severity: sev,
            purl: c.purl.clone(),
            name_key: c.name_key.clone(),
            fixed: version::recommend_fix(&c.pkg.ecosystem, &c.pkg.version, &fixed_refs)
                .map(|a| a.suggest),
            oath_ids,
        });
    }
    Ok((collapse_hits(out), unverified))
}

/// Hits on one component that describe one vulnerability (see `collapse`)
/// become one: the canonical advisory, the highest severity, its fix (or
/// another record's), and every id an oath may be filed under.
fn collapse_hits(hits: Vec<Hit>) -> Vec<Hit> {
    let mut by_purl: Vec<(String, Vec<Hit>)> = Vec::new();
    for h in hits {
        match by_purl.iter_mut().find(|(p, _)| *p == h.purl) {
            Some((_, list)) => list.push(h),
            None => by_purl.push((h.purl.clone(), vec![h])),
        }
    }
    let mut out = Vec::new();
    for (_, list) in by_purl {
        // `oath_ids` is the advisory's id followed by its other names.
        let items: Vec<AliasInfo> = list
            .iter()
            .map(|h| AliasInfo {
                id: h.advisory.clone(),
                aliases: h.oath_ids[1..].to_vec(),
                cve_id: h.oath_ids.iter().find(|i| osv::is_cve_id(i)).cloned(),
            })
            .collect();
        for group in collapse::groups(&items) {
            let canon = collapse::canonical(&items, &group);
            let mut hit = Hit {
                advisory: list[canon].advisory.clone(),
                severity: list[canon].severity,
                purl: list[canon].purl.clone(),
                name_key: list[canon].name_key.clone(),
                fixed: list[canon].fixed.clone(),
                oath_ids: list[canon].oath_ids.clone(),
            };
            for &i in &group {
                let other = &list[i];
                hit.severity = severity::merge(hit.severity, other.severity);
                if hit.fixed.is_none() {
                    hit.fixed = other.fixed.clone();
                }
                for id in &other.oath_ids {
                    if !hit.oath_ids.contains(id) {
                        hit.oath_ids.push(id.clone());
                    }
                }
            }
            out.push(hit);
        }
    }
    out
}

/// One advisory on one component, with what the stored row can tell us
/// without a fetch (severity, fixed versions).
struct Pair<'a> {
    c: &'a Checked,
    hit: &'a OsvHit,
    reusable: Option<(Severity, Vec<String>)>,
}

/// The stored fixed versions for one component, if the row has its key.
fn stored_fixed(s: &Stored, name_key: &str) -> Option<Vec<String>> {
    serde_json::from_value(s.fixed.get(name_key)?.clone()).ok()
}

/// Fetch OSV records, `FETCH_CONCURRENCY` at a time, until `budget` runs
/// out. Records that fail or are still pending at the deadline are left out
/// of the map; the caller decides what a missing record means.
async fn fetch_records(
    client: &OsvClient,
    ids: Vec<String>,
    budget: Duration,
) -> HashMap<String, Value> {
    let deadline = tokio::time::Instant::now() + budget;
    let mut out = HashMap::new();
    let mut queue = ids.into_iter();
    // Spawned tasks must own what they use, hence the client clone per task
    // (cheap: reqwest clients share one connection pool).
    let mut running = tokio::task::JoinSet::new();
    loop {
        while running.len() < FETCH_CONCURRENCY {
            let Some(id) = queue.next() else { break };
            let client = client.clone();
            running.spawn(async move {
                let rec = client.get(&id).await;
                (id, rec)
            });
        }
        match tokio::time::timeout_at(deadline, running.join_next()).await {
            Ok(None) => break,
            Ok(Some(Ok((id, Ok(rec))))) => {
                out.insert(id, rec);
            }
            Ok(Some(Ok((id, Err(e))))) => tracing::warn!("gate: osv record {id}: {e:#}"),
            Ok(Some(Err(e))) => tracing::warn!("gate: osv record fetch task failed: {e}"),
            Err(_) => {
                // Dropping the JoinSet aborts the fetches still running.
                tracing::warn!("gate: osv record fetches ran out of time");
                break;
            }
        }
    }
    out
}

/// The fallback. Returns the hits and the purls nothing vouched for:
/// everything when GHSA is unavailable or fails, otherwise the components
/// in ecosystems GitHub does not track.
pub(super) async fn ghsa_hits(
    pool: &PgPool,
    client: Option<&GhsaClient>,
    checked: &[Checked],
    budget: Duration,
) -> anyhow::Result<(Vec<Hit>, Vec<String>)> {
    let everything = || checked.iter().map(|c| c.purl.clone()).collect();
    let Some(client) = client else {
        tracing::warn!("gate: GITHUB_TOKEN is not set; no fallback, everything is unverified");
        return Ok((Vec::new(), everything()));
    };
    let pkgs: Vec<OsvPackage> = checked.iter().map(|c| c.pkg.clone()).collect();
    let all = match tokio::time::timeout(budget, client.check(&pkgs)).await {
        Ok(Ok(all)) => all,
        Ok(Err(e)) => {
            tracing::warn!("gate: github advisory db failed ({e:#}); everything is unverified");
            return Ok((Vec::new(), everything()));
        }
        Err(_) => {
            tracing::warn!("gate: github advisory db timed out; everything is unverified");
            return Ok((Vec::new(), everything()));
        }
    };

    let mut hits = Vec::new();
    let mut unverified = Vec::new();
    for (c, found) in checked.iter().zip(all) {
        if !ghsa::covers(&c.pkg) {
            unverified.push(c.purl.clone());
            continue;
        }
        for h in found {
            // Stored advisories that are this GHSA advisory under another id
            // (a CVE, a GO- id): oaths may be filed under those, and NVD may
            // have rated it higher.
            let known: Vec<(String, Option<String>, Severity)> = sqlx::query_as(
                "select id, cve_id, severity from advisories where id = $1 or $1 = any(aliases)",
            )
            .bind(&h.id)
            .fetch_all(pool)
            .await?;
            let mut oath_ids = vec![h.id.clone()];
            let mut sev = h.severity;
            for (id, cve, stored_sev) in known {
                sev = severity::merge(sev, stored_sev);
                for alias in std::iter::once(id).chain(cve) {
                    if !oath_ids.contains(&alias) {
                        oath_ids.push(alias);
                    }
                }
            }
            hits.push(Hit {
                advisory: h.id,
                severity: sev,
                purl: c.purl.clone(),
                name_key: c.name_key.clone(),
                fixed: h.fixed,
                oath_ids,
            });
        }
    }
    Ok((hits, unverified))
}
