//! NVD API 2.0 client and incremental refresh.
//!
//! We never mirror NVD: each run asks for the CVEs changed since the last
//! successful run (plus a one-off backfill per vendor:product) and matches
//! them locally against component CPEs. Only matching advisories are stored.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use url::Url;

use crate::config::HeimdallConfig;
use crate::model::Severity;
use crate::purl::osv_package;
use crate::vuln::collapse::{self, AliasInfo};
use crate::vuln::cpe::{self, concrete_version, vendor_product};
use crate::vuln::{retry, severity};

pub use crate::vuln::cpe::{cpe_matches, CpeRange};

const PAGE_SIZE: usize = 2000;
/// NVD rejects `lastMod` windows longer than 120 days.
const MAX_WINDOW_DAYS: i64 = 120;
/// 50 requests per 30 s with a key; 0.6 s apart stays under that.
const REQUEST_DELAY: Duration = Duration::from_millis(650);
const KV_LAST: &str = "nvd_last";
/// How far before the previous window's end the next window starts.
const WINDOW_OVERLAP_MINUTES: i64 = 15;

#[derive(Debug, Clone, PartialEq)]
pub struct NvdCve {
    pub id: String,
    pub cvss: Option<f32>,
    pub severity: Severity,
    pub summary: String,
    pub configs: Vec<CpeRange>,
}

#[derive(Clone)]
pub struct NvdClient {
    pub base: Url,
    pub api_key: String,
    pub http: reqwest::Client,
    /// Pause between requests; a field so tests can set it to zero.
    pub delay: Duration,
    /// When the next request may go out. Shared by clones so they all keep the pace.
    next_slot: Arc<Mutex<Instant>>,
}

impl NvdClient {
    pub fn new(http: reqwest::Client, api_key: String) -> NvdClient {
        NvdClient {
            base: Url::parse("https://services.nvd.nist.gov/rest/json/cves/2.0")
                .expect("static url"),
            api_key,
            http,
            delay: REQUEST_DELAY,
            next_slot: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// CVEs last modified in `[from, to]`. Windows over 120 days are split.
    pub async fn changed(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> anyhow::Result<Vec<NvdCve>> {
        let mut out = Vec::new();
        let mut start = from;
        while start < to {
            let end = (start + chrono::Duration::days(MAX_WINDOW_DAYS)).min(to);
            let params = [
                ("lastModStartDate", nvd_date(start)),
                ("lastModEndDate", nvd_date(end)),
            ];
            out.extend(self.pages(&params).await?);
            start = end;
        }
        Ok(out)
    }

    /// Every CVE that names `vendor_product` (`vendor:product`).
    pub async fn backfill(&self, vendor_product: &str) -> anyhow::Result<Vec<NvdCve>> {
        let params = [("virtualMatchString", format!("cpe:2.3:*:{vendor_product}"))];
        self.pages(&params).await
    }

    async fn pages(&self, params: &[(&str, String)]) -> anyhow::Result<Vec<NvdCve>> {
        let mut out = Vec::new();
        let mut start_index = 0usize;
        loop {
            self.pace().await;
            let mut url = self.base.clone();
            {
                let mut q = url.query_pairs_mut();
                for (k, v) in params {
                    q.append_pair(k, v);
                }
                q.append_pair("startIndex", &start_index.to_string());
                q.append_pair("resultsPerPage", &PAGE_SIZE.to_string());
            }
            let mut body: Value = retry::send("nvd request", || {
                let req = self.http.get(url.clone());
                if self.api_key.is_empty() {
                    req
                } else {
                    req.header("apiKey", &self.api_key)
                }
            })
            .await?
            .json()
            .await
            .context("nvd response body")?;
            let total = body["totalResults"].as_u64().unwrap_or(0) as usize;
            // A 200 without the array is not a page of CVEs (a maintenance
            // notice, a proxy's page): taking it as "nothing changed" would
            // move the window past CVEs we never saw. The array is taken out
            // of the page, not copied.
            let vulns = match body.get_mut("vulnerabilities").map(Value::take) {
                Some(Value::Array(list)) => list,
                _ => anyhow::bail!("nvd answered 200 without a vulnerabilities array"),
            };
            for v in &vulns {
                out.push(parse_cve(&v["cve"]).context("nvd record without id")?);
            }
            start_index += vulns.len();
            // An empty page ends the loop even if `totalResults` is wrong.
            if vulns.is_empty() || start_index >= total {
                return Ok(out);
            }
        }
    }

    /// Wait for our turn. The slot is booked before sleeping so concurrent
    /// callers queue up instead of all waking at once.
    async fn pace(&self) {
        let wait = {
            let mut next = self.next_slot.lock().expect("pace lock");
            let now = Instant::now();
            let slot = (*next).max(now);
            *next = slot + self.delay;
            slot - now
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// `2026-11-13T00:00:00.000+00:00`, the form the API wants.
fn nvd_date(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3f+00:00").to_string()
}

/// Read one `vulnerabilities[].cve` object. None when it has no id.
pub fn parse_cve(cve: &Value) -> Option<NvdCve> {
    let id = cve["id"].as_str()?.to_string();
    let summary = cve["descriptions"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|d| d["lang"] == "en")
        .and_then(|d| d["value"].as_str())
        .unwrap_or("")
        .to_string();
    // Highest base score over every CVSS version NVD lists.
    let cvss = ["cvssMetricV31", "cvssMetricV30", "cvssMetricV40"]
        .iter()
        .flat_map(|k| cve["metrics"][*k].as_array().into_iter().flatten())
        .filter_map(|m| m["cvssData"]["baseScore"].as_f64())
        .map(|s| s as f32)
        .reduce(f32::max);
    let severity = cvss.map_or(Severity::Unknown, |s| severity::from_score(f64::from(s)));
    let opt = |m: &Value, k: &str| m[k].as_str().map(String::from);
    let configs = cve["configurations"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["nodes"].as_array().into_iter().flatten())
        .flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten())
        .filter(|m| m["vulnerable"] == true)
        .filter_map(|m| {
            Some(CpeRange {
                criteria: m["criteria"].as_str()?.to_string(),
                start_incl: opt(m, "versionStartIncluding"),
                start_excl: opt(m, "versionStartExcluding"),
                end_incl: opt(m, "versionEndIncluding"),
                end_excl: opt(m, "versionEndExcluding"),
            })
        })
        .collect();
    Some(NvdCve {
        id,
        cvss,
        severity,
        summary,
        configs,
    })
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct NvdReport {
    /// CVEs NVD reported as changed in the window.
    pub changed: usize,
    /// (component, CVE) pairs that match right now.
    pub matched: usize,
    /// Version comparisons that found no order (each counted as no match).
    pub uncomparable: usize,
}

/// `(inventory_name, cpe)` of every configured target that has a `cpe`.
pub fn target_cpes(cfg: &HeimdallConfig) -> Vec<(String, String)> {
    let github = cfg
        .watchers
        .github
        .iter()
        .map(|t| (&t.inventory_name, &t.cpe));
    let eol = cfg
        .watchers
        .endoflife
        .iter()
        .map(|t| (&t.inventory_name, &t.cpe));
    github
        .chain(eol)
        .filter_map(|(name, cpe)| Some((name.clone(), cpe.clone()?)))
        .collect()
}

/// A component with one CPE to match and the version to match it at.
struct Candidate {
    component_id: i64,
    cpe: String,
    version: String,
    ecosystem: String,
}

/// Pull what changed since the last run, backfill unseen products, match
/// everything against the inventory and merge into `advisories`. `targets` is
/// `target_cpes(cfg)`. `kv nvd_last` moves only if all of this succeeded.
pub async fn refresh(
    pool: &PgPool,
    client: &NvdClient,
    targets: &[(String, String)],
    now: DateTime<Utc>,
) -> anyhow::Result<NvdReport> {
    let uncomparable_before = cpe::uncomparable_count();
    let candidates = candidates(pool, targets).await?;

    let last: Option<String> = sqlx::query_scalar("select value from kv where key = $1")
        .bind(KV_LAST)
        .fetch_optional(pool)
        .await?;
    // Each window starts a little before the previous one ended: NVD can
    // index a CVE late with an earlier lastModified. Seeing a CVE twice is
    // harmless, every write is an upsert.
    let from = match last {
        Some(v) => {
            v.parse::<DateTime<Utc>>()
                .with_context(|| format!("kv {KV_LAST} is not RFC 3339: {v}"))?
                - chrono::Duration::minutes(WINDOW_OVERLAP_MINUTES)
        }
        None => now - chrono::Duration::days(1),
    };

    let mut cves: BTreeMap<String, NvdCve> = BTreeMap::new();
    let changed = client.changed(from, now).await?;
    let changed_count = changed.len();
    for c in changed {
        cves.insert(c.id.clone(), c);
    }

    // vendor:product -> component versions we would match against it.
    let mut wanted: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for c in &candidates {
        if let Some(p) = vendor_product(&c.cpe) {
            wanted.entry(p).or_default().insert(c.version.clone());
        }
    }
    let done: Vec<(String, Vec<String>)> = sqlx::query_as(
        "select vendor_product, versions from nvd_products where backfilled_at is not null",
    )
    .fetch_all(pool)
    .await?;
    let done: HashMap<String, BTreeSet<String>> = done
        .into_iter()
        .map(|(p, v)| (p, v.into_iter().collect()))
        .collect();
    // Backfill a product again when a component version appeared that it was
    // not backfilled for: older CVEs may apply to that version.
    // One product failing must not stop the others, so errors are logged and
    // the product stays unrecorded (it is retried next run).
    let mut backfilled: Vec<(String, Vec<String>)> = Vec::new();
    for (product, versions) in &wanted {
        let seen = done.get(product);
        if seen.is_some_and(|s| versions.is_subset(s)) {
            continue;
        }
        match client.backfill(product).await {
            Ok(list) => {
                for c in list {
                    cves.entry(c.id.clone()).or_insert(c);
                }
                let mut all = versions.clone();
                all.extend(seen.into_iter().flatten().cloned());
                backfilled.push((product.clone(), all.into_iter().collect()));
            }
            Err(e) => tracing::warn!(product = %product, "nvd backfill failed, will retry: {e:#}"),
        }
    }

    // CVE id -> components it matches now.
    let mut matches: BTreeMap<&str, BTreeSet<i64>> = BTreeMap::new();
    for cve in cves.values() {
        let hit: BTreeSet<i64> = candidates
            .iter()
            .filter(|c| {
                cve.configs
                    .iter()
                    .any(|r| cpe_matches(r, &c.cpe, &c.version, &c.ecosystem))
            })
            .map(|c| c.component_id)
            .collect();
        matches.insert(cve.id.as_str(), hit);
    }

    let mut tx = pool.begin().await?;
    let matched = write_matches(&mut tx, &cves, &matches).await?;
    for (product, versions) in &backfilled {
        sqlx::query(
            "insert into nvd_products (vendor_product, backfilled_at, versions) values ($1, $2, $3) \
             on conflict (vendor_product) do update set \
               backfilled_at = excluded.backfilled_at, versions = excluded.versions",
        )
        .bind(product)
        .bind(now)
        .bind(versions)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "insert into kv (key, value) values ($1, $2) \
         on conflict (key) do update set value = excluded.value",
    )
    .bind(KV_LAST)
    .bind(now.to_rfc3339())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(NvdReport {
        changed: changed_count,
        matched,
        uncomparable: cpe::uncomparable_count().saturating_sub(uncomparable_before),
    })
}

/// Every (component, cpe, version) we can match: the CPEs stored on the
/// component plus the configured target CPE of `pkg:generic/<inventory_name>`.
async fn candidates(pool: &PgPool, targets: &[(String, String)]) -> anyhow::Result<Vec<Candidate>> {
    let rows: Vec<(i64, String, String, String, Vec<String>)> =
        sqlx::query_as("select id, purl, name_key, version, cpes from components")
            .fetch_all(pool)
            .await?;
    let mut out = Vec::new();
    for (component_id, purl, name_key, purl_version, cpes) in rows {
        // The OSV ecosystem picks the version ordering; otherwise lenient semver.
        let ecosystem = osv_package(&purl).map_or_else(|| "generic".to_string(), |p| p.ecosystem);
        let mut push = |cpe: String, version: String| {
            out.push(Candidate {
                component_id,
                cpe,
                version,
                ecosystem: ecosystem.clone(),
            });
        };
        for cpe in cpes {
            // A concrete version in the CPE beats the purl version.
            let version = concrete_version(&cpe).unwrap_or_else(|| purl_version.clone());
            push(cpe, version);
        }
        for (name, cpe) in targets {
            if name_key == format!("pkg:generic/{name}") {
                push(cpe.clone(), purl_version.clone());
            }
        }
    }
    Ok(out)
}

pub type Tx<'a> = sqlx::Transaction<'a, sqlx::Postgres>;

/// Upsert advisories for matching CVEs, add `nvd`/`both` links, and take away
/// the NVD side of links that no longer match. Returns the match count.
async fn write_matches(
    tx: &mut Tx<'_>,
    cves: &BTreeMap<String, NvdCve>,
    matches: &BTreeMap<&str, BTreeSet<i64>>,
) -> anyhow::Result<usize> {
    let cve_ids: Vec<String> = cves.keys().cloned().collect();
    let mut by_cve = load_existing(tx, &cve_ids).await?;
    // An nvd row next to an OSV row for one CVE is a duplicate: fold it in
    // first, then read again so the severities below are current.
    let mut folded = false;
    for (cve, rows) in &by_cve {
        if rows.iter().any(|r| r.2 == "nvd") && rows.iter().any(|r| r.2 != "nvd") {
            fold_duplicates(tx, cve).await?;
            folded = true;
        }
    }
    if folded {
        by_cve = load_existing(tx, &cve_ids).await?;
    }

    let mut touched: Vec<String> = Vec::new();
    let mut pair_c: Vec<i64> = Vec::new();
    let mut pair_a: Vec<String> = Vec::new();
    for (cve_id, cve) in cves {
        let hit = &matches[cve_id.as_str()];
        let mut rows = by_cve.remove(cve_id).unwrap_or_default();
        if !hit.is_empty() {
            if rows.is_empty() {
                insert_nvd_advisory(tx, cve).await?;
                rows.push((cve_id.clone(), cve.severity, "nvd".into()));
            } else {
                for (id, sev, source) in &rows {
                    merge_into(tx, id, *sev, source, cve).await?;
                }
            }
        }
        let ids: Vec<String> = rows.into_iter().map(|(id, _, _)| id).collect();
        for (c, id) in link_targets(tx, cve_id, &ids, hit).await? {
            pair_c.push(c);
            pair_a.push(id);
        }
        touched.extend(ids);
    }

    // Matching components get an nvd link; an existing osv link becomes both.
    sqlx::query(
        "insert into component_advisories (component_id, advisory_id, match_source) \
         select c, a, 'nvd' from unnest($1::bigint[], $2::text[]) as t(c, a) \
         on conflict (component_id, advisory_id) do update set match_source = \
           case when component_advisories.match_source = 'osv' then 'both' \
                else component_advisories.match_source end",
    )
    .bind(&pair_c)
    .bind(&pair_a)
    .execute(&mut **tx)
    .await?;

    // Links to these advisories that NVD no longer backs: nvd rows go, both
    // goes back to osv. OSV's own links are never deleted here.
    let stale = "not exists (select 1 from unnest($2::bigint[], $3::text[]) as t(c, a) \
                 where t.c = component_advisories.component_id \
                   and t.a = component_advisories.advisory_id)";
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "delete from component_advisories where advisory_id = any($1) \
         and match_source = 'nvd' and {stale}"
    )))
    .bind(&touched)
    .bind(&pair_c)
    .bind(&pair_a)
    .execute(&mut **tx)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "update component_advisories set match_source = 'osv' where advisory_id = any($1) \
         and match_source = 'both' and {stale}"
    )))
    .bind(&touched)
    .bind(&pair_c)
    .bind(&pair_a)
    .execute(&mut **tx)
    .await?;
    // An advisory only NVD knew about and nothing links to is just noise.
    sqlx::query(
        "delete from advisories where id = any($1) and source = 'nvd' \
         and not exists (select 1 from component_advisories where advisory_id = advisories.id)",
    )
    .bind(&touched)
    .execute(&mut **tx)
    .await?;

    Ok(pair_c.len().min(pair_a.len()))
}

/// CVE id -> (advisory id, severity, source) of every advisory carrying it.
async fn load_existing(
    tx: &mut Tx<'_>,
    cve_ids: &[String],
) -> anyhow::Result<HashMap<String, Vec<(String, Severity, String)>>> {
    let existing: Vec<(String, String, Severity, String)> = sqlx::query_as(
        "select id, coalesce(cve_id, id), severity, source from advisories \
         where cve_id = any($1) or id = any($1)",
    )
    .bind(cve_ids)
    .fetch_all(&mut **tx)
    .await?;
    let mut by_cve: HashMap<String, Vec<(String, Severity, String)>> = HashMap::new();
    for (id, cve, sev, source) in existing {
        by_cve.entry(cve).or_default().push((id, sev, source));
    }
    Ok(by_cve)
}

/// Which advisory each matched component is linked to for one CVE. With one
/// advisory carrying the CVE, that one. With several (OSV records from
/// different databases), a component OSV already links to one of them keeps
/// that one (an OSV link before an NVD-only one), and any other gets the
/// canonical one (see `collapse`): one CVE is one link per component, so one
/// finding.
async fn link_targets(
    tx: &mut Tx<'_>,
    cve_id: &str,
    ids: &[String],
    hit: &BTreeSet<i64>,
) -> anyhow::Result<Vec<(i64, String)>> {
    if ids.len() == 1 {
        return Ok(hit.iter().map(|c| (*c, ids[0].clone())).collect());
    }
    let canon = canonical_for_cve(cve_id, ids);
    let components: Vec<i64> = hit.iter().copied().collect();
    // Per component, the advisory OSV links (osv or both) first; an older
    // NVD-only link only when OSV links none of them.
    let linked: Vec<(i64, String)> = sqlx::query_as(
        "select distinct on (component_id) component_id, advisory_id \
         from component_advisories \
         where component_id = any($1) and advisory_id = any($2) \
         order by component_id, match_source = 'nvd', advisory_id",
    )
    .bind(&components)
    .bind(ids)
    .fetch_all(&mut **tx)
    .await?;
    let linked: HashMap<i64, String> = linked.into_iter().collect();
    Ok(hit
        .iter()
        .map(|c| (*c, linked.get(c).cloned().unwrap_or_else(|| canon.clone())))
        .collect())
}

/// The advisory that stands for a CVE several advisories carry.
fn canonical_for_cve(cve_id: &str, ids: &[String]) -> String {
    let items: Vec<AliasInfo> = ids
        .iter()
        .map(|id| AliasInfo {
            id: id.clone(),
            aliases: Vec::new(),
            cve_id: Some(cve_id.to_string()),
        })
        .collect();
    let all: Vec<usize> = (0..items.len()).collect();
    items[collapse::canonical(&items, &all)].id.clone()
}

/// One CVE must be one advisory. When an nvd-sourced advisory and an
/// OSV-sourced one share `cve_id` (NVD ran before OSV knew the CVE), move the
/// nvd row's links onto the OSV row the component already links (or the
/// canonical OSV row, see `link_targets`), copy `scores.nvd` to every OSV
/// row, keep the higher severity and delete the nvd row. A link NVD found
/// stays `nvd`; where OSV already links the component it becomes `both`.
/// Called by both the NVD and the OSV write paths.
pub async fn fold_duplicates(tx: &mut Tx<'_>, cve_id: &str) -> anyhow::Result<()> {
    let rows: Vec<(String, Severity, String, Value)> = sqlx::query_as(
        "select id, severity, source, scores from advisories where cve_id = $1 order by id",
    )
    .bind(cve_id)
    .fetch_all(&mut **tx)
    .await?;
    let Some(nvd) = rows.iter().find(|r| r.2 == "nvd") else {
        return Ok(());
    };
    let osv_ids: Vec<String> = rows
        .iter()
        .filter(|r| r.2 != "nvd")
        .map(|r| r.0.clone())
        .collect();
    if !osv_ids.is_empty() {
        sqlx::query(
            "insert into component_advisories (component_id, advisory_id, match_source) \
             select n.component_id, \
                    coalesce((select o.advisory_id from component_advisories o \
                              where o.component_id = n.component_id \
                                and o.advisory_id = any($3) \
                              order by o.match_source = 'nvd', o.advisory_id limit 1), $2), \
                    n.match_source \
             from component_advisories n where n.advisory_id = $1 \
             on conflict (component_id, advisory_id) do update set match_source = \
               case when component_advisories.match_source = 'nvd' then 'nvd' else 'both' end",
        )
        .bind(&nvd.0)
        .bind(canonical_for_cve(cve_id, &osv_ids))
        .bind(&osv_ids)
        .execute(&mut **tx)
        .await?;
    }
    for (id, sev, _, _) in rows.iter().filter(|r| r.2 != "nvd") {
        let score = nvd.3.get("nvd").cloned().unwrap_or(Value::Null);
        sqlx::query(
            "update advisories set severity = $2, \
               scores = scores || jsonb_build_object('nvd', $3::jsonb) where id = $1",
        )
        .bind(id)
        .bind(severity::merge(*sev, nvd.1))
        .bind(score)
        .execute(&mut **tx)
        .await?;
    }
    if rows.iter().any(|r| r.2 != "nvd") {
        sqlx::query("delete from advisories where id = $1")
            .bind(&nvd.0)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// scores.nvd as a JSON number. f32 -> f64 directly would show 9.800000190...
fn nvd_score(cve: &NvdCve) -> Value {
    match cve.cvss {
        Some(s) => s
            .to_string()
            .parse::<f64>()
            .map_or(Value::Null, |f| json!(f)),
        // Still a key, so OSV's `scores ? 'nvd'` guard sees NVD has looked.
        None => Value::Null,
    }
}

async fn insert_nvd_advisory(tx: &mut Tx<'_>, cve: &NvdCve) -> anyhow::Result<()> {
    sqlx::query(
        "insert into advisories (id, severity, summary, modified, source, scores, cve_id) \
         values ($1, $2, $3, now(), 'nvd', jsonb_build_object('nvd', $4::jsonb), $1)",
    )
    .bind(&cve.id)
    .bind(cve.severity)
    .bind(&cve.summary)
    .bind(nvd_score(cve))
    .execute(&mut **tx)
    .await
    .with_context(|| format!("inserting advisory {}", cve.id))?;
    Ok(())
}

/// Add NVD's score to an advisory that exists already. The higher severity wins.
/// OSV-sourced rows keep their summary and `modified` (OSV's refresh logic
/// compares that timestamp).
async fn merge_into(
    tx: &mut Tx<'_>,
    id: &str,
    current: Severity,
    source: &str,
    cve: &NvdCve,
) -> anyhow::Result<()> {
    // NVD with no score must not raise a Low to Unknown.
    let merged = if cve.cvss.is_some() {
        severity::merge(current, cve.severity)
    } else {
        current
    };
    let own = source == "nvd";
    sqlx::query(
        "update advisories set severity = $2, \
           scores = scores || jsonb_build_object('nvd', $3::jsonb), \
           summary = case when $4 and $5 <> '' then $5 else summary end, \
           modified = case when $4 then now() else modified end \
         where id = $1",
    )
    .bind(id)
    .bind(merged)
    .bind(nvd_score(cve))
    .bind(own)
    .bind(&cve.summary)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("merging nvd into advisory {id}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::{json, Value};
    use sqlx::PgPool;
    use wiremock::matchers::{header, method, path, query_param, query_param_is_missing};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const PG_CPE: &str = "cpe:2.3:a:postgresql:postgresql:16.4:*:*:*:*:*:*:*";
    const PG_PURL: &str = "pkg:generic/postgresql@16.4";
    const PG_KEY: &str = "pkg:generic/postgresql";

    fn range(criteria: &str, si: Option<&str>, ee: Option<&str>) -> CpeRange {
        CpeRange {
            criteria: criteria.into(),
            start_incl: si.map(String::from),
            start_excl: None,
            end_incl: None,
            end_excl: ee.map(String::from),
        }
    }

    fn client(server: &MockServer) -> NvdClient {
        let mut c = NvdClient::new(reqwest::Client::new(), "secret".into());
        c.base = Url::parse(&format!("{}/rest/json/cves/2.0", server.uri())).unwrap();
        c.delay = Duration::ZERO;
        c
    }

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, 0, 0, 0).unwrap()
    }

    /// A one-CVE NVD response matching postgresql 15.0 up to (excl) 17.0.
    fn page_with(id: &str, score: f64, vendor_product: &str) -> Value {
        json!({
            "totalResults": 1,
            "vulnerabilities": [{"cve": {
                "id": id,
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{
                    "vulnerable": true,
                    "criteria": format!("cpe:2.3:a:{vendor_product}:*:*:*:*:*:*:*:*"),
                    "versionStartIncluding": "15.0",
                    "versionEndExcluding": "17.0"
                }]}]}]
            }}]
        })
    }

    fn empty_page() -> Value {
        json!({"totalResults": 0, "vulnerabilities": []})
    }

    async fn mock_changed(server: &MockServer, body: Value) {
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param_is_missing("virtualMatchString"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    async fn mock_backfill(server: &MockServer, body: Value, times: u64) {
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param(
                "virtualMatchString",
                "cpe:2.3:*:postgresql:postgresql",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(times)
            .mount(server)
            .await;
    }

    async fn seed_pg(pool: &PgPool) -> i64 {
        sqlx::query_scalar(
            "insert into components (purl, name_key, ecosystem, version, cpes) \
             values ($1, $2, 'generic', '16.4', $3) returning id",
        )
        .bind(PG_PURL)
        .bind(PG_KEY)
        .bind(vec![PG_CPE.to_string()])
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn links(pool: &PgPool) -> Vec<(String, String)> {
        sqlx::query_as(
            "select advisory_id, match_source from component_advisories order by advisory_id",
        )
        .fetch_all(pool)
        .await
        .unwrap()
    }

    #[test]
    fn cpe_range_match() {
        let r = range(
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            Some("16.0"),
            Some("16.5"),
        );
        assert!(cpe_matches(&r, PG_CPE, "16.4", "generic"));
        assert!(!cpe_matches(&r, PG_CPE, "16.5", "generic"));
        assert!(!cpe_matches(&r, PG_CPE, "15.9", "generic"));
        // Exact version in the criteria is an exact match, not a range.
        let exact = range(
            "cpe:2.3:a:postgresql:postgresql:16.4:*:*:*:*:*:*:*",
            None,
            None,
        );
        assert!(cpe_matches(&exact, PG_CPE, "16.4", "generic"));
        assert!(!cpe_matches(&exact, PG_CPE, "16.3", "generic"));
    }

    #[test]
    fn vendor_product_must_match() {
        let r = range(
            "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            None,
            None,
        );
        let other = "cpe:2.3:a:postgresql:postgres:16.4:*:*:*:*:*:*:*";
        assert!(!cpe_matches(&r, other, "16.4", "generic"));
        // Case does not matter.
        let upper = "cpe:2.3:a:PostgreSQL:PostgreSQL:16.4:*:*:*:*:*:*:*";
        assert!(cpe_matches(&r, upper, "16.4", "generic"));
    }

    #[test]
    fn parses_cve_fields() {
        let page: Value =
            serde_json::from_str(include_str!("../../tests/fixtures/nvd/changed_page1.json"))
                .unwrap();
        let cve = parse_cve(&page["vulnerabilities"][0]["cve"]).unwrap();
        assert_eq!(cve.id, "CVE-2026-2001");
        assert_eq!(cve.cvss, Some(9.8)); // max of 9.8 and 9.1
        assert_eq!(cve.severity, Severity::Critical);
        assert_eq!(cve.summary, "Buffer overflow in PostgreSQL.");
        // Only the vulnerable cpeMatch is kept.
        assert_eq!(cve.configs.len(), 1);
        assert_eq!(cve.configs[0].start_incl.as_deref(), Some("16.0"));
        assert_eq!(cve.configs[0].end_excl.as_deref(), Some("16.5"));
    }

    #[tokio::test]
    async fn paging_and_window() {
        let server = MockServer::start().await;
        for (start, body) in [
            (
                "0",
                include_str!("../../tests/fixtures/nvd/changed_page1.json"),
            ),
            (
                "2",
                include_str!("../../tests/fixtures/nvd/changed_page2.json"),
            ),
        ] {
            Mock::given(method("GET"))
                .and(path("/rest/json/cves/2.0"))
                .and(header("apiKey", "secret"))
                .and(query_param("startIndex", start))
                .and(query_param("resultsPerPage", "2000"))
                .and(query_param(
                    "lastModStartDate",
                    "2026-11-01T00:00:00.000+00:00",
                ))
                .and(query_param(
                    "lastModEndDate",
                    "2026-11-13T00:00:00.000+00:00",
                ))
                .respond_with(
                    ResponseTemplate::new(200)
                        .set_body_json(serde_json::from_str::<Value>(body).unwrap()),
                )
                .expect(1)
                .mount(&server)
                .await;
        }
        let cves = client(&server).changed(at(1), at(13)).await.unwrap();
        let ids: Vec<&str> = cves.iter().map(|c| c.id.as_str()).collect();
        assert_eq!(ids, ["CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"]);
    }

    #[tokio::test]
    async fn windows_over_120_days_are_split() {
        let server = MockServer::start().await;
        mock_changed(&server, empty_page()).await;
        let from = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        // 250 days: 120 + 120 + 10.
        let to = from + chrono::Duration::days(250);
        client(&server).changed(from, to).await.unwrap();
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 3);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_and_nvd_same_cve_one_advisory_higher_severity(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(
            &server,
            page_with("CVE-2026-7000", 9.8, "postgresql:postgresql"),
        )
        .await;
        mock_backfill(&server, empty_page(), 1).await;
        let cid = seed_pg(&pool).await;
        sqlx::query(
            "insert into advisories (id, aliases, severity, source, scores, cve_id) values \
             ('GHSA-pg', '{CVE-2026-7000}', 'high', 'osv', '{\"osv\": 7.5}', 'CVE-2026-7000')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("insert into component_advisories values ($1, 'GHSA-pg', 'osv')")
            .bind(cid)
            .execute(&pool)
            .await
            .unwrap();

        let report = refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        assert_eq!(report.matched, 1);

        let rows: Vec<(String, String, Value)> =
            sqlx::query_as("select id, severity, scores from advisories")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].1, "critical");
        assert_eq!(rows[0].2, json!({"osv": 7.5, "nvd": 9.8}));
        assert_eq!(
            links(&pool).await,
            [("GHSA-pg".to_string(), "both".to_string())]
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn nvd_links_one_advisory_when_several_carry_the_cve(pool: PgPool) {
        // Debian's DSA and DEBIAN-CVE records both carry CVE-2026-7000.
        let server = MockServer::start().await;
        mock_changed(
            &server,
            page_with("CVE-2026-7000", 9.8, "postgresql:postgresql"),
        )
        .await;
        mock_backfill(&server, empty_page(), 1).await;
        seed_pg(&pool).await;
        sqlx::query(
            "insert into advisories (id, severity, source, cve_id) values \
             ('DSA-5000-1', 'high', 'osv', 'CVE-2026-7000'), \
             ('DEBIAN-CVE-2026-7000', 'high', 'osv', 'CVE-2026-7000')",
        )
        .execute(&pool)
        .await
        .unwrap();

        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        // One link, to the canonical record (smallest id: neither is GHSA).
        assert_eq!(
            links(&pool).await,
            [("DEBIAN-CVE-2026-7000".to_string(), "nvd".to_string())]
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn nvd_joins_the_advisory_osv_links_not_the_smallest(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(
            &server,
            page_with("CVE-2026-7000", 9.8, "postgresql:postgresql"),
        )
        .await;
        mock_backfill(&server, empty_page(), 1).await;
        let cid = seed_pg(&pool).await;
        sqlx::query(
            "insert into advisories (id, severity, source, cve_id) values \
             ('DSA-5000-1', 'high', 'osv', 'CVE-2026-7000'), \
             ('DEBIAN-CVE-2026-7000', 'high', 'osv', 'CVE-2026-7000')",
        )
        .execute(&pool)
        .await
        .unwrap();
        // OSV links DSA-5000-1; a stale NVD link sits on the smaller id.
        sqlx::query(
            "insert into component_advisories values ($1, 'DSA-5000-1', 'osv'), \
             ($1, 'DEBIAN-CVE-2026-7000', 'nvd')",
        )
        .bind(cid)
        .execute(&pool)
        .await
        .unwrap();

        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        assert_eq!(
            links(&pool).await,
            [("DSA-5000-1".to_string(), "both".to_string())]
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn nvd_only_link_marked(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(
            &server,
            page_with("CVE-2026-7001", 7.5, "postgresql:postgresql"),
        )
        .await;
        mock_backfill(&server, empty_page(), 1).await;
        seed_pg(&pool).await;

        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        let (id, cve, source, sev, scores): (String, Option<String>, String, String, Value) =
            sqlx::query_as("select id, cve_id, source, severity, scores from advisories")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(
            (id.as_str(), cve.as_deref()),
            ("CVE-2026-7001", Some("CVE-2026-7001"))
        );
        assert_eq!((source.as_str(), sev.as_str()), ("nvd", "high"));
        assert_eq!(scores, json!({"nvd": 7.5}));
        assert_eq!(
            links(&pool).await,
            [("CVE-2026-7001".to_string(), "nvd".to_string())]
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn backfill_once_per_product(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(&server, empty_page()).await;
        // expect(1): the second refresh must not backfill again.
        mock_backfill(
            &server,
            serde_json::from_str(include_str!(
                "../../tests/fixtures/nvd/backfill_postgresql.json"
            ))
            .unwrap(),
            1,
        )
        .await;
        seed_pg(&pool).await;

        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        assert_eq!(
            links(&pool).await,
            [("CVE-2025-3001".to_string(), "nvd".to_string())]
        );
        let done: i64 = sqlx::query_scalar(
            "select count(*) from nvd_products where vendor_product = 'postgresql:postgresql' and backfilled_at is not null",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(done, 1);
        refresh(&pool, &client(&server), &[], at(14)).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn failed_refresh_keeps_window(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503).insert_header("Retry-After", "0"))
            .mount(&server)
            .await;
        seed_pg(&pool).await;
        sqlx::query("insert into kv values ('nvd_last', '2026-11-10T00:00:00+00:00')")
            .execute(&pool)
            .await
            .unwrap();
        assert!(refresh(&pool, &client(&server), &[], at(13)).await.is_err());
        let last: String = sqlx::query_scalar("select value from kv where key = 'nvd_last'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(last, "2026-11-10T00:00:00+00:00");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn missing_vulnerabilities_array_is_error(pool: PgPool) {
        // A 200 that is not a CVE page (a maintenance notice, a proxy page).
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"message": "maintenance"})),
            )
            .mount(&server)
            .await;
        sqlx::query("insert into kv values ('nvd_last', '2026-11-10T00:00:00+00:00')")
            .execute(&pool)
            .await
            .unwrap();
        assert!(refresh(&pool, &client(&server), &[], at(13)).await.is_err());
        let last: String = sqlx::query_scalar("select value from kv where key = 'nvd_last'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            last, "2026-11-10T00:00:00+00:00",
            "the window does not move"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn window_overlaps_previous_end(pool: PgPool) {
        // A CVE NVD indexed late with a lastModified just before our last
        // end would fall between two windows; 15 minutes of overlap catch it.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param(
                "lastModStartDate",
                "2026-11-09T23:45:00.000+00:00",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .expect(1)
            .mount(&server)
            .await;
        sqlx::query("insert into kv values ('nvd_last', '2026-11-10T00:00:00+00:00')")
            .execute(&pool)
            .await
            .unwrap();
        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn success_moves_window_and_first_run_looks_back_a_day(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(query_param(
                "lastModStartDate",
                "2026-11-12T00:00:00.000+00:00",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .expect(1)
            .mount(&server)
            .await;
        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        let last: String = sqlx::query_scalar("select value from kv where key = 'nvd_last'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(last.parse::<DateTime<Utc>>().unwrap(), at(13));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn range_change_drops_nvd_link_and_both_reverts_to_osv(pool: PgPool) {
        let server = MockServer::start().await;
        // CVE-A (nvd-only) and CVE-B (merged into an OSV advisory) now only
        // affect versions >= 20, so postgresql 16.4 no longer matches.
        let moved = |id: &str| {
            let mut p = page_with(id, 9.0, "postgresql:postgresql");
            p["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
                ["versionStartIncluding"] = json!("20.0");
            p["vulnerabilities"][0]["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
                ["versionEndExcluding"] = json!("21.0");
            p
        };
        let mut both = moved("CVE-2026-8000");
        both["vulnerabilities"].as_array_mut().unwrap().extend(
            moved("CVE-2026-8001")["vulnerabilities"]
                .as_array()
                .unwrap()
                .clone(),
        );
        both["totalResults"] = json!(2);
        mock_changed(&server, both).await;
        mock_backfill(&server, empty_page(), 1).await;
        let cid = seed_pg(&pool).await;
        for (id, src, ms) in [("CVE-2026-8000", "nvd", "nvd"), ("GHSA-b", "osv", "both")] {
            let cve = if id == "GHSA-b" { "CVE-2026-8001" } else { id };
            sqlx::query("insert into advisories (id, severity, source, cve_id, scores) values ($1, 'high', $2, $3, '{\"nvd\": 9.0}')")
                .bind(id).bind(src).bind(cve).execute(&pool).await.unwrap();
            sqlx::query("insert into component_advisories values ($1, $2, $3)")
                .bind(cid)
                .bind(id)
                .bind(ms)
                .execute(&pool)
                .await
                .unwrap();
        }
        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        assert_eq!(
            links(&pool).await,
            [("GHSA-b".to_string(), "osv".to_string())]
        );
        // The nvd-only advisory has no link left and is removed.
        let n: i64 =
            sqlx::query_scalar("select count(*) from advisories where id = 'CVE-2026-8000'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(n, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn configured_target_cpe_applies_to_generic_component(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(&server, page_with("CVE-2026-7100", 8.0, "acme:gizmo")).await;
        Mock::given(method("GET"))
            .and(query_param("virtualMatchString", "cpe:2.3:*:acme:gizmo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .expect(1)
            .mount(&server)
            .await;
        // No cpes on the component itself: only the configured target has one.
        sqlx::query(
            "insert into components (purl, name_key, ecosystem, version) \
             values ('pkg:generic/gizmo@16.1', 'pkg:generic/gizmo', 'generic', '16.1')",
        )
        .execute(&pool)
        .await
        .unwrap();
        let targets = vec![(
            "gizmo".to_string(),
            "cpe:2.3:a:acme:gizmo:*:*:*:*:*:*:*:*".to_string(),
        )];
        let report = refresh(&pool, &client(&server), &targets, at(13))
            .await
            .unwrap();
        assert_eq!(report.matched, 1);
        assert_eq!(
            links(&pool).await,
            [("CVE-2026-7100".to_string(), "nvd".to_string())]
        );
    }

    async fn seed_generic(pool: &PgPool, name: &str, version: &str, cpe: &str) -> i64 {
        sqlx::query_scalar(
            "insert into components (purl, name_key, ecosystem, version, cpes) \
             values ($1, $2, 'generic', $3, $4) returning id",
        )
        .bind(format!("pkg:generic/{name}@{version}"))
        .bind(format!("pkg:generic/{name}"))
        .bind(version)
        .bind(vec![cpe.to_string()])
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn new_version_triggers_rebackfill(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(&server, empty_page()).await;
        // Once for 16.4, once more when 15.2 appears; not on a third run.
        mock_backfill(
            &server,
            serde_json::from_str(include_str!(
                "../../tests/fixtures/nvd/backfill_postgresql.json"
            ))
            .unwrap(),
            2,
        )
        .await;
        seed_pg(&pool).await;
        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        let old = seed_generic(
            &pool,
            "postgresql-old",
            "15.2",
            "cpe:2.3:a:postgresql:postgresql:15.2:*:*:*:*:*:*:*",
        )
        .await;
        refresh(&pool, &client(&server), &[], at(14)).await.unwrap();
        refresh(&pool, &client(&server), &[], at(15)).await.unwrap();

        let versions: Vec<String> = sqlx::query_scalar(
            "select versions from nvd_products where vendor_product = 'postgresql:postgresql'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(versions, ["15.2", "16.4"]);
        let linked: i64 =
            sqlx::query_scalar("select count(*) from component_advisories where component_id = $1")
                .bind(old)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(linked, 1);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn backfill_failure_isolated(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(&server, empty_page()).await;
        Mock::given(method("GET"))
            .and(query_param(
                "virtualMatchString",
                "cpe:2.3:*:postgresql:postgresql",
            ))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(query_param("virtualMatchString", "cpe:2.3:*:acme:gizmo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .mount(&server)
            .await;
        seed_pg(&pool).await;
        seed_generic(
            &pool,
            "gizmo",
            "1.0",
            "cpe:2.3:a:acme:gizmo:1.0:*:*:*:*:*:*:*",
        )
        .await;

        refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        let last: Option<String> =
            sqlx::query_scalar("select value from kv where key = 'nvd_last'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        assert!(last.is_some(), "window must advance");
        let recorded: Vec<String> =
            sqlx::query_scalar("select vendor_product from nvd_products order by 1")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(recorded, ["acme:gizmo"]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn escaped_product_is_sent_to_nvd_as_written(pool: PgPool) {
        let server = MockServer::start().await;
        mock_changed(&server, empty_page()).await;
        Mock::given(method("GET"))
            .and(query_param("virtualMatchString", r"cpe:2.3:*:gnu:g\+\+"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page_with(
                "CVE-2026-7200",
                7.0,
                r"gnu:g\+\+",
            )))
            .expect(1)
            .mount(&server)
            .await;
        let cpe = r"cpe:2.3:a:gnu:g\+\+:16.1:*:*:*:*:*:*:*";
        seed_generic(&pool, "gpp", "16.1", cpe).await;
        let report = refresh(&pool, &client(&server), &[], at(13)).await.unwrap();
        assert_eq!(report.matched, 1);
        let p: String = sqlx::query_scalar("select vendor_product from nvd_products")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(p, r"gnu:g\+\+");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn nvd_then_osv_same_cve_counts_once(pool: PgPool) {
        // NVD runs first and stores CVE-2026-5000 under its own id.
        let nvd_server = MockServer::start().await;
        mock_changed(&nvd_server, page_with("CVE-2026-5000", 9.8, "acme:widget")).await;
        mock_backfill_for(&nvd_server, "acme:widget").await;
        let cid: i64 = sqlx::query_scalar(
            "insert into components (purl, name_key, ecosystem, version, cpes) \
             values ('pkg:npm/widget@16.1.0', 'pkg:npm/widget', 'npm', '16.1.0', $1) returning id",
        )
        .bind(vec![
            "cpe:2.3:a:acme:widget:16.1.0:*:*:*:*:*:*:*".to_string()
        ])
        .fetch_one(&pool)
        .await
        .unwrap();
        refresh(&pool, &client(&nvd_server), &[], at(13))
            .await
            .unwrap();
        assert_eq!(
            links(&pool).await,
            [("CVE-2026-5000".to_string(), "nvd".to_string())]
        );

        // Then OSV learns the same CVE under a GHSA id (High).
        let osv_server = MockServer::start().await;
        let record = json!({
            "id": "GHSA-dup", "modified": "2026-05-01T00:00:00Z",
            "aliases": ["CVE-2026-5000"], "summary": "dup",
            "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "npm", "name": "widget"},
                          "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]
        });
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "GHSA-dup", "modified": "2026-05-01T00:00:00Z"}]}]
            })))
            .mount(&osv_server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/GHSA-dup"))
            .respond_with(ResponseTemplate::new(200).set_body_json(record))
            .mount(&osv_server)
            .await;
        let osv_client = crate::vuln::osv::OsvClient {
            base: Url::parse(&osv_server.uri()).unwrap(),
            http: reqwest::Client::new(),
        };
        crate::vuln::osv::refresh(&pool, &osv_client, &[(cid, "pkg:npm/widget@16.1.0".into())])
            .await
            .unwrap();

        let rows: Vec<(String, String, Value)> =
            sqlx::query_as("select id, severity, scores from advisories")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].0, "GHSA-dup");
        assert_eq!(rows[0].1, "critical");
        assert_eq!(rows[0].2["nvd"], json!(9.8));
        assert_eq!(
            links(&pool).await,
            [("GHSA-dup".to_string(), "both".to_string())]
        );
    }

    async fn mock_backfill_for(server: &MockServer, product: &str) {
        Mock::given(method("GET"))
            .and(query_param(
                "virtualMatchString",
                format!("cpe:2.3:*:{product}"),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(empty_page()))
            .mount(server)
            .await;
    }
}
