//! OSV.dev client and advisory refresh.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use url::Url;

use crate::model::Severity;
use crate::purl::{name_key, osv_package, OsvPackage};
use crate::vuln::collapse::{self, AliasInfo, Known};
use crate::vuln::{nvd, retry, severity};

const BATCH_SIZE: usize = 1000;
/// Safety valve against a server that keeps returning page tokens.
const MAX_PAGES: usize = 100;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct OsvHit {
    pub id: String,
    pub modified: DateTime<Utc>,
}

#[derive(Deserialize)]
struct BatchResponse {
    results: Vec<BatchResult>,
}

#[derive(Deserialize, Default)]
struct BatchResult {
    #[serde(default)]
    vulns: Vec<OsvHit>,
    next_page_token: Option<String>,
}

#[derive(Clone)]
pub struct OsvClient {
    pub base: Url,
    pub http: reqwest::Client,
}

impl OsvClient {
    pub fn new(http: reqwest::Client) -> OsvClient {
        OsvClient {
            base: Url::parse("https://api.osv.dev").expect("static url"),
            http,
        }
    }

    /// One result list per input package, in the same order.
    pub async fn query_batch(&self, pkgs: &[OsvPackage]) -> anyhow::Result<Vec<Vec<OsvHit>>> {
        let mut out = Vec::with_capacity(pkgs.len());
        for chunk in pkgs.chunks(BATCH_SIZE) {
            out.extend(self.query_chunk(chunk).await?);
        }
        Ok(out)
    }

    async fn query_chunk(&self, chunk: &[OsvPackage]) -> anyhow::Result<Vec<Vec<OsvHit>>> {
        let url = self.base.join("v1/querybatch")?;
        let mut hits: Vec<Vec<OsvHit>> = vec![Vec::new(); chunk.len()];
        // Page token per query index; None on the first round.
        let mut pending: Vec<(usize, Option<String>)> =
            (0..chunk.len()).map(|i| (i, None)).collect();

        for _ in 0..MAX_PAGES {
            if pending.is_empty() {
                break;
            }
            let queries: Vec<Value> = pending
                .iter()
                .map(|(i, token)| {
                    let p = &chunk[*i];
                    let mut q = json!({
                        "package": {"name": p.name, "ecosystem": p.ecosystem},
                        "version": p.version,
                    });
                    if let Some(t) = token {
                        q["page_token"] = json!(t);
                    }
                    q
                })
                .collect();
            let body = json!({ "queries": queries });
            let resp: BatchResponse =
                retry::send("osv querybatch", || self.http.post(url.clone()).json(&body))
                    .await?
                    .json()
                    .await
                    .context("osv querybatch body")?;
            if resp.results.len() != pending.len() {
                return Err(anyhow!(
                    "osv returned {} results for {} queries",
                    resp.results.len(),
                    pending.len()
                ));
            }
            // Only queries that came back with a token are asked again.
            let mut next = Vec::new();
            for ((i, _), result) in pending.iter().zip(resp.results) {
                hits[*i].extend(result.vulns);
                if let Some(t) = result.next_page_token.filter(|t| !t.is_empty()) {
                    next.push((*i, Some(t)));
                }
            }
            pending = next;
        }
        // Returning what we have would make the caller treat it as complete
        // and delete the links of the advisories that were cut off.
        if !pending.is_empty() {
            return Err(anyhow!(
                "osv querybatch still had page tokens after {MAX_PAGES} pages"
            ));
        }
        Ok(hits)
    }

    pub async fn get(&self, id: &str) -> anyhow::Result<Value> {
        // Build the path by segment so odd characters in an id are encoded.
        let mut url = self.base.clone();
        url.path_segments_mut()
            .map_err(|_| anyhow!("osv base url cannot be a base"))?
            .pop_if_empty()
            .extend(["v1", "vulns", id]);
        retry::send(&format!("osv get {id}"), || self.http.get(url.clone()))
            .await?
            .json()
            .await
            .with_context(|| format!("osv get {id} body"))
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RefreshReport {
    /// Components OSV could be asked about (purl maps to an OSV ecosystem).
    pub checked: usize,
    pub new_links: usize,
    /// Full advisory records downloaded.
    pub fetched: usize,
}

/// A component we asked OSV about.
struct Checked {
    component_id: i64,
    name_key: String,
    pkg: OsvPackage,
}

/// The parts of an existing advisory row that decide whether to refetch,
/// and what it is also known as.
#[derive(sqlx::FromRow)]
struct Stored {
    id: String,
    modified: DateTime<Utc>,
    fixed: Value,
    severity: Severity,
    has_nvd: bool,
    aliases: Vec<String>,
    cve_id: Option<String>,
}

/// What we keep per advisory before it is written.
struct Advisory {
    id: String,
    aliases: Vec<String>,
    severity: Severity,
    summary: String,
    fixed: BTreeMap<String, Vec<String>>,
    modified: DateTime<Utc>,
    score: Option<f64>,
    cve_id: Option<String>,
}

/// Ask OSV about every component, upsert the advisories it reports and replace
/// the OSV links of the checked components. NVD-only links are left alone.
/// Records that describe one vulnerability (see `collapse`) give one link,
/// to the group's canonical advisory.
pub async fn refresh(
    pool: &PgPool,
    client: &OsvClient,
    components: &[(i64, String)],
) -> anyhow::Result<RefreshReport> {
    let mut checked = Vec::new();
    for (component_id, purl) in components {
        if let Some(pkg) = osv_package(purl) {
            checked.push(Checked {
                component_id: *component_id,
                name_key: name_key(purl)?,
                pkg,
            });
        }
    }
    let pkgs: Vec<OsvPackage> = checked.iter().map(|c| c.pkg.clone()).collect();
    let all_hits = client.query_batch(&pkgs).await?;

    // advisory id -> newest `modified` reported, and which checked components hit it.
    let mut newest: HashMap<String, DateTime<Utc>> = HashMap::new();
    let mut hit_by: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, hits) in all_hits.iter().enumerate() {
        for hit in hits {
            let e = newest.entry(hit.id.clone()).or_insert(hit.modified);
            *e = (*e).max(hit.modified);
            hit_by.entry(hit.id.clone()).or_default().push(idx);
        }
    }

    let ids: Vec<String> = newest.keys().cloned().collect();
    let stored: HashMap<String, Stored> = sqlx::query_as::<_, Stored>(
        "select id, modified, fixed, severity, scores ? 'nvd' as has_nvd, aliases, cve_id \
         from advisories where id = any($1)",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|s| (s.id.clone(), s))
    .collect();

    let mut fetched = Vec::new();
    for (id, modified) in &newest {
        // `fixed` has a key for every component that was ever checked against
        // the advisory (empty list when there is no fix), so a missing key
        // means a new component and the record must be read again.
        let up_to_date = stored.get(id).is_some_and(|st| {
            st.modified >= *modified
                && hit_by[id]
                    .iter()
                    .all(|i| st.fixed.get(&checked[*i].name_key).is_some())
        });
        if up_to_date {
            continue;
        }
        let vuln = client.get(id).await?;
        let keys: Vec<&Checked> = hit_by[id].iter().map(|i| &checked[*i]).collect();
        let mut adv = build_advisory(&vuln, &keys)?;
        // NVD may already have raised the severity; an OSV refresh must not lower it.
        if let Some(st) = stored.get(id).filter(|st| st.has_nvd) {
            adv.severity = severity::merge(adv.severity, st.severity);
        }
        fetched.push(adv);
    }

    // Collapse each component's hits to one advisory per vulnerability. An
    // advisory already linked to ANY component keeps standing for its group,
    // so findings (keyed by advisory, not version) never move to another id:
    // not when a record joins, not for a new version or another service.
    let known = known_advisories(&stored, &fetched)?;
    let linked: HashSet<String> = sqlx::query_scalar(
        "select distinct advisory_id from component_advisories where advisory_id = any($1)",
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?
    .into_iter()
    .collect();
    // What each checked component is linked to now: its own link in a group
    // beats one elsewhere, so records that disagree on affected ranges (one
    // component hits GHSA only, another PYSEC and GHSA) never re-key it.
    let checked_ids: Vec<i64> = checked.iter().map(|c| c.component_id).collect();
    let mut own: HashMap<i64, HashSet<String>> = HashMap::new();
    let rows: Vec<(i64, String)> = sqlx::query_as(
        "select component_id, advisory_id from component_advisories \
         where component_id = any($1) and advisory_id = any($2)",
    )
    .bind(&checked_ids)
    .bind(&ids)
    .fetch_all(pool)
    .await?;
    for (cid, aid) in rows {
        own.entry(cid).or_default().insert(aid);
    }
    let none = HashSet::new();
    let mut merged = BTreeMap::new();
    let mut desired: BTreeSet<(i64, String)> = BTreeSet::new();
    for (c, hits) in checked.iter().zip(&all_hits) {
        let mut hit_ids: Vec<String> = hits.iter().map(|h| h.id.clone()).collect();
        hit_ids.sort();
        hit_ids.dedup();
        let mine = own.get(&c.component_id).unwrap_or(&none);
        for id in collapse::collapse_hits(&hit_ids, &c.name_key, &known, mine, &linked, &mut merged)
        {
            desired.insert((c.component_id, id));
        }
    }

    let mut tx = pool.begin().await?;
    for adv in &fetched {
        upsert_advisory(&mut tx, adv).await?;
    }
    collapse::store_merged(&mut tx, &merged).await?;
    let before: BTreeSet<(i64, String)> = sqlx::query_as::<_, (i64, String)>(
        "select component_id, advisory_id from component_advisories \
         where component_id = any($1) and match_source in ('osv', 'both')",
    )
    .bind(&checked_ids)
    .fetch_all(&mut *tx)
    .await?
    .into_iter()
    .collect();

    // Drop OSV's side of every link first, then re-add what OSV reports now:
    // osv rows vanish, both -> nvd, and the insert below turns nvd -> both again.
    sqlx::query(
        "delete from component_advisories where component_id = any($1) and match_source = 'osv'",
    )
    .bind(&checked_ids)
    .execute(&mut *tx)
    .await?;
    sqlx::query("update component_advisories set match_source = 'nvd' where component_id = any($1) and match_source = 'both'")
        .bind(&checked_ids)
        .execute(&mut *tx)
        .await?;
    let (cids, aids): (Vec<i64>, Vec<String>) = desired.iter().cloned().unzip();
    sqlx::query(
        "insert into component_advisories (component_id, advisory_id, match_source) \
         select c, a, 'osv' from unnest($1::bigint[], $2::text[]) as t(c, a) \
         on conflict (component_id, advisory_id) do update set match_source = 'both'",
    )
    .bind(&cids)
    .bind(&aids)
    .execute(&mut *tx)
    .await?;
    // NVD may have stored this CVE under its own id before OSV knew it. Fold
    // only now that OSV's links are in: a component linked for the first time
    // then moves its NVD link onto the advisory OSV just linked it to, not
    // onto the CVE's canonical row across all ecosystems (a second link).
    for adv in &fetched {
        if let Some(cve) = &adv.cve_id {
            nvd::fold_duplicates(&mut tx, cve).await?;
        }
    }
    tx.commit().await?;

    Ok(RefreshReport {
        checked: checked.len(),
        new_links: desired.difference(&before).count(),
        fetched: fetched.len(),
    })
}

/// What each hit advisory is also known as, with its severity and fixed
/// versions: from the fresh record when it was fetched, else the stored row.
fn known_advisories(
    stored: &HashMap<String, Stored>,
    fetched: &[Advisory],
) -> anyhow::Result<HashMap<String, Known>> {
    let mut known = HashMap::new();
    for adv in fetched {
        let info = AliasInfo {
            id: adv.id.clone(),
            aliases: adv.aliases.clone(),
            cve_id: adv.cve_id.clone(),
        };
        let fixed = serde_json::to_value(&adv.fixed)?;
        known.insert(
            adv.id.clone(),
            Known {
                info,
                severity: adv.severity,
                fixed,
            },
        );
    }
    for (id, st) in stored {
        known.entry(id.clone()).or_insert_with(|| Known {
            info: AliasInfo {
                id: id.clone(),
                aliases: st.aliases.clone(),
                cve_id: st.cve_id.clone(),
            },
            severity: st.severity,
            fixed: st.fixed.clone(),
        });
    }
    Ok(known)
}

async fn upsert_advisory(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    adv: &Advisory,
) -> anyhow::Result<()> {
    let scores = match adv.score {
        Some(s) => json!({ "osv": s }),
        None => json!({}),
    };
    // `fixed` is merged so keys from other components survive; `scores` keeps
    // an existing NVD score while the osv key is replaced (or dropped).
    sqlx::query(
        "insert into advisories (id, aliases, severity, summary, fixed, modified, source, scores, cve_id) \
         values ($1, $2, $3, $4, $5, $6, 'osv', $7, $8) \
         on conflict (id) do update set \
           aliases = excluded.aliases, \
           severity = excluded.severity, \
           summary = excluded.summary, \
           fixed = advisories.fixed || excluded.fixed, \
           modified = excluded.modified, \
           scores = (advisories.scores - 'osv') || excluded.scores, \
           cve_id = excluded.cve_id",
    )
    .bind(&adv.id)
    .bind(&adv.aliases)
    .bind(adv.severity)
    .bind(&adv.summary)
    .bind(serde_json::to_value(&adv.fixed)?)
    .bind(adv.modified)
    .bind(scores)
    .bind(&adv.cve_id)
    .execute(&mut **tx)
    .await
    .with_context(|| format!("upserting advisory {}", adv.id))?;
    Ok(())
}

/// A record's id, aliases and the CVE it is about (the id itself when it is
/// a CVE, else the first CVE alias).
pub(crate) fn record_names(vuln: &Value) -> anyhow::Result<AliasInfo> {
    let id = vuln["id"]
        .as_str()
        .context("osv record without id")?
        .to_string();
    let aliases: Vec<String> = vuln["aliases"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let cve_id = std::iter::once(&id)
        .chain(aliases.iter())
        .find(|a| is_cve_id(a))
        .cloned();
    Ok(AliasInfo {
        id,
        aliases,
        cve_id,
    })
}

fn build_advisory(vuln: &Value, hitting: &[&Checked]) -> anyhow::Result<Advisory> {
    let AliasInfo {
        id,
        aliases,
        cve_id,
    } = record_names(vuln)?;
    let modified = vuln["modified"]
        .as_str()
        .context("osv record without modified")?
        .parse::<DateTime<Utc>>()
        .context("osv modified is not RFC 3339")?;
    let summary = match vuln["summary"].as_str() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => vuln["details"]
            .as_str()
            .unwrap_or("")
            .lines()
            .next()
            .unwrap_or("")
            .to_string(),
    };
    let mut fixed = BTreeMap::new();
    for c in hitting {
        fixed.insert(c.name_key.clone(), fixed_versions(vuln, &c.pkg));
    }
    Ok(Advisory {
        severity: severity::normalize(vuln),
        score: severity::cvss_score(vuln),
        id,
        aliases,
        summary,
        fixed,
        modified,
        cve_id,
    })
}

/// `^CVE-\d{4}-\d+$` without pulling in the regex crate.
pub(crate) fn is_cve_id(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("CVE-") else {
        return false;
    };
    let Some((year, seq)) = rest.split_once('-') else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && !seq.is_empty()
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// `fixed` events of the `affected[]` entries for exactly this package,
/// first-seen order, no duplicates.
pub(crate) fn fixed_versions(vuln: &Value, pkg: &OsvPackage) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let affected = vuln["affected"].as_array().into_iter().flatten();
    for a in affected {
        if a["package"]["ecosystem"] != pkg.ecosystem.as_str()
            || a["package"]["name"] != pkg.name.as_str()
        {
            continue;
        }
        let events = a["ranges"]
            .as_array()
            .into_iter()
            .flatten()
            .flat_map(|r| r["events"].as_array().into_iter().flatten());
        for e in events {
            if let Some(f) = e["fixed"].as_str() {
                if !out.iter().any(|x| x == f) {
                    out.push(f.to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};
    use sqlx::PgPool;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    const CVSS_ID: &str = "GHSA-h7vf-3kq9-m2wx";
    const WORDS_ID: &str = "GHSA-9c4p-j6rt-v5nz";
    const PURL: &str = "pkg:npm/widget@1.2.0";
    const NAME_KEY: &str = "pkg:npm/widget";

    fn fixture(s: &str) -> Value {
        serde_json::from_str(s).unwrap()
    }

    async fn osv_mock() -> (MockServer, OsvClient) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(fixture(include_str!(
                    "../../tests/fixtures/osv/querybatch.json"
                ))),
            )
            .mount(&server)
            .await;
        for (id, body) in [
            (
                CVSS_ID,
                include_str!("../../tests/fixtures/osv/GHSA-h7vf-3kq9-m2wx.json"),
            ),
            (
                WORDS_ID,
                include_str!("../../tests/fixtures/osv/GHSA-9c4p-j6rt-v5nz.json"),
            ),
        ] {
            // expect(1): a second refresh with unchanged `modified` must not refetch.
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{id}")))
                .respond_with(ResponseTemplate::new(200).set_body_json(fixture(body)))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client = OsvClient {
            base: Url::parse(&server.uri()).unwrap(),
            http: reqwest::Client::new(),
        };
        (server, client)
    }

    async fn seed_component(pool: &PgPool, purl: &str) -> i64 {
        sqlx::query_scalar(
            "insert into components (purl, name_key, ecosystem, version) \
             values ($1, $2, 'npm', '1.2.0') returning id",
        )
        .bind(purl)
        .bind(NAME_KEY)
        .fetch_one(pool)
        .await
        .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn refresh_links_and_skips_unchanged(pool: PgPool) {
        let (_server, client) = osv_mock().await;
        let cid = seed_component(&pool, PURL).await;
        let comps = vec![(cid, PURL.to_string())];

        let first = refresh(&pool, &client, &comps).await.unwrap();
        assert_eq!(
            first,
            RefreshReport {
                checked: 1,
                new_links: 2,
                fetched: 2
            }
        );
        let linked: i64 = sqlx::query_scalar(
            "select count(*) from component_advisories where component_id = $1 and match_source = 'osv'",
        )
        .bind(cid)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(linked, 2);

        let second = refresh(&pool, &client, &comps).await.unwrap();
        assert_eq!(second.fetched, 0);
        assert_eq!(second.new_links, 0);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fixed_versions_recorded(pool: PgPool) {
        let (_server, client) = osv_mock().await;
        let cid = seed_component(&pool, PURL).await;
        refresh(&pool, &client, &[(cid, PURL.to_string())])
            .await
            .unwrap();
        let fixed: Value = sqlx::query_scalar("select fixed from advisories where id = $1")
            .bind(CVSS_ID)
            .fetch_one(&pool)
            .await
            .unwrap();
        // Only the queried package's events count, not `other-package`'s.
        assert_eq!(fixed[NAME_KEY], json!(["1.9.1"]));
        assert_eq!(fixed.as_object().unwrap().len(), 1);
        let no_fix: Value = sqlx::query_scalar("select fixed from advisories where id = $1")
            .bind(WORDS_ID)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(no_fix[NAME_KEY], json!([]));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn cve_alias_recorded(pool: PgPool) {
        let (_server, client) = osv_mock().await;
        let cid = seed_component(&pool, PURL).await;
        refresh(&pool, &client, &[(cid, PURL.to_string())])
            .await
            .unwrap();
        let (cve, scores, sev): (Option<String>, Value, String) =
            sqlx::query_as("select cve_id, scores, severity from advisories where id = $1")
                .bind(CVSS_ID)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cve.as_deref(), Some("CVE-2026-1111"));
        assert_eq!(scores["osv"], json!(9.8));
        assert_eq!(sev, "critical");
        let (cve, scores): (Option<String>, Value) =
            sqlx::query_as("select cve_id, scores from advisories where id = $1")
                .bind(WORDS_ID)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(cve, None);
        assert!(scores.get("osv").is_none());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn nvd_links_survive_and_both_reverts(pool: PgPool) {
        let (_server, client) = osv_mock().await;
        let cid = seed_component(&pool, PURL).await;
        let comps = vec![(cid, PURL.to_string())];
        refresh(&pool, &client, &comps).await.unwrap();

        // An NVD-only advisory, and an NVD link on an advisory OSV reports.
        sqlx::query(
            "insert into advisories (id, severity, source) values ('CVE-2026-9999', 'high', 'nvd')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("insert into component_advisories values ($1, 'CVE-2026-9999', 'nvd')")
            .bind(cid)
            .execute(&pool)
            .await
            .unwrap();
        // Pretend NVD also matched the CVSS advisory.
        sqlx::query("update component_advisories set match_source = 'both' where advisory_id = $1")
            .bind(CVSS_ID)
            .execute(&pool)
            .await
            .unwrap();

        refresh(&pool, &client, &comps).await.unwrap();
        let rows: Vec<(String, String)> = sqlx::query_as(
            "select advisory_id, match_source from component_advisories order by advisory_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert!(rows.contains(&("CVE-2026-9999".into(), "nvd".into())));
        assert!(rows.contains(&(CVSS_ID.into(), "both".into())));
        assert!(rows.contains(&(WORDS_ID.into(), "osv".into())));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn both_goes_back_to_nvd_when_osv_drops_it(pool: PgPool) {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"results": [{}]})))
            .mount(&server)
            .await;
        let client = OsvClient {
            base: Url::parse(&server.uri()).unwrap(),
            http: reqwest::Client::new(),
        };
        let cid = seed_component(&pool, PURL).await;
        sqlx::query(
            "insert into advisories (id, severity, source) values ('GHSA-gone', 'high', 'osv')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("insert into component_advisories values ($1, 'GHSA-gone', 'both')")
            .bind(cid)
            .execute(&pool)
            .await
            .unwrap();
        refresh(&pool, &client, &[(cid, PURL.to_string())])
            .await
            .unwrap();
        let ms: String = sqlx::query_scalar(
            "select match_source from component_advisories where advisory_id = 'GHSA-gone'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ms, "nvd");
    }

    #[tokio::test]
    async fn query_batch_follows_page_tokens() {
        let server = MockServer::start().await;
        // Page 1 has a token; page 2 (request carries the token) has none.
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .and(wiremock::matchers::body_partial_json(
                json!({"queries": [{"page_token": "t2"}]}),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": "B", "modified": "2026-01-02T00:00:00Z"}]}]
            })))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [{"id": "A", "modified": "2026-01-01T00:00:00Z"}],
                    "next_page_token": "t2"
                }]
            })))
            .mount(&server)
            .await;
        let client = OsvClient {
            base: Url::parse(&server.uri()).unwrap(),
            http: reqwest::Client::new(),
        };
        let pkg = OsvPackage {
            ecosystem: "npm".into(),
            name: "widget".into(),
            version: "1.2.0".into(),
        };
        let hits = client.query_batch(&[pkg]).await.unwrap();
        let ids: Vec<&str> = hits[0].iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["A", "B"]);
    }

    #[tokio::test]
    async fn query_batch_page_cap_errors() {
        let server = MockServer::start().await;
        // Every page carries a token, so the loop can only end at the cap.
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{
                    "vulns": [{"id": "A", "modified": "2026-01-01T00:00:00Z"}],
                    "next_page_token": "again"
                }]
            })))
            .mount(&server)
            .await;
        let client = OsvClient {
            base: Url::parse(&server.uri()).unwrap(),
            http: reqwest::Client::new(),
        };
        let pkg = OsvPackage {
            ecosystem: "npm".into(),
            name: "widget".into(),
            version: "1.2.0".into(),
        };
        let err = client.query_batch(&[pkg]).await.unwrap_err();
        assert!(format!("{err:#}").contains("page"), "{err:#}");
    }

    #[tokio::test]
    async fn get_retries_on_429_then_succeeds() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/X"))
            .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "0"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1/vulns/X"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"id": "X"})))
            .expect(1)
            .mount(&server)
            .await;
        let client = OsvClient {
            base: Url::parse(&server.uri()).unwrap(),
            http: reqwest::Client::new(),
        };
        assert_eq!(client.get("X").await.unwrap()["id"], "X");
    }

    /// An OSV record for `widget` with the given severity word and optional fix.
    fn osv_record(id: &str, modified: &str, word: &str, fixed: Option<&str>) -> Value {
        let mut events = vec![json!({"introduced": "0"})];
        if let Some(f) = fixed {
            events.push(json!({"fixed": f}));
        }
        json!({
            "id": id,
            "modified": modified,
            "aliases": ["CVE-2026-5000"],
            "summary": "test",
            "database_specific": {"severity": word},
            "affected": [{
                "package": {"ecosystem": "npm", "name": "widget"},
                "ranges": [{"type": "SEMVER", "events": events}]
            }]
        })
    }

    /// Mount querybatch (one hit) and the record for `id`.
    async fn mount_record(server: &MockServer, record: &Value, expect_get: u64) {
        let id = record["id"].as_str().unwrap();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [{"id": id, "modified": record["modified"]}]}]
            })))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/vulns/{id}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(record))
            .expect(expect_get)
            .mount(server)
            .await;
    }

    fn client_for(server: &MockServer) -> OsvClient {
        OsvClient {
            base: Url::parse(&server.uri()).unwrap(),
            http: reqwest::Client::new(),
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_refresh_never_lowers_nvd_raised_severity(pool: PgPool) {
        let server = MockServer::start().await;
        mount_record(
            &server,
            &osv_record("GHSA-sev", "2026-05-01T00:00:00Z", "HIGH", None),
            1,
        )
        .await;
        let cid = seed_component(&pool, PURL).await;
        sqlx::query(
            "insert into advisories (id, severity, source, scores, modified, cve_id) \
             values ('GHSA-sev', 'critical', 'osv', '{\"nvd\": 9.8}', '2026-01-01T00:00:00Z', 'CVE-2026-5000')",
        )
        .execute(&pool)
        .await
        .unwrap();
        refresh(&pool, &client_for(&server), &[(cid, PURL.to_string())])
            .await
            .unwrap();
        let (sev, scores): (String, Value) =
            sqlx::query_as("select severity, scores from advisories where id = 'GHSA-sev'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sev, "critical");
        assert_eq!(scores["nvd"], json!(9.8));
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_raises_severity_without_nvd(pool: PgPool) {
        let server = MockServer::start().await;
        mount_record(
            &server,
            &osv_record("GHSA-sev", "2026-05-01T00:00:00Z", "HIGH", None),
            1,
        )
        .await;
        let cid = seed_component(&pool, PURL).await;
        sqlx::query(
            "insert into advisories (id, severity, source, modified, cve_id) \
             values ('GHSA-sev', 'medium', 'osv', '2026-01-01T00:00:00Z', 'CVE-2026-5000')",
        )
        .execute(&pool)
        .await
        .unwrap();
        refresh(&pool, &client_for(&server), &[(cid, PURL.to_string())])
            .await
            .unwrap();
        let sev: String =
            sqlx::query_scalar("select severity from advisories where id = 'GHSA-sev'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(sev, "high");
    }

    /// Mount one querybatch result (all `records` hit widget) and each record.
    async fn mount_hits(server: &MockServer, records: &[&Value]) {
        server.reset().await;
        let hits: Vec<Value> = records
            .iter()
            .map(|r| json!({"id": r["id"], "modified": r["modified"]}))
            .collect();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"results": [{"vulns": hits}]})),
            )
            .mount(server)
            .await;
        for rec in records {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{}", rec["id"].as_str().unwrap())))
                .respond_with(ResponseTemplate::new(200).set_body_json(*rec))
                .mount(server)
                .await;
        }
    }

    /// widget in prod/api through the inventory store; returns its component id.
    async fn widget_in_inventory(pool: &PgPool) -> i64 {
        use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
        let sid = upsert_service(pool, "prod", "api").await.unwrap();
        let item = InventoryItem {
            purl: PURL.to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        };
        replace_components(pool, sid, crate::model::Source::Git, &[item])
            .await
            .unwrap();
        sqlx::query_scalar("select id from components where purl = $1")
            .bind(PURL)
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn vuln_keys(pool: &PgPool) -> Vec<(String, String)> {
        sqlx::query_as("select key, status from findings where kind = 'vuln' order by id")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn canonical_id_is_sticky_when_cve_alias_appears_later(pool: PgPool) {
        // PyPI's record names the CVE and GitHub's; GitHub's has no CVE yet.
        let mut pysec = osv_record("PYSEC-2026-1", "2026-05-01T00:00:00Z", "HIGH", None);
        pysec["aliases"] = json!(["CVE-2026-5000", "GHSA-xxxx-yyyy-zzzz"]);
        let mut ghsa = osv_record("GHSA-xxxx-yyyy-zzzz", "2026-05-01T00:00:00Z", "HIGH", None);
        ghsa["aliases"] = json!([]);
        let server = MockServer::start().await;
        let cid = widget_in_inventory(&pool).await;
        let comps = [(cid, PURL.to_string())];
        mount_hits(&server, &[&pysec, &ghsa]).await;
        refresh(&pool, &client_for(&server), &comps).await.unwrap();
        crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        let first = vuln_keys(&pool).await;
        assert_eq!(first.len(), 1);

        // GitHub adds the CVE alias. The finding keeps its key: no new card.
        ghsa["aliases"] = json!(["CVE-2026-5000"]);
        ghsa["modified"] = json!("2026-06-01T00:00:00Z");
        mount_hits(&server, &[&pysec, &ghsa]).await;
        refresh(&pool, &client_for(&server), &comps).await.unwrap();
        let report = crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(vuln_keys(&pool).await, first);
        assert!(report.opened.is_empty(), "{report:?}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn canonical_id_stays_when_a_ghsa_record_joins_later(pool: PgPool) {
        // First only PyPI's record is known; it is linked.
        let pysec = osv_record("PYSEC-2026-2", "2026-05-01T00:00:00Z", "HIGH", None);
        let mut ghsa = osv_record("GHSA-aaaa-bbbb-cccc", "2026-05-01T00:00:00Z", "HIGH", None);
        ghsa["aliases"] = json!(["CVE-2026-5000", "PYSEC-2026-2"]);
        let server = MockServer::start().await;
        let cid = widget_in_inventory(&pool).await;
        let comps = [(cid, PURL.to_string())];
        mount_hits(&server, &[&pysec]).await;
        refresh(&pool, &client_for(&server), &comps).await.unwrap();
        // GitHub's record turns up: the rule alone would pick it.
        mount_hits(&server, &[&pysec, &ghsa]).await;
        refresh(&pool, &client_for(&server), &comps).await.unwrap();
        let links: Vec<String> = sqlx::query_scalar(
            "select advisory_id from component_advisories where component_id = $1",
        )
        .bind(cid)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(links, ["PYSEC-2026-2"]);
        let (aliases, cve): (Vec<String>, Option<String>) =
            sqlx::query_as("select aliases, cve_id from advisories where id = 'PYSEC-2026-2'")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            aliases.contains(&"GHSA-aaaa-bbbb-cccc".to_string()),
            "{aliases:?}"
        );
        assert_eq!(
            cve.as_deref(),
            Some("CVE-2026-5000"),
            "the group's CVE is stored"
        );
    }

    /// Put widget@`version` in `service` (prod), alone; returns its component id.
    async fn widget_at(pool: &PgPool, service: &str, version: &str) -> (i64, String) {
        use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
        let purl = format!("pkg:npm/widget@{version}");
        let sid = upsert_service(pool, "prod", service).await.unwrap();
        let item = InventoryItem {
            purl: purl.clone(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        };
        replace_components(pool, sid, crate::model::Source::Git, &[item])
            .await
            .unwrap();
        let id = sqlx::query_scalar("select id from components where purl = $1")
            .bind(&purl)
            .fetch_one(pool)
            .await
            .unwrap();
        (id, purl)
    }

    /// PYSEC-2026-3 alone, then joined by a GHSA record that names it.
    fn pysec_then_ghsa() -> (Value, Value) {
        let pysec = osv_record("PYSEC-2026-3", "2026-05-01T00:00:00Z", "HIGH", None);
        let mut ghsa = osv_record("GHSA-dddd-eeee-ffff", "2026-05-01T00:00:00Z", "HIGH", None);
        ghsa["aliases"] = json!(["CVE-2026-5000", "PYSEC-2026-3"]);
        (pysec, ghsa)
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn version_bump_keeps_canonical_id(pool: PgPool) {
        let (pysec, ghsa) = pysec_then_ghsa();
        let server = MockServer::start().await;
        let old = widget_at(&pool, "api", "1.0.0").await;
        mount_hits(&server, &[&pysec]).await;
        refresh(&pool, &client_for(&server), &[old]).await.unwrap();
        crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        sqlx::query("update findings set notified_at = now()")
            .execute(&pool)
            .await
            .unwrap();
        let first = vuln_keys(&pool).await;

        // GitHub's record joins; the service moves to widget 1.0.1, a new
        // component no advisory was linked to yet.
        mount_hits(&server, &[&pysec, &ghsa]).await;
        let new = widget_at(&pool, "api", "1.0.1").await;
        refresh(&pool, &client_for(&server), &[new]).await.unwrap();
        let report = crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(vuln_keys(&pool).await, first, "same finding key");
        assert!(report.opened.is_empty(), "no second card: {report:?}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn second_component_converges_on_linked_id(pool: PgPool) {
        let (pysec, ghsa) = pysec_then_ghsa();
        let server = MockServer::start().await;
        let api = widget_at(&pool, "api", "1.0.0").await;
        mount_hits(&server, &[&pysec]).await;
        refresh(&pool, &client_for(&server), std::slice::from_ref(&api))
            .await
            .unwrap();

        // After GitHub's record joined, another service runs widget 1.0.1.
        mount_hits(&server, &[&pysec, &ghsa]).await;
        let web = widget_at(&pool, "web", "1.0.1").await;
        refresh(&pool, &client_for(&server), std::slice::from_ref(&web))
            .await
            .unwrap();
        crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        let refs: Vec<String> = sqlx::query_scalar(
            "select distinct ref_id from findings where kind = 'vuln' order by ref_id",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(refs, ["PYSEC-2026-3"], "one advisory id for both services");
    }

    /// Mount querybatch with one result per component, in order (`hits`
    /// indexes `records`), and every record.
    async fn mount_hits_per_component(server: &MockServer, records: &[&Value], hits: &[&[usize]]) {
        server.reset().await;
        let results: Vec<Value> = hits
            .iter()
            .map(|idx| {
                let vulns: Vec<Value> = idx
                    .iter()
                    .map(|&i| json!({"id": records[i]["id"], "modified": records[i]["modified"]}))
                    .collect();
                json!({ "vulns": vulns })
            })
            .collect();
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "results": results })))
            .mount(server)
            .await;
        for rec in records {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{}", rec["id"].as_str().unwrap())))
                .respond_with(ResponseTemplate::new(200).set_body_json(*rec))
                .mount(server)
                .await;
        }
    }

    /// Issue #12: PyPI's and GitHub's records disagree on affected ranges, so
    /// one component hits both and another GitHub's only. Once GitHub's is
    /// linked to the second, the first must keep its PyPI link, not move to
    /// GitHub's (a resolve and a new card).
    #[sqlx::test(migrations = "./migrations")]
    async fn differing_ranges_do_not_rekey_a_linked_component(pool: PgPool) {
        let pysec = osv_record("PYSEC-2026-4", "2026-05-01T00:00:00Z", "HIGH", None);
        let mut ghsa = osv_record("GHSA-gggg-hhhh-iiii", "2026-05-01T00:00:00Z", "HIGH", None);
        ghsa["aliases"] = json!(["CVE-2026-5000", "PYSEC-2026-4"]);
        let server = MockServer::start().await;
        let api = widget_at(&pool, "api", "1.0.0").await;
        let web = widget_at(&pool, "web", "1.0.1").await;
        let now = chrono::Utc::now;

        // Only PyPI's record is known: api links it.
        mount_hits_per_component(&server, &[&pysec], &[&[0]]).await;
        refresh(&pool, &client_for(&server), std::slice::from_ref(&api))
            .await
            .unwrap();
        crate::matcher::run(&pool, "prod", now()).await.unwrap();

        // GitHub's record joins: api hits both, web (outside PyPI's range) only
        // GitHub's, so web is linked to it.
        let both = [api.clone(), web.clone()];
        mount_hits_per_component(&server, &[&pysec, &ghsa], &[&[0, 1], &[1]]).await;
        refresh(&pool, &client_for(&server), &both).await.unwrap();
        crate::matcher::run(&pool, "prod", now()).await.unwrap();
        sqlx::query("update findings set notified_at = now()")
            .execute(&pool)
            .await
            .unwrap();
        let settled = vuln_keys(&pool).await;

        // Both records are now linked somewhere. Later refreshes must not
        // move api from PYSEC to GHSA.
        for _ in 0..2 {
            refresh(&pool, &client_for(&server), &both).await.unwrap();
            let report = crate::matcher::run(&pool, "prod", now()).await.unwrap();
            assert!(report.opened.is_empty(), "no new card: {report:?}");
            assert_eq!(report.resolved, 0, "nothing resolved: {report:?}");
            assert_eq!(vuln_keys(&pool).await, settled);
        }
        let api_links: Vec<String> = sqlx::query_scalar(
            "select advisory_id from component_advisories where component_id = $1",
        )
        .bind(api.0)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(api_links, ["PYSEC-2026-4"]);
    }

    /// Issue #13: NVD matched the component before OSV knew the CVE, and
    /// another ecosystem's record (sorting before ours) carries the CVE too.
    /// The first OSV link must absorb NVD's, not add a second link.
    #[sqlx::test(migrations = "./migrations")]
    async fn first_osv_link_absorbs_nvd_link_without_a_second_one(pool: PgPool) {
        let cid = widget_in_inventory(&pool).await;
        sqlx::query(
            "insert into advisories (id, severity, source, scores, cve_id) values \
             ('CVE-2026-5000', 'critical', 'nvd', '{\"nvd\": 9.8}', 'CVE-2026-5000'), \
             ('DEBIAN-CVE-2026-5000', 'high', 'osv', '{}', 'CVE-2026-5000')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("insert into component_advisories values ($1, 'CVE-2026-5000', 'nvd')")
            .bind(cid)
            .execute(&pool)
            .await
            .unwrap();

        let server = MockServer::start().await;
        let pysec = osv_record("PYSEC-2026-5", "2026-05-01T00:00:00Z", "HIGH", None);
        mount_hits(&server, &[&pysec]).await;
        refresh(&pool, &client_for(&server), &[(cid, PURL.to_string())])
            .await
            .unwrap();

        let links: Vec<(String, String)> = sqlx::query_as(
            "select advisory_id, match_source from component_advisories where component_id = $1",
        )
        .bind(cid)
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(links, [("PYSEC-2026-5".to_string(), "both".to_string())]);
        crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        let vulns = vuln_keys(&pool).await;
        assert_eq!(vulns.len(), 1, "{vulns:?}");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn osv_aliases_collapse_to_one_advisory(pool: PgPool) {
        use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
        use crate::model::{FindingKind, Source};

        // Go's database and GitHub's both publish CVE-2026-5000 for widget.
        // GitHub's is HIGH without a fix; Go's is LOW with one.
        let go = osv_record("GO-2026-0001", "2026-05-01T00:00:00Z", "LOW", Some("1.9.1"));
        let mut ghsa = osv_record("GHSA-cccc-dddd-eeee", "2026-05-01T00:00:00Z", "HIGH", None);
        ghsa["aliases"] = json!(["CVE-2026-5000", "GO-2026-0001"]);
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/querybatch"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "results": [{"vulns": [
                    {"id": go["id"], "modified": go["modified"]},
                    {"id": ghsa["id"], "modified": ghsa["modified"]},
                ]}]
            })))
            .mount(&server)
            .await;
        for rec in [&go, &ghsa] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/vulns/{}", rec["id"].as_str().unwrap())))
                .respond_with(ResponseTemplate::new(200).set_body_json(rec))
                .mount(&server)
                .await;
        }
        let sid = upsert_service(&pool, "prod", "api").await.unwrap();
        let item = InventoryItem {
            purl: PURL.to_string(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        };
        replace_components(&pool, sid, Source::Git, &[item])
            .await
            .unwrap();
        let cid: i64 = sqlx::query_scalar("select id from components where purl = $1")
            .bind(PURL)
            .fetch_one(&pool)
            .await
            .unwrap();

        // Twice: the second run reads the aliases from the stored rows.
        for _ in 0..2 {
            refresh(&pool, &client_for(&server), &[(cid, PURL.to_string())])
                .await
                .unwrap();
            let links: Vec<String> = sqlx::query_scalar(
                "select advisory_id from component_advisories where component_id = $1",
            )
            .bind(cid)
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(links, vec!["GHSA-cccc-dddd-eeee".to_string()]);
        }
        let (aliases, sev, fixed): (Vec<String>, String, Value) = sqlx::query_as(
            "select aliases, severity, fixed from advisories where id = 'GHSA-cccc-dddd-eeee'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert!(aliases.contains(&"GO-2026-0001".to_string()), "{aliases:?}");
        assert!(
            aliases.contains(&"CVE-2026-5000".to_string()),
            "{aliases:?}"
        );
        assert_eq!(sev, "high", "the higher severity wins");
        assert_eq!(fixed[NAME_KEY], json!(["1.9.1"]), "Go's fix is kept");

        crate::matcher::run(&pool, "prod", chrono::Utc::now())
            .await
            .unwrap();
        let findings: Vec<(FindingKind, String)> =
            sqlx::query_as("select kind, ref_id from findings order by kind")
                .fetch_all(&pool)
                .await
                .unwrap();
        let vulns: Vec<&(FindingKind, String)> = findings
            .iter()
            .filter(|(k, _)| *k == FindingKind::Vuln)
            .collect();
        assert_eq!(vulns.len(), 1, "{findings:?}");
        assert_eq!(vulns[0].1, "GHSA-cccc-dddd-eeee");
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn fix_appears_refetches(pool: PgPool) {
        let server = MockServer::start().await;
        let cid = seed_component(&pool, PURL).await;
        let comps = vec![(cid, PURL.to_string())];
        mount_record(
            &server,
            &osv_record("GHSA-fix", "2026-05-01T00:00:00Z", "HIGH", None),
            1,
        )
        .await;
        let first = refresh(&pool, &client_for(&server), &comps).await.unwrap();
        assert_eq!(first.fetched, 1);
        let fixed: Value = sqlx::query_scalar("select fixed from advisories where id = 'GHSA-fix'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(fixed[NAME_KEY], json!([]));

        // Same advisory, newer `modified`, now with a fixed event.
        server.reset().await;
        mount_record(
            &server,
            &osv_record("GHSA-fix", "2026-06-01T00:00:00Z", "HIGH", Some("1.9.1")),
            1,
        )
        .await;
        let second = refresh(&pool, &client_for(&server), &comps).await.unwrap();
        assert_eq!(second.fetched, 1);
        let fixed: Value = sqlx::query_scalar("select fixed from advisories where id = 'GHSA-fix'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(fixed[NAME_KEY], json!(["1.9.1"]));
    }
}
