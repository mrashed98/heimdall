//! EPSS, FIRST's Exploit Prediction Scoring System: for each CVE, the chance
//! (0 to 1) that it is exploited in the wild in the next 30 days, and its
//! percentile among all CVEs. Published once a day as one gzipped CSV of every
//! CVE (about 3 MB, 400k rows). Only the CVEs Heimdall's advisories name are
//! kept; the table is replaced whole on each good download.
// Exception: predates AppState.clock; move these Utc::now() calls to it. Expires 2027-03-01, approval: pending (owner).
#![allow(clippy::disallowed_methods)]

use std::collections::HashSet;
use std::io::{BufRead, BufReader};

use anyhow::{bail, Context};
use chrono::{NaiveDate, Utc};
use flate2::read::GzDecoder;
use reqwest::Client;
use sqlx::PgPool;

use crate::vuln::retry;

/// The daily feed of every scored CVE.
pub const FEED_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";

/// A full feed has about 400k rows. Far fewer means a truncated or wrong
/// file, and replacing the table with it would wipe good scores.
const MIN_FEED_ROWS: usize = 100_000;

#[derive(Debug, Clone, PartialEq)]
pub struct Score {
    pub cve: String,
    pub score: f32,
    pub percentile: f32,
}

#[derive(Debug)]
pub struct Feed {
    /// The day the scores are for (from the `score_date` comment).
    pub date: NaiveDate,
    /// Rows for the wanted CVEs only.
    pub scores: Vec<Score>,
    /// Every data row in the file, kept or not.
    pub total: usize,
}

#[derive(Debug)]
pub struct Refresh {
    pub kept: usize,
    pub total: usize,
    pub date: NaiveDate,
}

/// Decode the gzipped CSV and keep the rows whose CVE is in `wanted`.
/// The file starts with `#model_version:...,score_date:2026-11-22T...` and a
/// `cve,epss,percentile` header; a different header is an error, so a format
/// change is noticed instead of storing columns in the wrong place.
pub fn parse(gz: &[u8], wanted: &HashSet<String>) -> anyhow::Result<Feed> {
    let mut date = None;
    let mut header = false;
    let mut scores = Vec::new();
    let mut total = 0;
    for line in BufReader::new(GzDecoder::new(gz)).lines() {
        let line = line.context("epss feed: not a gzipped text file")?;
        let line = line.trim_end();
        if let Some(comment) = line.strip_prefix('#') {
            date = comment
                .split(',')
                .find_map(|kv| kv.strip_prefix("score_date:"))
                .and_then(|d| d.get(..10))
                .and_then(|d| NaiveDate::parse_from_str(d, "%Y-%m-%d").ok())
                .or(date);
            continue;
        }
        if !header {
            if line != "cve,epss,percentile" {
                bail!("epss feed: unexpected header {line:?}");
            }
            header = true;
            continue;
        }
        if line.is_empty() {
            continue;
        }
        total += 1;
        let mut cols = line.split(',');
        let (Some(cve), Some(score), Some(pct)) = (cols.next(), cols.next(), cols.next()) else {
            bail!("epss feed: short row {line:?}");
        };
        if !wanted.contains(cve) {
            continue;
        }
        let parse = |v: &str| {
            v.parse::<f32>()
                .ok()
                .filter(|x| (0.0..=1.0).contains(x))
                .with_context(|| format!("epss feed: bad value {v:?} for {cve}"))
        };
        scores.push(Score {
            cve: cve.to_string(),
            score: parse(score)?,
            percentile: parse(pct)?,
        });
    }
    if !header {
        bail!("epss feed: empty file");
    }
    Ok(Feed {
        date: date.unwrap_or_else(|| Utc::now().date_naive()),
        scores,
        total,
    })
}

/// Every CVE id an advisory names, as its id, its CVE or an alias.
async fn wanted_cves(pool: &PgPool) -> anyhow::Result<HashSet<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT x FROM advisories, unnest(aliases || ARRAY[id, cve_id]) AS x \
         WHERE x LIKE 'CVE-%'",
    )
    .fetch_all(pool)
    .await?;
    Ok(ids.into_iter().collect())
}

/// Replace the stored scores with `feed`'s, in one transaction.
pub async fn store(pool: &PgPool, feed: &Feed) -> anyhow::Result<()> {
    let (mut cves, mut scores, mut pcts) = (Vec::new(), Vec::new(), Vec::new());
    for s in &feed.scores {
        cves.push(s.cve.as_str());
        scores.push(s.score);
        pcts.push(s.percentile);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM epss").execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO epss (cve_id, score, percentile, scored_on) \
         SELECT u.c, u.s, u.p, $4 FROM unnest($1::text[], $2::real[], $3::real[]) AS u(c, s, p)",
    )
    .bind(&cves)
    .bind(&scores)
    .bind(&pcts)
    .bind(feed.date)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Download the feed and store the scores of the CVEs Heimdall knows.
// ponytail: CVEs first seen after a run get their score on the next daily run.
pub async fn refresh(pool: &PgPool, http: &Client, url: &str) -> anyhow::Result<Refresh> {
    let wanted = wanted_cves(pool).await?;
    let body = retry::send("epss feed", || http.get(url))
        .await?
        .bytes()
        .await
        .map_err(|e| retry::request_failed("epss feed", e))?;
    // 400k rows of decoding: off the async workers, which also answer probes.
    let feed = tokio::task::spawn_blocking(move || parse(&body, &wanted)).await??;
    if feed.total < MIN_FEED_ROWS {
        bail!(
            "epss feed has only {} rows (expected at least {MIN_FEED_ROWS}); kept the old scores",
            feed.total
        );
    }
    store(pool, &feed).await?;
    Ok(Refresh {
        kept: feed.scores.len(),
        total: feed.total,
        date: feed.date,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn gz(text: &str) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::fast());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    fn wanted(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    const FEED: &str = "#model_version:v2026.06.15,score_date:2026-11-22T12:03:04Z\n\
                        cve,epss,percentile\n\
                        CVE-1999-0001,0.04753,0.92097\n\
                        CVE-2024-3094,0.85,0.999\n\
                        CVE-2025-0002,0.0001,0.01\n";

    #[test]
    fn keeps_only_wanted_cves_and_reads_the_date() {
        let f = parse(&gz(FEED), &wanted(&["CVE-2024-3094", "CVE-2030-9"])).unwrap();
        assert_eq!(f.total, 3);
        assert_eq!(f.date, NaiveDate::from_ymd_opt(2026, 11, 22).unwrap());
        assert_eq!(
            f.scores,
            vec![Score {
                cve: "CVE-2024-3094".into(),
                score: 0.85,
                percentile: 0.999
            }]
        );
    }

    #[test]
    fn rejects_a_changed_header_bad_values_and_plain_text() {
        let w = wanted(&["CVE-1"]);
        assert!(parse(&gz("cve,percentile,epss\nCVE-1,0.1,0.2\n"), &w).is_err());
        assert!(parse(&gz("cve,epss,percentile\nCVE-1,2.5,0.2\n"), &w).is_err());
        assert!(parse(&gz("cve,epss,percentile\nCVE-1,0.1\n"), &w).is_err());
        assert!(parse(&gz(""), &w).is_err());
        assert!(parse(b"cve,epss,percentile\n", &w).is_err());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn store_replaces_the_table_and_wanted_reads_aliases(pool: PgPool) {
        sqlx::query(
            "INSERT INTO advisories (id, aliases, severity, source, cve_id) VALUES \
             ('GHSA-x', '{CVE-2024-3094}', 'critical', 'osv', 'CVE-2024-3094'), \
             ('CVE-2025-0002', '{}', 'low', 'nvd', NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        let w = wanted_cves(&pool).await.unwrap();
        assert_eq!(w, wanted(&["CVE-2024-3094", "CVE-2025-0002"]));

        store(&pool, &parse(&gz(FEED), &w).unwrap()).await.unwrap();
        let next = "cve,epss,percentile\nCVE-2024-3094,0.5,0.9\n";
        store(&pool, &parse(&gz(next), &w).unwrap()).await.unwrap();
        let rows: Vec<(String, f32)> = sqlx::query_as("SELECT cve_id, score FROM epss")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(rows, vec![("CVE-2024-3094".to_string(), 0.5)]);
    }
}
