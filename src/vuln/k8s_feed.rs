//! Kubernetes official CVE feed (JSON Feed 1.1, auto-refreshed by the
//! Kubernetes project). Every realm running Kubernetes or k3s gets one K8sCve
//! finding per feed entry. These findings are one-shot: never resolved here.

use std::collections::BTreeSet;

use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use url::Url;

use crate::inventory::store::effective_components;
use crate::matcher::key;
use crate::model::{FindingKind, Severity};
use crate::vuln::retry;

/// Path of the feed on `https://kubernetes.io`.
pub const FEED_PATH: &str = "/docs/reference/issues-security/official-cve-feed/index.json";

/// The components that mean a realm runs Kubernetes.
const KUBERNETES_KEYS: [&str; 2] = ["pkg:generic/kubernetes", "pkg:generic/k3s"];

/// On a realm's first sight of the feed, only items this recent alert.
const FIRST_SIGHT_DAYS: i64 = 90;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sCve {
    pub id: String,
    pub summary: String,
    /// The tracking issue on GitHub.
    pub url: String,
    pub published: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct Feed {
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    id: String,
    #[serde(default)]
    summary: String,
    #[serde(default)]
    url: String,
    date_published: Option<DateTime<Utc>>,
}

/// Every CVE in the feed at `base` (`https://kubernetes.io`). A feed with
/// no items is an error: the real feed is never empty, and taking an empty
/// one as the truth would record nothing as seen and flood on the next run.
pub async fn fetch(http: &Client, base: &Url) -> anyhow::Result<Vec<K8sCve>> {
    let url = base.join(FEED_PATH).context("k8s cve feed url")?;
    let resp = retry::send("k8s cve feed", || http.get(url.clone())).await?;
    let feed: Feed = resp.json().await.context("k8s cve feed: body")?;
    if feed.items.is_empty() {
        anyhow::bail!("k8s cve feed has no items; ignoring it");
    }
    Ok(feed
        .items
        .into_iter()
        .map(|i| K8sCve {
            id: i.id,
            summary: i.summary,
            url: i.url,
            published: i.date_published,
        })
        .collect())
}

/// Open a High K8sCve finding (`k8s_cve|realm|id`) for each feed CVE this
/// realm has not seen, when the realm runs Kubernetes or k3s. Returns the new
/// finding ids. Takes the realm's matcher lock so it never races the
/// matcher's writes.
///
/// Seen ids live in `kv` under `k8sfeed_seen|<realm>` (a JSON array). On the
/// realm's first sight of the feed only items published in the last 90 days
/// alert (undated items count as old), so years of history do not flood
/// Teams; every item is recorded as seen. After that, any unseen item alerts,
/// however old.
///
/// An empty `cves` is an error and writes nothing: recorded as the first
/// sight, it would leave the seen list empty, and the next good feed would
/// alert on every item it holds.
pub async fn run(
    pool: &PgPool,
    realm: &str,
    cves: &[K8sCve],
    now: DateTime<Utc>,
) -> anyhow::Result<Vec<i64>> {
    if cves.is_empty() {
        tracing::warn!(realm = %realm, "k8s cve feed is empty; seen ids left as they are");
        anyhow::bail!("k8s cve feed is empty");
    }
    let mut tx = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('matcher:' || $1))")
        .bind(realm)
        .execute(&mut *tx)
        .await?;
    let runs_kubernetes = effective_components(&mut *tx, realm)
        .await?
        .iter()
        .any(|c| KUBERNETES_KEYS.contains(&c.name_key.as_str()));
    if !runs_kubernetes {
        return Ok(Vec::new());
    }

    let seen_key = format!("k8sfeed_seen|{realm}");
    let stored: Option<String> = sqlx::query_scalar("SELECT value FROM kv WHERE key = $1")
        .bind(&seen_key)
        .fetch_optional(&mut *tx)
        .await?;
    let first_sight = stored.is_none();
    let mut seen: BTreeSet<String> = match stored {
        Some(json) => serde_json::from_str(&json).context("k8s feed seen ids")?,
        None => BTreeSet::new(),
    };
    let recent_since = now - Duration::days(FIRST_SIGHT_DAYS);

    let mut opened = Vec::new();
    for cve in cves {
        // `insert` is false for an id seen before.
        if !seen.insert(cve.id.clone()) {
            continue;
        }
        if first_sight && !cve.published.is_some_and(|p| p >= recent_since) {
            continue;
        }
        let details = json!({
            "id": cve.id,
            "summary": cve.summary,
            "url": cve.url,
            "published": cve.published,
        });
        // DO NOTHING on an existing key: seen before, whatever its status.
        let id: Option<i64> = sqlx::query_scalar(
            "INSERT INTO findings (key, kind, realm, ref_id, severity, details, opened_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (key) DO NOTHING RETURNING id",
        )
        .bind(key(FindingKind::K8sCve, &[realm, &cve.id]))
        .bind(FindingKind::K8sCve)
        .bind(realm)
        .bind(&cve.id)
        .bind(Severity::High)
        .bind(&details)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        opened.extend(id);
    }
    sqlx::query(
        "INSERT INTO kv (key, value) VALUES ($1, $2) \
         ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
    )
    .bind(&seen_key)
    .bind(serde_json::to_string(&seen)?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(opened)
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use sqlx::PgPool;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
    use crate::model::Source;

    async fn component(pool: &PgPool, realm: &str, purl: &str) {
        let svc = upsert_service(pool, realm, "cluster").await.unwrap();
        let item = InventoryItem {
            purl: purl.to_string(),
            cpes: vec![],
            direct: false,
            via_image_digest: None,
        };
        replace_components(pool, svc, Source::Cluster, &[item])
            .await
            .unwrap();
    }

    async fn feed() -> Vec<K8sCve> {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(FEED_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                std::fs::read_to_string("tests/fixtures/watchers/k8s_cve_feed.json").unwrap(),
            ))
            .mount(&server)
            .await;
        fetch(&reqwest::Client::new(), &Url::parse(&server.uri()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn feed_parses() {
        let cves = feed().await;
        assert_eq!(cves.len(), 3);
        assert_eq!(cves[0].id, "CVE-2026-116472");
        assert_eq!(cves[0].summary, "ingress-nginx mirror-target self-DOS");
        assert_eq!(
            cves[0].url,
            "https://github.com/kubernetes/kubernetes/issues/143852"
        );
        assert!(cves[0].published.is_some());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn k8s_cve_once_per_realm(pool: PgPool) {
        component(&pool, "dev", "pkg:generic/k3s@v1.31.2+k3s1").await;
        component(&pool, "prod", "pkg:generic/kubernetes@1.31.2").await;
        component(&pool, "qa", "pkg:npm/left-pad@1.0.0").await;
        let cves = feed().await;
        let now = Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap();

        assert_eq!(run(&pool, "dev", &cves, now).await.unwrap().len(), 3);
        assert!(run(&pool, "dev", &cves, now).await.unwrap().is_empty());
        assert_eq!(run(&pool, "prod", &cves, now).await.unwrap().len(), 3);
        assert!(run(&pool, "qa", &cves, now).await.unwrap().is_empty());

        let keys: Vec<(String, String)> =
            sqlx::query_as("SELECT key, severity FROM findings WHERE realm = 'dev' ORDER BY key")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(keys.len(), 3);
        assert!(keys.contains(&("k8s_cve|dev|CVE-2026-116472".into(), "high".into())));
    }

    fn cve(id: &str, published: Option<DateTime<Utc>>) -> K8sCve {
        K8sCve {
            id: id.to_string(),
            summary: String::new(),
            url: String::new(),
            published,
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn first_sight_skips_items_older_than_90_days(pool: PgPool) {
        component(&pool, "dev", "pkg:generic/kubernetes@1.31.2").await;
        let now = Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap();
        let days = |d: i64| Some(now - chrono::Duration::days(d));
        let first = vec![
            cve("CVE-OLD-1", days(200)),
            cve("CVE-RECENT", days(10)),
            cve("CVE-UNDATED", None),
        ];
        let opened = run(&pool, "dev", &first, now).await.unwrap();
        assert_eq!(
            opened.len(),
            1,
            "only the recent item alerts on first sight"
        );
        let keys: Vec<String> = sqlx::query_scalar("SELECT key FROM findings")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(keys, ["k8s_cve|dev|CVE-RECENT"]);

        // After the first sight, an unseen item alerts however old it is;
        // the old ones recorded as seen stay quiet.
        let mut second = first.clone();
        second.push(cve("CVE-OLD-2", days(300)));
        assert_eq!(run(&pool, "dev", &second, now).await.unwrap().len(), 1);
        assert!(run(&pool, "dev", &second, now).await.unwrap().is_empty());
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn empty_feed_does_not_seed_seen(pool: PgPool) {
        component(&pool, "dev", "pkg:generic/kubernetes@1.31.2").await;
        let now = Utc.with_ymd_and_hms(2026, 11, 13, 12, 0, 0).unwrap();
        // A broken feed (an empty page, a CDN error page parsed as no items).
        assert!(run(&pool, "dev", &[], now).await.is_err());
        let seen: Option<String> = sqlx::query_scalar("SELECT value FROM kv WHERE key = $1")
            .bind("k8sfeed_seen|dev")
            .fetch_optional(&pool)
            .await
            .unwrap();
        assert_eq!(seen, None, "seen ids are not seeded from an empty feed");

        // So the next good feed is still a first sight: old items stay quiet.
        let days = |d: i64| Some(now - chrono::Duration::days(d));
        let cves = vec![cve("CVE-OLD", days(200)), cve("CVE-RECENT", days(10))];
        assert_eq!(run(&pool, "dev", &cves, now).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn fetch_of_an_empty_feed_is_an_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(FEED_PATH))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"items": []}"#))
            .mount(&server)
            .await;
        let got = fetch(&reqwest::Client::new(), &Url::parse(&server.uri()).unwrap()).await;
        assert!(got.is_err());
    }
}
