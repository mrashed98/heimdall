//! Retention: old rows are deleted once a day. Findings and releases are kept
//! a year, sent outbox rows 30 days (all configurable). Oaths and their
//! events are the audit trail and are kept forever, so nothing here touches
//! them.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use crate::config::HeimdallConfig;
use crate::version::compare;
use crate::watchers;

/// Rows one cleanup deleted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionReport {
    pub findings: u64,
    pub releases: u64,
    pub outbox: u64,
    pub scan_attempts: u64,
}

/// Delete resolved findings, releases and sent outbox rows past their age,
/// and scan-attempt rows of images that are no longer pending or running.
/// Open findings and unsent outbox rows are never deleted, however old.
pub async fn cleanup(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    now: DateTime<Utc>,
) -> anyhow::Result<RetentionReport> {
    let r = &cfg.retention;
    let days = |n: u32| now - Duration::days(i64::from(n));
    let findings =
        sqlx::query("DELETE FROM findings WHERE status = 'resolved' AND resolved_at < $1")
            .bind(days(r.findings_days))
            .execute(pool)
            .await?
            .rows_affected();
    let releases = old_releases(pool, cfg, days(r.releases_days)).await?;
    // `sent_at < $1` is false for NULL, so unsent rows always stay.
    let outbox = sqlx::query("DELETE FROM outbox WHERE sent_at < $1")
        .bind(days(r.outbox_days))
        .execute(pool)
        .await?
        .rows_affected();
    // A digest is pending while a service references it and it has no SBOM.
    // Once it is scanned (the SBOM row exists) or nothing references it
    // (it left the cluster), its failure history is dead weight.
    let scan_attempts = sqlx::query(
        "DELETE FROM image_scan_attempts a \
         WHERE EXISTS (SELECT 1 FROM image_sboms i WHERE i.digest = a.digest) \
            OR NOT EXISTS (SELECT 1 FROM service_components sc \
                           WHERE sc.via_image_digest = a.digest)",
    )
    .execute(pool)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM sessions WHERE expires_at <= $1 OR last_seen_at <= $1 - ($2 * interval '1 hour')")
        .bind(now).bind(i64::from(cfg.auth.as_ref().map_or(12, |a| a.session.idle_hours))).execute(pool).await?;
    sqlx::query("DELETE FROM login_failures WHERE occurred_at <= $1 - interval '15 minutes'")
        .bind(now)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM audit_log WHERE occurred_at < $1")
        .bind(days(r.audit_days))
        .execute(pool)
        .await?;
    for table in ["realm_daily", "service_daily"] {
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DELETE FROM {table} WHERE day < $1"
        )))
        .bind(days(r.trends_days).date_naive())
        .execute(pool)
        .await?;
    }
    Ok(RetentionReport {
        findings,
        releases,
        outbox,
        scan_attempts,
    })
}

/// Delete releases published before `cutoff` that no longer matter: their
/// target is not watched any more, or they are not newer than what runs.
/// An old release still newer than what runs is kept, or the watchers would
/// insert it again as new (fresh id, notes refetched, alerts repeated).
/// Undated releases are kept: there is no age to judge them by.
async fn old_releases(
    pool: &PgPool,
    cfg: &HeimdallConfig,
    cutoff: DateTime<Utc>,
) -> anyhow::Result<u64> {
    let old: Vec<(i64, String, String)> =
        sqlx::query_as("SELECT id, target, version FROM releases WHERE published_at < $1")
            .bind(cutoff)
            .fetch_all(pool)
            .await?;
    if old.is_empty() {
        return Ok(0);
    }
    let watched = watchers::watched_versions(pool, cfg).await?;
    let ids: Vec<i64> = old
        .into_iter()
        .filter(|(_, target, version)| match watched.get(target) {
            None => true,
            Some((Some(current), eco)) => matches!(
                compare(eco, version, current),
                Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
            ),
            // Unknown current version: cannot tell, so keep it.
            Some((None, _)) => false,
        })
        .map(|(id, _, _)| id)
        .collect();
    let deleted = sqlx::query("DELETE FROM releases WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?
        .rows_affected();
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn count(pool: &PgPool, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_drops_trend_days_past_their_age(pool: PgPool) {
        let cfg: HeimdallConfig =
            serde_saphyr::from_str("realms: [prod]\nretention: {trends_days: 30}").unwrap();
        let now: DateTime<Utc> = "2026-11-13T12:00:00Z".parse().unwrap();
        let svc = crate::inventory::store::upsert_service(&pool, "prod", "api")
            .await
            .unwrap();
        for day in ["2026-10-13", "2026-10-14"] {
            sqlx::query("INSERT INTO realm_daily VALUES ('prod', $1::date, 0, 0, 0, 0, 0)")
                .bind(day)
                .execute(&pool)
                .await
                .unwrap();
            sqlx::query("INSERT INTO service_daily VALUES ($1, $2::date, 0, 0, 0, 0, 0)")
                .bind(svc)
                .bind(day)
                .execute(&pool)
                .await
                .unwrap();
        }
        cleanup(&pool, &cfg, now).await.unwrap();
        for table in ["realm_daily", "service_daily"] {
            let days: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT day::text FROM {table} ORDER BY day"
            )))
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(days, ["2026-10-14"], "{table}");
        }
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_keeps_oaths(pool: PgPool) {
        let cfg: HeimdallConfig = serde_saphyr::from_str("realms: [prod]").unwrap();
        let now: DateTime<Utc> = "2026-11-13T00:00:00Z".parse().unwrap();
        let old = now - Duration::days(400);
        let recent = now - Duration::days(10);
        let svc = crate::inventory::store::upsert_service(&pool, "prod", "api")
            .await
            .unwrap();

        // Findings: old resolved (deleted), recent resolved and old open (kept).
        for (key, status, resolved_at) in [
            ("old-resolved", "resolved", Some(old)),
            ("recent-resolved", "resolved", Some(recent)),
            ("old-open", "open", None),
        ] {
            sqlx::query(
                "INSERT INTO findings (key, kind, realm, service_id, severity, status, \
                 opened_at, resolved_at) VALUES ($1, 'vuln', 'prod', $2, 'high', $3, $4, $5)",
            )
            .bind(key)
            .bind(svc)
            .bind(status)
            .bind(old)
            .bind(resolved_at)
            .execute(&pool)
            .await
            .unwrap();
        }
        // Releases: one old (deleted), one recent (kept).
        for (version, published) in [("1.0.0", old), ("2.0.0", recent)] {
            sqlx::query(
                "INSERT INTO releases (target, version, published_at) VALUES ('x', $1, $2)",
            )
            .bind(version)
            .bind(published)
            .execute(&pool)
            .await
            .unwrap();
        }
        // Outbox: old sent (deleted), old unsent and recent sent (kept).
        for (group, sent_at) in [("a", Some(old)), ("b", None), ("c", Some(recent))] {
            sqlx::query(
                "INSERT INTO outbox (group_key, card, route, next_attempt_at, sent_at) \
                 VALUES ($1, '{}', 'default', $2, $3)",
            )
            .bind(group)
            .bind(old)
            .bind(sent_at)
            .execute(&pool)
            .await
            .unwrap();
        }
        // An old, long-expired oath with an event: kept forever.
        let oath: i64 = sqlx::query_scalar(
            "INSERT INTO oaths (advisory_id, name_key, service_name, realm, kind, reason, \
             version_at_creation, expires_at, created_by, created_at, status) \
             VALUES ('CVE-1', 'pkg:npm/x', 'api', 'prod', 'snooze', 'why', '1.0.0', $1, \
             'me', $1, 'expired') RETURNING id",
        )
        .bind(old)
        .fetch_one(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO oath_events (oath_id, event, at, by) VALUES ($1, 'expired', $2, 'heimdall')")
            .bind(oath)
            .bind(old)
            .execute(&pool)
            .await
            .unwrap();

        let r = cleanup(&pool, &cfg, now).await.unwrap();
        assert_eq!(
            r,
            RetentionReport {
                findings: 1,
                releases: 1,
                outbox: 1,
                scan_attempts: 0,
            }
        );
        let keys: Vec<String> = sqlx::query_scalar("SELECT key FROM findings ORDER BY key")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(keys, vec!["old-open", "recent-resolved"]);
        assert_eq!(count(&pool, "releases").await, 1);
        let groups: Vec<String> =
            sqlx::query_scalar("SELECT group_key FROM outbox ORDER BY group_key")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(groups, vec!["b", "c"]);
        assert_eq!(count(&pool, "oaths").await, 1);
        assert_eq!(count(&pool, "oath_events").await, 1);
    }

    // ---- releases --------------------------------------------------------

    /// prod runs kubernetes 1.30.2, a watched GitHub target.
    async fn k8s_setup(pool: &PgPool) -> HeimdallConfig {
        use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
        let svc = upsert_service(pool, "prod", "cluster").await.unwrap();
        let item = InventoryItem {
            purl: "pkg:generic/kubernetes@1.30.2".into(),
            cpes: vec![],
            direct: true,
            via_image_digest: None,
        };
        replace_components(pool, svc, crate::model::Source::Cluster, &[item])
            .await
            .unwrap();
        serde_saphyr::from_str(
            "realms: [prod]\nwatchers:\n  github:\n    - { repo: kubernetes/kubernetes, inventory_name: kubernetes, major_component: 1 }\n",
        )
        .unwrap()
    }

    fn now() -> DateTime<Utc> {
        "2026-11-13T00:00:00Z".parse().unwrap()
    }

    async fn old_release(pool: &PgPool, target: &str, version: &str) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO releases (target, version, published_at) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(target)
        .bind(version)
        .bind(now() - Duration::days(400))
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn release_ids(pool: &PgPool) -> Vec<i64> {
        sqlx::query_scalar("SELECT id FROM releases ORDER BY id")
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_keeps_old_release_still_newer_than_running(pool: PgPool) {
        let cfg = k8s_setup(&pool).await;
        let id = old_release(&pool, "kubernetes", "1.31.0").await;
        let r = cleanup(&pool, &cfg, now()).await.unwrap();
        assert_eq!(r.releases, 0);
        assert_eq!(release_ids(&pool).await, vec![id]);

        // The watchers store it again: same row, no new id.
        let target = watchers::WatchTarget {
            name: "kubernetes".into(),
            kind: watchers::WatchKind::Github,
            current: Some("1.30.2".into()),
            major_component: 1,
            repo: Some("kubernetes/kubernetes".into()),
            name_key: None,
        };
        let info = watchers::ReleaseInfo {
            version: "1.31.0".into(),
            published_at: Some(now() - Duration::days(400)),
        };
        let new = watchers::store_releases(&pool, &target, &[info])
            .await
            .unwrap();
        assert_eq!(new, 0);
        assert_eq!(release_ids(&pool).await, vec![id]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_deletes_old_superseded_release(pool: PgPool) {
        let cfg = k8s_setup(&pool).await;
        old_release(&pool, "kubernetes", "1.30.0").await;
        old_release(&pool, "kubernetes", "1.30.2").await;
        let keep = old_release(&pool, "kubernetes", "1.31.0").await;
        let r = cleanup(&pool, &cfg, now()).await.unwrap();
        assert_eq!(r.releases, 2);
        assert_eq!(release_ids(&pool).await, vec![keep]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_deletes_release_of_unplanned_target(pool: PgPool) {
        let cfg = k8s_setup(&pool).await;
        old_release(&pool, "retired-thing", "9.0.0").await;
        // Recent releases of an unplanned target are not old enough yet.
        let recent: i64 = sqlx::query_scalar(
            "INSERT INTO releases (target, version, published_at) VALUES ('retired-thing', '9.1.0', $1) RETURNING id",
        )
        .bind(now() - Duration::days(10))
        .fetch_one(&pool)
        .await
        .unwrap();
        let r = cleanup(&pool, &cfg, now()).await.unwrap();
        assert_eq!(r.releases, 1);
        assert_eq!(release_ids(&pool).await, vec![recent]);
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_drops_scan_attempts_of_images_no_longer_pending(pool: PgPool) {
        use crate::inventory::store::{replace_components, upsert_service, InventoryItem};
        let cfg: HeimdallConfig = serde_saphyr::from_str("realms: [prod]").unwrap();
        let svc = upsert_service(&pool, "prod", "api").await.unwrap();
        let item = InventoryItem {
            purl: "pkg:oci/api?repository_url=ghcr.io/x/api".into(),
            cpes: vec![],
            direct: true,
            via_image_digest: Some("sha256:pending".into()),
        };
        replace_components(&pool, svc, crate::model::Source::Cluster, &[item])
            .await
            .unwrap();
        // pending: referenced, no SBOM. scanned: has an SBOM. gone: unreferenced.
        for d in ["sha256:pending", "sha256:scanned", "sha256:gone"] {
            sqlx::query("INSERT INTO image_scan_attempts (digest, attempts) VALUES ($1, 2)")
                .bind(d)
                .execute(&pool)
                .await
                .unwrap();
        }
        sqlx::query("INSERT INTO image_sboms (digest, image_ref) VALUES ('sha256:scanned', 'r')")
            .execute(&pool)
            .await
            .unwrap();
        let r = cleanup(&pool, &cfg, now()).await.unwrap();
        assert_eq!(r.scan_attempts, 2);
        let left: Vec<String> = sqlx::query_scalar("SELECT digest FROM image_scan_attempts")
            .fetch_all(&pool)
            .await
            .unwrap();
        assert_eq!(left, vec!["sha256:pending"]);
    }
}
