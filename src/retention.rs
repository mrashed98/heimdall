//! Retention: old rows are deleted once a day. Findings and releases are kept
//! a year, sent outbox rows 30 days (all configurable). Oaths and their
//! events are the audit trail and are kept forever, so nothing here touches
//! them.

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;

use crate::config::HeimdallConfig;

/// Rows one cleanup deleted.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RetentionReport {
    pub findings: u64,
    pub releases: u64,
    pub outbox: u64,
}

/// Delete resolved findings, releases and sent outbox rows past their age.
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
    // Undated releases are kept: there is no age to judge them by.
    let releases = sqlx::query("DELETE FROM releases WHERE published_at < $1")
        .bind(days(r.releases_days))
        .execute(pool)
        .await?
        .rows_affected();
    // `sent_at < $1` is false for NULL, so unsent rows always stay.
    let outbox = sqlx::query("DELETE FROM outbox WHERE sent_at < $1")
        .bind(days(r.outbox_days))
        .execute(pool)
        .await?
        .rows_affected();
    Ok(RetentionReport {
        findings,
        releases,
        outbox,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn count(pool: &PgPool, table: &str) -> i64 {
        sqlx::query_scalar(&format!("SELECT count(*) FROM {table}"))
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn retention_keeps_oaths(pool: PgPool) {
        let cfg: HeimdallConfig = serde_yaml::from_str("realms: [prod]").unwrap();
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
                outbox: 1
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
}
