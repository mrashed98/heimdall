//! Daily counts of open findings per severity, per realm and per service.
//! `snapshot` runs after every matcher pass and overwrites the day's row, so
//! a day ends up holding its last counts. Days the server was down have no
//! row; readers show them as gaps rather than zeros.

use chrono::NaiveDate;
use sqlx::PgPool;

const COUNTS: &str = "count(f.id) FILTER (WHERE f.severity='critical'), \
     count(f.id) FILTER (WHERE f.severity='high'), \
     count(f.id) FILTER (WHERE f.severity='medium'), \
     count(f.id) FILTER (WHERE f.severity='low'), \
     count(f.id) FILTER (WHERE f.severity='unknown')";
const UPDATE: &str = "critical=EXCLUDED.critical, high=EXCLUDED.high, \
     medium=EXCLUDED.medium, low=EXCLUDED.low, unknown=EXCLUDED.unknown";

/// Record `day`'s open findings for every realm in `realms` and every service
/// in them. Running it again the same day replaces that day's rows.
pub async fn snapshot(pool: &PgPool, realms: &[String], day: NaiveDate) -> anyhow::Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO realm_daily (realm, day, critical, high, medium, low, unknown) \
         SELECT r.realm, $2, {COUNTS} FROM unnest($1::text[]) AS r(realm) \
         LEFT JOIN findings f ON f.realm=r.realm AND f.status='open' GROUP BY r.realm \
         ON CONFLICT (realm, day) DO UPDATE SET {UPDATE}"
    )))
    .bind(realms)
    .bind(day)
    .execute(&mut *tx)
    .await?;
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO service_daily (service_id, day, critical, high, medium, low, unknown) \
         SELECT s.id, $2, {COUNTS} FROM services s \
         LEFT JOIN findings f ON f.service_id=s.id AND f.realm=s.realm AND f.status='open' \
         WHERE s.realm=ANY($1) GROUP BY s.id \
         ON CONFLICT (service_id, day) DO UPDATE SET {UPDATE}"
    )))
    .bind(realms)
    .bind(day)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::store::upsert_service;

    async fn finding(
        pool: &PgPool,
        key: &str,
        realm: &str,
        service: i64,
        severity: &str,
        status: &str,
    ) {
        sqlx::query("INSERT INTO findings (key, kind, realm, service_id, severity, status) VALUES ($1, 'vuln', $2, $3, $4, $5)")
            .bind(key).bind(realm).bind(service).bind(severity).bind(status)
            .execute(pool).await.unwrap();
    }

    async fn rows(pool: &PgPool, sql: &str) -> Vec<(String, String, i32, i32, i32)> {
        sqlx::query_as(sqlx::AssertSqlSafe(sql.to_owned()))
            .fetch_all(pool)
            .await
            .unwrap()
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn snapshot_counts_open_findings_and_replaces_the_day(pool: PgPool) {
        let api = upsert_service(&pool, "prod", "api").await.unwrap();
        let idle = upsert_service(&pool, "prod", "idle").await.unwrap();
        let job = upsert_service(&pool, "dev", "job").await.unwrap();
        finding(&pool, "a", "prod", api, "critical", "open").await;
        finding(&pool, "b", "prod", api, "high", "open").await;
        finding(&pool, "c", "prod", api, "high", "resolved").await;
        finding(&pool, "d", "dev", job, "critical", "open").await;
        let realms = ["prod".to_owned(), "staging".to_owned()];
        let day1 = NaiveDate::from_ymd_opt(2026, 11, 1).unwrap();
        let day2 = day1.succ_opt().unwrap();
        snapshot(&pool, &realms, day1).await.unwrap();
        sqlx::query("UPDATE findings SET status='resolved' WHERE key='a'")
            .execute(&pool)
            .await
            .unwrap();
        snapshot(&pool, &realms, day2).await.unwrap();
        finding(&pool, "e", "prod", api, "medium", "open").await;
        snapshot(&pool, &realms, day2).await.unwrap();

        let realm_sql =
            "SELECT realm, day::text, critical, high, medium FROM realm_daily ORDER BY day, realm";
        assert_eq!(
            rows(&pool, realm_sql).await,
            [
                ("prod".into(), "2026-11-01".into(), 1, 1, 0),
                ("staging".into(), "2026-11-01".into(), 0, 0, 0),
                ("prod".into(), "2026-11-02".into(), 0, 1, 1),
                ("staging".into(), "2026-11-02".into(), 0, 0, 0),
            ],
            "resolved findings and other realms are not counted; a second run the same day replaces it"
        );
        let service_sql = "SELECT s.name, d.day::text, d.critical, d.high, d.medium FROM service_daily d JOIN services s ON s.id=d.service_id ORDER BY d.day, s.name";
        assert_eq!(
            rows(&pool, service_sql).await,
            [
                ("api".into(), "2026-11-01".into(), 1, 1, 0),
                ("idle".into(), "2026-11-01".into(), 0, 0, 0),
                ("api".into(), "2026-11-02".into(), 0, 1, 1),
                ("idle".into(), "2026-11-02".into(), 0, 0, 0),
            ]
        );
        let _ = idle;
    }
}
