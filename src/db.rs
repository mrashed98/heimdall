use anyhow::Context;
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Pool size. Ten leaves room for the scheduled loops, a few requests and
/// `/healthz` at once, so a busy minute does not time out the readiness probe.
pub const MAX_CONNECTIONS: u32 = 10;

/// Connect to Postgres (`MAX_CONNECTIONS`) and apply pending migrations.
/// Migrations are embedded in the binary at compile time from `./migrations`.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect(url)
        .await
        .context("connecting to postgres")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    #[sqlx::test(migrations = "./migrations")]
    async fn migrations_apply(pool: PgPool) {
        let n: i64 = sqlx::query_scalar("select count(*) from findings")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn connect_runs_migrations() {
        let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
        let pool = super::connect(&url).await.unwrap();
        let one: i32 = sqlx::query_scalar("SELECT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(one, 1);
    }
}
