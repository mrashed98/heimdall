use anyhow::Context;
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Connect to Postgres (max 5 connections) and apply pending migrations.
/// Migrations are embedded in the binary at compile time from `./migrations`.
pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(5)
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
