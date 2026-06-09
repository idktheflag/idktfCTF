use anyhow::Result;
use sqlx::PgPool;

pub mod models;

pub async fn connect(database_url: &str) -> Result<PgPool> {
    let pool = PgPool::connect(database_url).await?;
    sqlx::migrate("./migrations").run(&pool).await?;
    Ok(pool)
}
