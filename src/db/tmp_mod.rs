// db/mod.rs — database connection setup and migration runner.

use anyhow::Result;
use sqlx::PgPool;

pub mod models;

// connect() creates the connection pool and runs any pending migrations.
//
// sqlx::migrate!("./migrations") is a compile-time macro that embeds all
// .sql files from the migrations/ directory into the binary. At runtime,
// .run(&pool) executes any migrations that haven't been applied yet.
// sqlx tracks applied migrations in a _sqlx_migrations table it creates
// automatically.
//
// We call this once at startup in main(). If the DB is unreachable or a
// migration fails, we crash immediately (via the .expect() in main) rather
// than serving broken requests.
pub async fn connect(database_url: &str) -> Result<PgPool> {
    // connect() opens connections lazily; connect_lazy() would also work.
    // We use the eager version so startup fails fast if the DB is down.
    let pool = PgPool::connect(database_url).await?;

    // Apply any unapplied migrations from the ./migrations directory.
    // The path is relative to CARGO_MANIFEST_DIR (where Cargo.toml lives).
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
