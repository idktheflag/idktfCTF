// state.rs — shared application state passed to every handler.
//
// Axum's .with_state() method attaches a value to the router that gets
// cloned into each request. We wrap it in Arc<AppState> so cloning is
// cheap (just increments a reference count) rather than copying the
// entire struct including the database connection pool.
//
// Arc = Atomically Reference Counted. It lets multiple owners share
// the same heap allocation. When the last Arc drops, the data is freed.
// "Atomic" means the ref-count changes are thread-safe without a mutex.

use sqlx::PgPool;

// #[derive(Clone)] is needed because Axum clones the state for each handler.
// PgPool already implements Clone cheaply (it's internally Arc'd too).
#[derive(Clone)]
pub struct AppState {
    // PgPool manages a pool of reusable database connections.
    // Opening a new TCP connection to Postgres on every request would be
    // very slow; the pool keeps connections warm and lends them out.
    pub pool: PgPool,

    // The secret used to sign and verify JWTs. Loaded from the JWT_SECRET
    // environment variable at startup. Never hardcoded, never logged.
    pub jwt_secret: String,
}
