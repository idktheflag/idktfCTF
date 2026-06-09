// state.rs — AppState: the shared application context.
//
// AppState is wrapped in Arc<AppState> and cloned into every handler.
// Arc = "Atomically Reference Counted" — cheap to clone (just increments a
// counter), thread-safe, and the data is freed when the last Arc is dropped.
//
// Each field here is something we want to share across requests:
//   - pool:         database connection pool (sqlx manages the connections)
//   - jwt_secret:   HMAC key for signing/verifying JWTs
//   - http:         HTTP client with connection pooling for CTFtime OAuth calls
//   - ctftime:      OAuth credentials, optional (can run without CTFtime)
//   - frontend_url: where to redirect the browser after OAuth
//   - rate_limiter: in-memory flag submission rate limiter (see auth/ratelimit.rs)

use std::sync::Arc;

use crate::auth::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub pool:         sqlx::PgPool,
    pub jwt_secret:   String,
    pub http:         reqwest::Client,
    pub ctftime:      Option<CtftimeConfig>,
    pub frontend_url: String,
    // Arc here because AppState itself is Clone (for Axum's .with_state()),
    // but RateLimiter holds a Mutex and cannot be Clone. Wrapping in Arc lets
    // all clones point at the same underlying RateLimiter instance.
    pub rate_limiter: Arc<RateLimiter>,
}

#[derive(Clone)]
pub struct CtftimeConfig {
    pub client_id:     String,
    pub client_secret: String,
    pub redirect_uri:  String,
}
