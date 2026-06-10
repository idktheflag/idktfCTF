use std::sync::Arc;

use crate::auth::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub pool: sqlx::PgPool,
    pub jwt_secret: String,
    pub http: reqwest::Client,
    pub ctftime: Option<CtftimeConfig>,
    pub frontend_url: String,
    pub rate_limiter: Arc<RateLimiter>,
}

#[derive(Clone)]
pub struct CtftimeConfig {
    pub client_id:     String,
    pub client_secret: String,
    pub redirect_uri:  String,
}
