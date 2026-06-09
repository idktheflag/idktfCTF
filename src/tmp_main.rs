// main.rs — application entry point.
//
// Responsibilities:
//   1. Read configuration from environment variables (fail fast if missing).
//   2. Connect to the database and run pending migrations.
//   3. Build shared AppState.
//   4. Wire up the Axum router with all routes.
//   5. Bind the TCP listener and serve forever.
//
// Env vars:
//   Required: DATABASE_URL, JWT_SECRET
//   Optional: CTFTIME_CLIENT_ID, CTFTIME_CLIENT_SECRET, CTFTIME_REDIRECT_URI
//             FRONTEND_URL (default: http://localhost:4321)

use std::sync::Arc;

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};

mod auth;
mod db;
mod error;
mod routes;
mod state;

use state::{AppState, CtftimeConfig};

#[tokio::main]
async fn main() {
    // tracing_subscriber reads the RUST_LOG env var to set log levels.
    // e.g. RUST_LOG=info,sqlx=warn to silence noisy sqlx query logs.
    tracing_subscriber::fmt::init();

    // ── Required env vars ──────────────────────────────────────────────────────
    // .expect() panics with a useful message if the var is missing.
    // We want to fail at startup, not silently use wrong values.
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost/ctf)");
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set — use a long random string (e.g. openssl rand -hex 32)");

    // ── Database ───────────────────────────────────────────────────────────────
    let pool = db::connect(&db_url)
        .await
        .expect("failed to connect to PostgreSQL and run migrations");
    tracing::info!("database connected, migrations applied");

    // ── CTFtime OAuth (optional) ───────────────────────────────────────────────
    // All three vars must be set together. If any is missing, CTFtime login is
    // disabled (returns 400) rather than crashing the server.
    let ctftime = match (
        std::env::var("CTFTIME_CLIENT_ID"),
        std::env::var("CTFTIME_CLIENT_SECRET"),
        std::env::var("CTFTIME_REDIRECT_URI"),
    ) {
        (Ok(client_id), Ok(client_secret), Ok(redirect_uri)) => {
            tracing::info!("CTFtime OAuth enabled (client_id={})", client_id);
            Some(CtftimeConfig { client_id, client_secret, redirect_uri })
        }
        _ => {
            tracing::warn!("CTFtime OAuth disabled — set CTFTIME_CLIENT_ID, CTFTIME_CLIENT_SECRET, CTFTIME_REDIRECT_URI to enable");
            None
        }
    };

    let frontend_url = std::env::var("FRONTEND_URL")
        .unwrap_or_else(|_| "http://localhost:4321".to_string());

    // ── Shared state ───────────────────────────────────────────────────────────
    let state = Arc::new(AppState {
        pool,
        jwt_secret,
        http: reqwest::Client::new(),
        ctftime,
        frontend_url,
        // A fresh rate limiter with no recorded attempts.
        // The Arc is needed because AppState must be Clone but RateLimiter
        // contains a Mutex and can't be cloned naively.
        rate_limiter: Arc::new(auth::ratelimit::RateLimiter::new()),
    });

    // ── Router ─────────────────────────────────────────────────────────────────
    // Axum matches routes in declaration order. The handler's type signature
    // (via AuthUser/AdminUser extractors) enforces auth — not a middleware layer.
    let app = Router::new()
        // ── Public ────────────────────────────────────────────────────────────
        .route("/health", get(routes::health::handler))
        .route("/auth/register", post(auth::login::register))
        .route("/auth/login",    post(auth::login::login))
        .route("/auth/ctftime",          get(auth::ctftime::redirect))
        .route("/auth/ctftime/callback", get(auth::ctftime::callback))
        // ── Authenticated — competitors ────────────────────────────────────────
        .route("/challenges",            get(routes::challenges::list_challenges))
        .route("/challenges/:id",        get(routes::challenges::get_challenge))
        .route("/challenges/:id/submit", post(routes::challenges::submit_flag))
        .route("/scoreboard/users",      get(routes::scoreboard::user_scores))
        .route("/scoreboard/teams",      get(routes::scoreboard::team_scores))
        .route("/users/me",              get(routes::users::me))
        // ── Teams ─────────────────────────────────────────────────────────────
        // Separate resource from /users because teams have their own lifecycle.
        .route("/teams",      post(routes::teams::create_team))
        .route("/teams/join", post(routes::teams::join_team))
        .route("/teams/leave", delete(routes::teams::leave_team))
        .route("/teams/me",   get(routes::teams::my_team))
        .route("/teams/:id",  get(routes::teams::get_team))
        // ── Admin only ────────────────────────────────────────────────────────
        // AdminUser extractor in each handler enforces the admin requirement.
        .route("/admin/challenges",            get(routes::admin::list_challenges))
        .route("/admin/challenges",            post(routes::admin::create_challenge))
        .route("/admin/challenges/:id",        put(routes::admin::update_challenge))
        .route("/admin/challenges/:id",        delete(routes::admin::delete_challenge))
        .route("/admin/challenges/:id/toggle", patch(routes::admin::toggle_challenge))
        .route("/admin/users",                 get(routes::admin::list_users))
        // Attach shared state. Axum clones the Arc<AppState> into each request.
        .with_state(state);

    // ── Bind + serve ───────────────────────────────────────────────────────────
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind port 3000");
    tracing::info!("listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
