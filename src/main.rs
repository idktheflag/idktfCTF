use std::sync::Arc;

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

mod auth;
mod db;
mod error;
mod routes;
mod state;

use state::{AppState, CtftimeConfig};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let db_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set (e.g. postgres://user:pass@localhost/ctf)");
    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set — use a long random string (e.g. openssl rand -hex 32)");
    let pool = db::connect(&db_url)
        .await
        .expect("failed to connect to PostgreSQL and run migrations");
    tracing::info!("database connected, migrations applied");
    let ctftime = match (
        std::env::var("CTFTIME_CLIENT_ID"),
        std::env::var("CTFTIME_CLIENT_SECRET"),
        std::env::var("CTFTIME_REDIRECT_URI"),
    ) {
        (Ok(client_id), Ok(client_secret), Ok(redirect_uri)) => {
            tracing::info!("CTFtime OAuth enabled (client_id={})", client_id);
            Some(CtftimeConfig {
                client_id,
                client_secret,
                redirect_uri,
            })
        }
        _ => {
            tracing::warn!("CTFtime OAuth disabled — set CTFTIME_CLIENT_ID, CTFTIME_CLIENT_SECRET, CTFTIME_REDIRECT_URI to enable");
            None
        }
    };
    let frontend_url =
        std::env::var("FRONTEND_URL").unwrap_or_else(|_| "http://localhost:4321".to_string());
    let state = Arc::new(AppState {
        pool,
        jwt_secret,
        http: reqwest::Client::new(),
        ctftime,
        frontend_url,
        rate_limiter: Arc::new(auth::ratelimit::RateLimiter::new()),
    });

    let app = Router::new()
        // ── Public ────────────────────────────────────────────────────────────
        .route("/health", get(routes::health::handler))
        .route("/auth/register", post(auth::login::register))
        .route("/auth/login", post(auth::login::login))
        .route("/auth/ctftime", get(auth::ctftime::redirect))
        .route("/auth/ctftime/callback", get(auth::ctftime::callback))
        // ── Authenticated — competitors ────────────────────────────────────────
        .route("/challenges", get(routes::challenges::list_challenges))
        .route("/challenges/:id", get(routes::challenges::get_challenge))
        .route(
            "/challenges/:id/submit",
            post(routes::challenges::submit_flag),
        )
        .route("/scoreboard/users", get(routes::scoreboard::user_scores))
        .route("/scoreboard/teams", get(routes::scoreboard::team_scores))
        .route("/users/me", get(routes::users::me))
        // ── Teams ─────────────────────────────────────────────────────────────
        .route("/teams", post(routes::teams::create_team))
        .route("/teams/join", post(routes::teams::join_team))
        .route("/teams/leave", delete(routes::teams::leave_team))
        .route("/teams/me", get(routes::teams::my_team))
        .route("/teams/:id", get(routes::teams::get_team))
        // ── Admin only ────────────────────────────────────────────────────────
        .route("/admin/challenges", get(routes::admin::list_challenges))
        .route("/admin/challenges", post(routes::admin::create_challenge))
        .route(
            "/admin/challenges/:id",
            put(routes::admin::update_challenge),
        )
        .route(
            "/admin/challenges/:id",
            delete(routes::admin::delete_challenge),
        )
        .route(
            "/admin/challenges/:id/toggle",
            patch(routes::admin::toggle_challenge),
        )
        .route("/admin/users", get(routes::admin::list_users))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind port 3000");
    tracing::info!("listening on 0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
