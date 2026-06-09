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

use state::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let db_url=std::env::var("DATABASE_URL")
        .expect("DATABASE_URL environment variable must be set");
    let jwt_secret=std::env::var("JWT_SECRET")
        .expect("JWT_SECRET environment variable must be set");
    let pool=db::connect(&db_url)
        .await
        .expect("failed to connect to database and run migrations");
    tracing::info!("database connected, migrations applied");
    // arc new wraps appstate in atomic reference couted pointer
    // clone is cheap
    let state = Arc::new(AppState { pool, jwt_secret });

    let app = Router::new()
        // ── Public ────────────────────────────────────────────────────────────
        .route("/health",         get(routes::health::handler))
        .route("/auth/register",  post(auth::login::register))
        .route("/auth/login",     post(auth::login::login))
        // ── Authenticated (any valid user) ────────────────────────────────────
        .route("/challenges",              get(routes::challenges::list_challenges))
        .route("/challenges/:id",          get(routes::challenges::get_challenge))
        .route("/challenges/:id/submit",   post(routes::challenges::submit_flag))
        .route("/scoreboard/users",        get(routes::scoreboard::user_scores))
        .route("/scoreboard/teams",        get(routes::scoreboard::team_scores))
        .route("/users/me",                get(routes::users::me))
        // ── Admin only ────────────────────────────────────────────────────────
        // The AdminUser extractor in each handler enforces the admin check.
        // No separate middleware layer needed — the type system handles it.
        .route("/admin/challenges",             get(routes::admin::list_challenges))
        .route("/admin/challenges",             post(routes::admin::create_challenge))
        .route("/admin/challenges/:id",         put(routes::admin::update_challenge))
        .route("/admin/challenges/:id",         delete(routes::admin::delete_challenge))
        .route("/admin/challenges/:id/toggle",  patch(routes::admin::toggle_challenge))
        .route("/admin/users",                  get(routes::admin::list_users))
        // Attach shared state. Axum clones the Arc into each handler call.
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();
    tracing::info!("listening on port 3000");
    axum::serve(listener, app).await.unwrap();
}

