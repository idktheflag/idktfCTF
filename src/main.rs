use axum::{Router, routing::{get, post}};

mod routes;
mod auth; 

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/health",get(routes::health::handler))
        .route("/auth/register", post(auth::login::register))
        .route("/auth/login", post(auth::login::login));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener,app).await.unwrap();
}
