use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use crate::auth::crypto::jwt;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

pub async fn register(Json(body): Json<RegisterRequest>) -> impl IntoResponse {
    // TODO: hash password + save to db
    let token = jwt::create_token(&body.username).unwrap();
    (StatusCode::CREATED, Json(AuthResponse { token }))
}

pub async fn login(Json(body): Json<LoginRequest>) -> impl IntoResponse {
    // TODO: verify password from db
    let token = jwt::create_token(&body.email).unwrap();
    (StatusCode::OK, Json(AuthResponse { token }))
}


