use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::crypto::jwt, db::models::User, error::AppError, state::AppState};

// request/response types
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

// handlers
// post /auth/register
// state is axum's built in shared state extractor
// json parses req body into registerrequest
// both are extracted before handler body run

pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    let pwd_hash = bcrypt::hash(&body.password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt hash fail: {e}")))?;
    let uid: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash)
        VALUES ($1, $2, $3)
        RETURNING id",
    )
    .bind(&body.username)
    .bind(&body.email)
    .bind(&pwd_hash)
    .fetch_one(&state.pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err)
            if db_err.constraint() == Some("users_username_key")
                || db_err.constraint() == Some("users_email_key") =>
        {
            AppError::Conflict("username or email already taken".into())
        }
        other => AppError::Database(other),
    })?;
    let token = jwt::create_token(&state.jwt_secret, uid, &body.username, false)?;
    Ok((StatusCode::CREATED, Json(AuthResponse { token })))
}

// post /auth/login
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;
    // pwd_hash is None if this account was created via CTFtime OAuth.
    // Tell them to log in with CTFtime instead of returning a confusing 401.
    let hash = user
        .pwd_hash
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("this account uses CTFtime login".into()))?;

    let valid = bcrypt::verify(&body.password, hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt verify failed: {e}")))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }
    let token = jwt::create_token(&state.jwt_secret, user.id, &user.username, user.is_admin)?;
    Ok(Json(AuthResponse { token }))
}
