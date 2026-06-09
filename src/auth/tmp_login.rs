// auth/login.rs — registration and login handlers.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::crypto::jwt,
    db::models::User,
    error::AppError,
    state::AppState,
};

// ── Request / response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub email:    String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email:    String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

// ── Handlers ─────────────────────────────────────────────────────────────────

// POST /auth/register
//
// State(state) is Axum's built-in extractor for shared state.
// Json(body) parses the request body as JSON into RegisterRequest.
// Both are extracted before the handler body runs.
pub async fn register(
    State(state): State<Arc<AppState>>,
    Json(body):   Json<RegisterRequest>,
) -> Result<(StatusCode, Json<AuthResponse>), AppError> {
    // bcrypt hashes the password with a cost factor of 12 (DEFAULT_COST).
    // Cost 12 means 2^12 = 4096 iterations of the Blowfish cipher.
    // This is intentionally slow (~200ms) to make brute-force attacks expensive.
    // The hash includes the cost factor and a random salt, so two identical
    // passwords produce different hashes every time.
    let password_hash = bcrypt::hash(&body.password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt hash failed: {e}")))?;

    // INSERT ... RETURNING id lets us get the new UUID in one round-trip.
    // We use query_as (not the query_as! macro) because the macro needs a
    // live DATABASE_URL at compile time; the non-macro version checks at runtime.
    let user_id: Uuid = sqlx::query_scalar(
        "INSERT INTO users (username, email, password_hash)
         VALUES ($1, $2, $3)
         RETURNING id",
    )
    .bind(&body.username)
    .bind(&body.email)
    .bind(&password_hash)
    .fetch_one(&state.pool)
    .await
    // Map database errors: unique-constraint violations become 409 Conflict.
    // db_err.constraint() returns the constraint name defined in the migration.
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err)
            if db_err.constraint() == Some("users_username_key")
                || db_err.constraint() == Some("users_email_key") =>
        {
            AppError::Conflict("username or email already taken".into())
        }
        other => AppError::Database(other),
    })?;

    let token = jwt::create_token(&state.jwt_secret, user_id, &body.username, false)?;
    Ok((StatusCode::CREATED, Json(AuthResponse { token })))
}

// POST /auth/login
pub async fn login(
    State(state): State<Arc<AppState>>,
    Json(body):   Json<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    // Look up the user by email. fetch_optional returns None if not found.
    // We return the same error (Unauthorized) whether the email doesn't exist
    // OR the password is wrong — this prevents user enumeration attacks
    // (an attacker shouldn't be able to tell which emails are registered).
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
        .bind(&body.email)
        .fetch_optional(&state.pool)
        .await?
        .ok_or(AppError::Unauthorized)?;

    // bcrypt::verify re-hashes the provided password with the salt stored in
    // the hash string and compares the results in constant time.
    let valid = bcrypt::verify(&body.password, &user.password_hash)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("bcrypt verify failed: {e}")))?;

    if !valid {
        return Err(AppError::Unauthorized);
    }

    let token = jwt::create_token(&state.jwt_secret, user.id, &user.username, user.is_admin)?;
    Ok(Json(AuthResponse { token }))
}
