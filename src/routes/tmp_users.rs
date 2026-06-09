// routes/users.rs — user profile endpoints.

use std::sync::Arc;

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{auth::middleware::AuthUser, db::models::User, error::AppError, state::AppState};

// The public profile response. Notably absent: password_hash.
// Never serialize fields you wouldn't want the user to see.
#[derive(Serialize)]
pub struct UserProfile {
    pub id:         Uuid,
    pub username:   String,
    pub email:      Option<String>,
    pub is_admin:   bool,
    pub team_id:    Option<Uuid>,
    pub ctftime_id: Option<i32>,
    pub created_at: DateTime<Utc>,
}

// GET /users/me
// Returns the profile of the currently authenticated user.
pub async fn me(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<UserProfile>, AppError> {
    // We could return the claims directly (they have username/is_admin),
    // but hitting the DB ensures we return fresh data (e.g. if is_admin changed).
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_optional(&state.pool)
        .await?
        // A valid JWT for a deleted user returns 404, not a crash.
        .ok_or(AppError::NotFound)?;

    Ok(Json(UserProfile {
        id:         user.id,
        username:   user.username,
        email:      user.email,
        is_admin:   user.is_admin,
        team_id:    user.team_id,
        ctftime_id: user.ctftime_id,
        created_at: user.created_at,
    }))
}
