// routes/admin.rs — admin-only challenge management and user listing.
//
// Every handler here takes AdminUser instead of AuthUser.
// AdminUser's FromRequestParts implementation checks is_admin == true,
// so a regular user hitting these routes gets 403 Forbidden.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::middleware::AdminUser,
    db::models::{Challenge, User},
    error::AppError,
    state::AppState,
};

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateChallengeRequest {
    pub title:       String,
    pub description: String,
    pub category:    String,
    pub points:      i32,
    pub flag:        String,
    pub hint:        Option<String>,
    pub author:      Option<String>,
}

// PUT reuses the same shape — every field is required on update.
pub type UpdateChallengeRequest = CreateChallengeRequest;

#[derive(Serialize)]
pub struct CreatedResponse {
    pub id: Uuid,
}

// Admin challenge response includes the flag (unlike the public endpoints).
#[derive(Serialize)]
pub struct AdminChallengeResponse {
    pub id:          Uuid,
    pub title:       String,
    pub description: String,
    pub category:    String,
    pub points:      i32,
    pub flag:        String,
    pub hint:        Option<String>,
    pub is_visible:  bool,
    pub author:      Option<String>,
}

#[derive(Serialize)]
pub struct AdminUserResponse {
    pub id:         Uuid,
    pub username:   String,
    pub email:      Option<String>,
    pub is_admin:   bool,
    pub team_id:    Option<Uuid>,
    pub ctftime_id: Option<i32>,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// POST /admin/challenges
pub async fn create_challenge(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Json(body): Json<CreateChallengeRequest>,
) -> Result<(StatusCode, Json<CreatedResponse>), AppError> {
    let id: Uuid = sqlx::query_scalar(
        "INSERT INTO challenges (title, description, category, points, flag, hint, author)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id",
    )
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.category)
    .bind(body.points)
    .bind(&body.flag)
    .bind(&body.hint)
    .bind(&body.author)
    .fetch_one(&state.pool)
    .await?;

    Ok((StatusCode::CREATED, Json(CreatedResponse { id })))
}

// PUT /admin/challenges/:id
// Replaces all fields. Returns 204 No Content on success, 404 if not found.
pub async fn update_challenge(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateChallengeRequest>,
) -> Result<StatusCode, AppError> {
    let affected = sqlx::query(
        "UPDATE challenges
         SET title=$1, description=$2, category=$3, points=$4, flag=$5, hint=$6, author=$7
         WHERE id=$8",
    )
    .bind(&body.title)
    .bind(&body.description)
    .bind(&body.category)
    .bind(body.points)
    .bind(&body.flag)
    .bind(&body.hint)
    .bind(&body.author)
    .bind(id)
    .execute(&state.pool)
    .await?
    // rows_affected() tells us if the UPDATE matched any row.
    .rows_affected();

    if affected == 0 {
        Err(AppError::NotFound)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// DELETE /admin/challenges/:id
pub async fn delete_challenge(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let affected = sqlx::query("DELETE FROM challenges WHERE id = $1")
        .bind(id)
        .execute(&state.pool)
        .await?
        .rows_affected();

    if affected == 0 {
        Err(AppError::NotFound)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// PATCH /admin/challenges/:id/toggle
// Flips is_visible without requiring the client to send the full challenge.
pub async fn toggle_challenge(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, AppError> {
    let affected = sqlx::query(
        "UPDATE challenges SET is_visible = NOT is_visible WHERE id = $1",
    )
    .bind(id)
    .execute(&state.pool)
    .await?
    .rows_affected();

    if affected == 0 {
        Err(AppError::NotFound)
    } else {
        Ok(StatusCode::NO_CONTENT)
    }
}

// GET /admin/users
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
) -> Result<Json<Vec<AdminUserResponse>>, AppError> {
    let users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at")
        .fetch_all(&state.pool)
        .await?;

    let response = users
        .into_iter()
        .map(|u| AdminUserResponse {
            id:         u.id,
            username:   u.username,
            email:      u.email,
            is_admin:   u.is_admin,
            team_id:    u.team_id,
            ctftime_id: u.ctftime_id,
        })
        .collect();

    Ok(Json(response))
}

// GET /admin/challenges — returns challenges including flags
pub async fn list_challenges(
    State(state): State<Arc<AppState>>,
    _admin: AdminUser,
) -> Result<Json<Vec<AdminChallengeResponse>>, AppError> {
    let challenges =
        sqlx::query_as::<_, Challenge>("SELECT * FROM challenges ORDER BY created_at")
            .fetch_all(&state.pool)
            .await?;

    let response = challenges
        .into_iter()
        .map(|c| AdminChallengeResponse {
            id:          c.id,
            title:       c.title,
            description: c.description,
            category:    c.category,
            points:      c.points,
            flag:        c.flag,
            hint:        c.hint,
            is_visible:  c.is_visible,
            author:      c.author,
        })
        .collect();

    Ok(Json(response))
}
