use std::{collections::HashSet, sync::Arc};

use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::middleware::AuthUser,
    db::models::Challenge,
    error::AppError,
    state::AppState,
};

#[derive(Serialize)]
pub struct ChallengeListItem {
    pub id:           Uuid,
    pub title:        String,
    pub category:     String,
    pub points:       i32,
    pub hint:         Option<String>,
    pub solved_by_me: bool,
}

#[derive(Serialize)]
pub struct ChallengeDetail {
    pub id:          Uuid,
    pub title:       String,
    pub description: String,
    pub category:    String,
    pub points:      i32,
    pub hint:        Option<String>,
    pub author:      Option<String>,
    pub created_at:  DateTime<Utc>,
    pub solved_by_me: bool,
}

#[derive(Deserialize)]
pub struct SubmitRequest {
    pub flag: String,
}

#[derive(Serialize)]
pub struct SubmitResponse {
    pub correct:       bool,
    pub first_blood:   bool,
    pub points_earned: i32,
}

// GET /challenges
// Returns all visible challenges, tagged with whether the caller solved them.
pub async fn list_challenges(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<Vec<ChallengeListItem>>, AppError> {
    // Fetch every visible challenge, ordered for a nice UI.
    let challenges = sqlx::query_as::<_, Challenge>(
        "SELECT * FROM challenges WHERE is_visible = true ORDER BY category, points",
    )
    .fetch_all(&state.pool)
    .await?;
    let solved_ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT challenge_id FROM solves WHERE user_id = $1",
    )
    .bind(auth.user_id)
    .fetch_all(&state.pool)
    .await?;
    let solved_set: HashSet<Uuid> = solved_ids.into_iter().collect();

    let items = challenges
        .into_iter()
        .map(|c| ChallengeListItem {
            solved_by_me: solved_set.contains(&c.id),
            id:       c.id,
            title:    c.title,
            category: c.category,
            points:   c.points,
            hint:     c.hint,
        })
        .collect();

    Ok(Json(items))
}

// GET /challenges/:id
pub async fn get_challenge(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ChallengeDetail>, AppError> {
    let challenge = sqlx::query_as::<_, Challenge>(
        "SELECT * FROM challenges WHERE id = $1 AND is_visible = true",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let solved: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM solves WHERE user_id = $1 AND challenge_id = $2",
    )
    .bind(auth.user_id)
    .bind(id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(Json(ChallengeDetail {
        solved_by_me: solved.is_some(),
        id:          challenge.id,
        title:       challenge.title,
        description: challenge.description,
        category:    challenge.category,
        points:      challenge.points,
        hint:        challenge.hint,
        author:      challenge.author,
        created_at:  challenge.created_at,
    }))
}

// POST /challenges/:id/submit
pub async fn submit_flag(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(challenge_id): Path<Uuid>,
    Json(body): Json<SubmitRequest>,
) -> Result<Json<SubmitResponse>, AppError> {
    state.rate_limiter.check(auth.user_id).await?;
    let challenge = sqlx::query_as::<_, Challenge>(
        "SELECT * FROM challenges WHERE id = $1 AND is_visible = true",
    )
    .bind(challenge_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let already_solved: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM solves WHERE user_id = $1 AND challenge_id = $2",
    )
    .bind(auth.user_id)
    .bind(challenge_id)
    .fetch_optional(&state.pool)
    .await?;

    if already_solved.is_some() {
        return Err(AppError::Conflict("already solved".into()));
    }

    // Wrong flag — return false without recording anything.
    if challenge.flag != body.flag {
        return Ok(Json(SubmitResponse {
            correct: false, first_blood: false, points_earned: 0,
        }));
    }
    let mut tx = state.pool.begin().await?;
    let solve_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM solves WHERE challenge_id = $1",
    )
    .bind(challenge_id)
    .fetch_one(&mut *tx)
    .await?;

    let is_first_blood = solve_count == 0;

    sqlx::query(
        "INSERT INTO solves (user_id, challenge_id, is_first_blood) VALUES ($1, $2, $3)",
    )
    .bind(auth.user_id)
    .bind(challenge_id)
    .bind(is_first_blood)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(Json(SubmitResponse {
        correct: true,
        first_blood: is_first_blood,
        points_earned: challenge.points,
    }))
}

