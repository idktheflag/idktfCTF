// routes/scoreboard.rs — user and team leaderboards.

use std::sync::Arc;

use axum::{extract::State, Json};
use chrono::{DateTime, Utc};
use serde::Serialize;
use uuid::Uuid;

use crate::{auth::middleware::AuthUser, error::AppError, state::AppState};

// These structs map to the user_scores and team_scores VIEWs in the DB.
// sqlx::FromRow is needed so sqlx can deserialize the query result.
// SUM(integer) returns bigint in Postgres → i64 in Rust.
// COUNT(*) also returns bigint → i64.
#[derive(sqlx::FromRow)]
struct UserScoreRow {
    id:            Uuid,
    username:      String,
    team_id:       Option<Uuid>,
    score:         i64,
    solve_count:   i64,
    last_solve_at: Option<DateTime<Utc>>,
}

#[derive(sqlx::FromRow)]
struct TeamScoreRow {
    id:            Uuid,
    name:          String,
    score:         i64,
    solve_count:   i64,
    last_solve_at: Option<DateTime<Utc>>,
}

// Public response types (what the API sends to clients).
#[derive(Serialize)]
pub struct UserScore {
    pub rank:          usize,
    pub id:            Uuid,
    pub username:      String,
    pub team_id:       Option<Uuid>,
    pub score:         i64,
    pub solve_count:   i64,
    pub last_solve_at: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
pub struct TeamScore {
    pub rank:          usize,
    pub id:            Uuid,
    pub name:          String,
    pub score:         i64,
    pub solve_count:   i64,
    pub last_solve_at: Option<DateTime<Utc>>,
}

// GET /scoreboard/users
pub async fn user_scores(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser, // _ prefix = we need auth enforced but don't use the value
) -> Result<Json<Vec<UserScore>>, AppError> {
    // Query the view. ORDER BY score DESC so rank 1 has the highest score.
    // Tie-break by last_solve_at ASC: solved earlier = higher rank (fairer).
    let rows = sqlx::query_as::<_, UserScoreRow>(
        "SELECT * FROM user_scores ORDER BY score DESC, last_solve_at ASC NULLS LAST",
    )
    .fetch_all(&state.pool)
    .await?;

    // enumerate() gives us (index, value); index + 1 is the 1-based rank.
    let scores = rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| UserScore {
            rank:          i + 1,
            id:            r.id,
            username:      r.username,
            team_id:       r.team_id,
            score:         r.score,
            solve_count:   r.solve_count,
            last_solve_at: r.last_solve_at,
        })
        .collect();

    Ok(Json(scores))
}

// GET /scoreboard/teams
pub async fn team_scores(
    State(state): State<Arc<AppState>>,
    _auth: AuthUser,
) -> Result<Json<Vec<TeamScore>>, AppError> {
    let rows = sqlx::query_as::<_, TeamScoreRow>(
        "SELECT * FROM team_scores ORDER BY score DESC, last_solve_at ASC NULLS LAST",
    )
    .fetch_all(&state.pool)
    .await?;

    let scores = rows
        .into_iter()
        .enumerate()
        .map(|(i, r)| TeamScore {
            rank:          i + 1,
            id:            r.id,
            name:          r.name,
            score:         r.score,
            solve_count:   r.solve_count,
            last_solve_at: r.last_solve_at,
        })
        .collect();

    Ok(Json(scores))
}
