use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{auth::middleware::AuthUser, error::AppError, state::AppState};

#[derive(Serialize)]
pub struct TeamResponse {
    pub id: Uuid,
    pub name: String,
    pub invite_code: Option<String>, // revealed only to members, see get_team
    pub ctftime_id: Option<i32>,
    pub member_count: i64,
}

#[derive(Serialize)]
pub struct TeamMember {
    pub id: Uuid,
    pub username: String,
    pub score: i64,
}

#[derive(Serialize)]
pub struct TeamDetail {
    pub id: Uuid,
    pub name: String,
    pub invite_code: Option<String>,
    pub ctftime_id: Option<i32>,
    pub members: Vec<TeamMember>,
    pub total_score: i64,
}

#[derive(Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct JoinTeamRequest {
    pub invite_code: String,
}

fn generate_invite_code() -> String {
    Uuid::new_v4().simple().to_string()[..8].to_string()
}

// POST /teams
// Create a new team. The caller must not already be on a team.
// Returns 201 Created with the new team (including invite code).
pub async fn create_team(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Json(body): Json<CreateTeamRequest>,
) -> Result<(StatusCode, Json<TeamResponse>), AppError> {
    if body.name.trim().is_empty() {
        return Err(AppError::BadRequest("team name cannot be empty".into()));
    }
    if body.name.len() > 64 {
        return Err(AppError::BadRequest(
            "team name must be 64 characters or fewer".into(),
        ));
    }

    // Ensure the user isn't already on a team.
    let existing_team: Option<Uuid> = sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.pool)
        .await?;

    if existing_team.is_some() {
        return Err(AppError::Conflict(
            "you are already on a team — leave it first".into(),
        ));
    }

    let invite_code = generate_invite_code();

    let team_id: Uuid =
        sqlx::query_scalar("INSERT INTO teams (name, invite_code) VALUES ($1, $2) RETURNING id")
            .bind(body.name.trim())
            .bind(&invite_code)
            .fetch_one(&state.pool)
            .await
            .map_err(|e| {
                if let sqlx::Error::Database(ref de) = e {
                    if de.constraint() == Some("teams_name_key") {
                        return AppError::Conflict("a team with that name already exists".into());
                    }
                }
                AppError::Database(e)
            })?;

    sqlx::query("UPDATE users SET team_id = $1 WHERE id = $2")
        .bind(team_id)
        .bind(auth.user_id)
        .execute(&state.pool)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(TeamResponse {
            id: team_id,
            name: body.name.trim().to_string(),
            invite_code: Some(invite_code),
            ctftime_id: None,
            member_count: 1,
        }),
    ))
}

// POST /teams/join
// Join an existing team by invite code. Fails if already on a team.
pub async fn join_team(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Json(body): Json<JoinTeamRequest>,
) -> Result<Json<TeamResponse>, AppError> {
    // Check for existing membership.
    let existing_team: Option<Uuid> = sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.pool)
        .await?;

    if existing_team.is_some() {
        return Err(AppError::Conflict(
            "you are already on a team — leave it first".into(),
        ));
    }

    let team = sqlx::query_as::<_, (Uuid, String, Option<i32>)>(
        "SELECT id, name, ctftime_id FROM teams WHERE invite_code = $1",
    )
    .bind(body.invite_code.trim())
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let (team_id, team_name, ctftime_id) = team;

    let member_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE team_id = $1")
        .bind(team_id)
        .fetch_one(&state.pool)
        .await?;

    sqlx::query("UPDATE users SET team_id = $1 WHERE id = $2")
        .bind(team_id)
        .bind(auth.user_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(TeamResponse {
        id: team_id,
        name: team_name,
        // Members can see the invite code so they can share it.
        invite_code: Some(body.invite_code.trim().to_string()),
        ctftime_id,
        member_count: member_count + 1,
    }))
}

// DELETE /teams/leave
// Leave the current team. If the team becomes empty and has no CTFtime link,
// it's deleted to avoid cluttering the scoreboard.
pub async fn leave_team(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<StatusCode, AppError> {
    let team_id: Option<Uuid> = sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.pool)
        .await?;

    let team_id = team_id.ok_or_else(|| AppError::BadRequest("you are not on a team".into()))?;

    sqlx::query("UPDATE users SET team_id = NULL WHERE id = $1")
        .bind(auth.user_id)
        .execute(&state.pool)
        .await?;
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE team_id = $1")
        .bind(team_id)
        .fetch_one(&state.pool)
        .await?;

    if remaining == 0 {
        sqlx::query("DELETE FROM teams WHERE id = $1 AND ctftime_id IS NULL")
            .bind(team_id)
            .execute(&state.pool)
            .await?;
    }

    // 204 No Content is the conventional response for a successful DELETE
    // that doesn't return a body.
    Ok(StatusCode::NO_CONTENT)
}

// GET /teams/me
// Return the caller's current team (or 404 if not on one).
pub async fn my_team(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
) -> Result<Json<TeamDetail>, AppError> {
    let team_id: Option<Uuid> = sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
        .bind(auth.user_id)
        .fetch_one(&state.pool)
        .await?;

    let team_id = team_id.ok_or(AppError::NotFound)?;

    get_team_by_id(&state, team_id, true).await
}

// GET /teams/:id
// Get a team's public info. Members additionally see the invite code.
pub async fn get_team(
    State(state): State<Arc<AppState>>,
    auth: AuthUser,
    Path(team_id): Path<Uuid>,
) -> Result<Json<TeamDetail>, AppError> {
    // Is the requester a member of this team?
    let requester_team: Option<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
            .bind(auth.user_id)
            .fetch_one(&state.pool)
            .await?;

    let is_member = requester_team == Some(team_id);

    get_team_by_id(&state, team_id, is_member).await
}

async fn get_team_by_id(
    state: &Arc<AppState>,
    team_id: Uuid,
    include_invite_code: bool,
) -> Result<Json<TeamDetail>, AppError> {
    let team = sqlx::query_as::<_, (String, Option<String>, Option<i32>)>(
        "SELECT name, invite_code, ctftime_id FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;
    let (name, invite_code, ctftime_id) = team;
    #[derive(sqlx::FromRow)]
    struct MemberRow {
        id: Uuid,
        username: String,
        score: i64,
    }

    let members: Vec<MemberRow> = sqlx::query_as(
        "SELECT u.id, u.username, COALESCE(us.score, 0)::BIGINT AS score
         FROM users u
         LEFT JOIN user_scores us ON us.id = u.id
         WHERE u.team_id = $1
         ORDER BY score DESC, u.username ASC",
    )
    .bind(team_id)
    .fetch_all(&state.pool)
    .await?;

    let total_score: i64 = members.iter().map(|m| m.score).sum();

    Ok(Json(TeamDetail {
        id: team_id,
        name,
        invite_code: if include_invite_code {
            invite_code
        } else {
            None
        },
        ctftime_id,
        total_score,
        members: members
            .into_iter()
            .map(|m| TeamMember {
                id: m.id,
                username: m.username,
                score: m.score,
            })
            .collect(),
    }))
}
