// routes/teams.rs — team management: create, join via invite code, leave, view.
//
// Teams are optional — solo players have team_id = NULL. A team can be created
// by any logged-in user; members share a total score on the scoreboard.
//
// Invite-code flow:
//   1. Player A calls POST /teams → gets back { invite_code: "a1b2c3d4" }
//   2. Player A shares the code with teammates out-of-band (Discord, etc.)
//   3. Players B/C call POST /teams/join { invite_code: "a1b2c3d4" }
//
// CTFtime teams: when a user logs in via CTFtime OAuth, their CTFtime team is
// upserted into our teams table (see auth/ctftime.rs). Those teams don't have
// invite codes and can't be manually joined — membership comes from CTFtime.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::middleware::AuthUser,
    error::AppError,
    state::AppState,
};

// ── Response types ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct TeamResponse {
    pub id:           Uuid,
    pub name:         String,
    // Invite code is revealed only to members (see get_team).
    pub invite_code:  Option<String>,
    pub ctftime_id:   Option<i32>,
    pub member_count: i64,
}

#[derive(Serialize)]
pub struct TeamMember {
    pub id:       Uuid,
    pub username: String,
    pub score:    i64,
}

#[derive(Serialize)]
pub struct TeamDetail {
    pub id:          Uuid,
    pub name:        String,
    pub invite_code: Option<String>,
    pub ctftime_id:  Option<i32>,
    pub members:     Vec<TeamMember>,
    pub total_score: i64,
}

// ── Request types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateTeamRequest {
    pub name: String,
}

#[derive(Deserialize)]
pub struct JoinTeamRequest {
    pub invite_code: String,
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Generates an 8-character hex invite code from a random UUID.
///
/// UUID v4 uses the OS CSPRNG (cryptographically secure random number generator),
/// so the 32 bits in 8 hex chars have 2^32 ≈ 4 billion possible values.
/// That's enough entropy to make brute-forcing impractical for a CTF.
fn generate_invite_code() -> String {
    // Uuid::new_v4().simple() formats without hyphens: "a1b2c3d4e5f60718..."
    // We take the first 8 characters.
    Uuid::new_v4().simple().to_string()[..8].to_string()
}

// ── Handlers ───────────────────────────────────────────────────────────────────

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
        return Err(AppError::BadRequest("team name must be 64 characters or fewer".into()));
    }

    // Ensure the user isn't already on a team.
    let existing_team: Option<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
            .bind(auth.user_id)
            .fetch_one(&state.pool)
            .await?;

    if existing_team.is_some() {
        return Err(AppError::Conflict(
            "you are already on a team — leave it first".into(),
        ));
    }

    let invite_code = generate_invite_code();

    // Create the team. The UNIQUE constraint on teams.name catches duplicates.
    let team_id: Uuid = sqlx::query_scalar(
        "INSERT INTO teams (name, invite_code) VALUES ($1, $2) RETURNING id",
    )
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

    // Put the creator on the team immediately.
    sqlx::query("UPDATE users SET team_id = $1 WHERE id = $2")
        .bind(team_id)
        .bind(auth.user_id)
        .execute(&state.pool)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(TeamResponse {
            id:           team_id,
            name:         body.name.trim().to_string(),
            invite_code:  Some(invite_code),
            ctftime_id:   None,
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
    let existing_team: Option<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
            .bind(auth.user_id)
            .fetch_one(&state.pool)
            .await?;

    if existing_team.is_some() {
        return Err(AppError::Conflict(
            "you are already on a team — leave it first".into(),
        ));
    }

    // Look up the team by invite code.
    // We use a tuple query to fetch multiple columns in one hit.
    let team = sqlx::query_as::<_, (Uuid, String, Option<i32>)>(
        "SELECT id, name, ctftime_id FROM teams WHERE invite_code = $1",
    )
    .bind(body.invite_code.trim())
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let (team_id, team_name, ctftime_id) = team;

    // Count current members before adding the new one (for the response).
    let member_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE team_id = $1")
            .bind(team_id)
            .fetch_one(&state.pool)
            .await?;

    // Join.
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
    let team_id: Option<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
            .bind(auth.user_id)
            .fetch_one(&state.pool)
            .await?;

    let team_id =
        team_id.ok_or_else(|| AppError::BadRequest("you are not on a team".into()))?;

    // Remove the user from the team.
    sqlx::query("UPDATE users SET team_id = NULL WHERE id = $1")
        .bind(auth.user_id)
        .execute(&state.pool)
        .await?;

    // If the team is now empty and has no CTFtime association, delete it.
    // We keep CTFtime-linked teams because they may be rejoined via OAuth —
    // deleting them would cause a foreign key conflict on re-upsert.
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
    let team_id: Option<Uuid> =
        sqlx::query_scalar("SELECT team_id FROM users WHERE id = $1")
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

// ── Shared query logic ─────────────────────────────────────────────────────────

// Shared between get_team and my_team to avoid duplicating the big JOIN.
async fn get_team_by_id(
    state: &Arc<AppState>,
    team_id: Uuid,
    include_invite_code: bool,
) -> Result<Json<TeamDetail>, AppError> {
    // Fetch team row.
    let team = sqlx::query_as::<_, (String, Option<String>, Option<i32>)>(
        "SELECT name, invite_code, ctftime_id FROM teams WHERE id = $1",
    )
    .bind(team_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or(AppError::NotFound)?;

    let (name, invite_code, ctftime_id) = team;

    // Fetch members with their per-user scores from the view we created in the migration.
    // The user_scores VIEW lives in 001_initial.sql — it JOINs users + solves + challenges.
    #[derive(sqlx::FromRow)]
    struct MemberRow {
        id:       Uuid,
        username: String,
        score:    i64,
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
        invite_code: if include_invite_code { invite_code } else { None },
        ctftime_id,
        total_score,
        members: members
            .into_iter()
            .map(|m| TeamMember {
                id:       m.id,
                username: m.username,
                score:    m.score,
            })
            .collect(),
    }))
}
