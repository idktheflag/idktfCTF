use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub pwd_hash: String,
    pub is_admin: bool,
    pub team_id: Option<Uuid>, //none=solo
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Challenge {
    pub id: Uuid,
    pub title: String,
    pub description: String,
    pub category: String,
    pub points: i32,
    pub flag: String, // plaintext, so never send to non-admin clients - do we want to wrap this?
    pub hint: Option<String>,
    pub is_visible: bool,
    pub author: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Solve {
    pub id:             Uuid,
    pub user_id:        Uuid,
    pub challenge_id:   Uuid,
    pub is_first_blood: bool,
    pub solved_at:      DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Team {
    pub id:          Uuid,
    pub name:        String,
    pub invite_code: Option<String>,
    pub created_at:  DateTime<Utc>,
}
