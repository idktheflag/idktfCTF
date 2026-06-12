use chrono::{DateTime, Utc};
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    // Option because CTFtime OAuth may not provide an email address.
    pub email: Option<String>,
    // #[sqlx(rename = "...")] maps this field to a differently-named DB column.
    // We use pwd_hash in Rust (shorter) but the DB column is password_hash.
    // Option because CTFtime-only users authenticate via OAuth, not password.
    #[sqlx(rename = "password_hash")]
    pub pwd_hash: Option<String>,
    pub is_admin: bool,
    pub team_id: Option<Uuid>, // None = solo player
    // Set on first CTFtime OAuth login. None = password-only account.
    pub ctftime_id: Option<i32>,
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
#[allow(dead_code)]
pub struct Solve {
    pub id: Uuid,
    pub user_id: Uuid,
    pub challenge_id: Uuid,
    pub is_first_blood: bool,
    pub solved_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub invite_code: Option<String>,
    // Set when a team is created/linked via CTFtime OAuth.
    pub ctftime_id: Option<i32>,
    pub created_at: DateTime<Utc>,
}
