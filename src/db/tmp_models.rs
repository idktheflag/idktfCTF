// db/models.rs — Rust structs that map 1:1 to database rows.
//
// sqlx::FromRow lets sqlx deserialize a query result directly into these
// structs by matching column names to field names. No manual mapping needed.
//
// These structs are "internal" types — they may contain sensitive fields
// (like password_hash, flag) that we strip out before sending responses.

use chrono::{DateTime, Utc};
use uuid::Uuid;

// Mirrors the `users` table exactly.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct User {
    pub id:            Uuid,
    pub username:      String,
    pub email:         String,
    pub password_hash: String, // bcrypt hash — never send this to clients
    pub is_admin:      bool,
    pub team_id:       Option<Uuid>, // None = solo player
    pub created_at:    DateTime<Utc>,
}

// Mirrors the `challenges` table exactly.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Challenge {
    pub id:          Uuid,
    pub title:       String,
    pub description: String,
    pub category:    String,
    pub points:      i32,
    pub flag:        String, // plaintext — never send this to non-admin clients
    pub hint:        Option<String>,
    pub is_visible:  bool,
    pub author:      Option<String>,
    pub created_at:  DateTime<Utc>,
}

// Mirrors the `solves` table exactly.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Solve {
    pub id:             Uuid,
    pub user_id:        Uuid,
    pub challenge_id:   Uuid,
    pub is_first_blood: bool,
    pub solved_at:      DateTime<Utc>,
}

// Mirrors the `teams` table exactly.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Team {
    pub id:          Uuid,
    pub name:        String,
    pub invite_code: Option<String>,
    pub created_at:  DateTime<Utc>,
}
