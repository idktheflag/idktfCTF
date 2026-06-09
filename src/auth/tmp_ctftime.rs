// auth/ctftime.rs — CTFtime OAuth2 login and account linking.
//
// CTFtime is team-centric: a CTFtime "account" represents a team, not an
// individual. One CTFtime login = one team. Multiple members of the same
// real-world team would share one local account created via CTFtime OAuth.
//
// Two use-cases handled here:
//   1. New login  — no JWT in header → create or find account, return JWT
//   2. Linking    — valid JWT in header → attach ctftime_id to existing account
//
// OAuth2 authorization code flow recap:
//   Client → GET /auth/ctftime          (we redirect to CTFtime)
//   CTFtime → GET /auth/ctftime/callback?code=...&state=...
//   We POST code to CTFtime token endpoint → get access_token
//   We GET ctftime.org/user with access_token → get profile
//   We upsert local user/team, issue our JWT

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Redirect,
    Json,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    auth::{crypto::jwt, middleware::AuthUser},
    error::AppError,
    state::AppState,
};

type HmacSha256 = Hmac<Sha256>;

// ── CTFtime API response types ────────────────────────────────────────────────
// These match what oauth.ctftime.org/user returns.
// If CTFtime ever changes their response shape, update these structs.

#[derive(Deserialize)]
struct CtftimeProfile {
    // CTFtime team/user ID — this is what we store as ctftime_id
    id:   i32,
    // Team name — used as the local username for CTFtime accounts
    name: String,
    // Team info (present when "team" scope was requested)
    team: Option<CtftimeTeamInfo>,
}

#[derive(Deserialize)]
struct CtftimeTeamInfo {
    id:   i32,
    name: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

// ── Response type ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

// ── Query params ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code:  String,
    pub state: String,
}

// ── GET /auth/ctftime ─────────────────────────────────────────────────────────
//
// Builds the CTFtime authorization URL and redirects the user's browser there.
// If the user is already logged in (JWT in header), we embed their user ID in
// the state param so the callback knows to link rather than create.
//
// Option<AuthUser> is Axum's "optional extractor" pattern: the handler runs
// whether or not a valid JWT is present. None = anonymous, Some = logged in.
pub async fn redirect(
    State(state): State<Arc<AppState>>,
    maybe_auth: Option<AuthUser>,
) -> Result<Redirect, AppError> {
    let config = state.ctftime.as_ref()
        .ok_or_else(|| AppError::BadRequest("CTFtime OAuth is not configured".into()))?;

    // Build a signed state token to prevent CSRF attacks.
    // CSRF (Cross-Site Request Forgery): a malicious site could link to
    // /auth/ctftime/callback?code=stolen_code, tricking our server into
    // logging a victim in as someone else. The state param, checked on
    // callback, proves the callback originated from our own redirect.
    let state_token = generate_state(&state.jwt_secret, maybe_auth.map(|a| a.user_id));

    // Build the authorization URL. CTFtime will redirect back here after
    // the user authorizes our app.
    let url = format!(
        "https://oauth.ctftime.org/authorize\
         ?response_type=code\
         &client_id={}\
         &redirect_uri={}\
         &scope=profile+team\
         &state={}",
        config.client_id,
        urlencoding::encode(&config.redirect_uri),
        state_token,
    );

    Ok(Redirect::to(&url))
}

// ── GET /auth/ctftime/callback ────────────────────────────────────────────────
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackQuery>,
) -> Result<Json<AuthResponse>, AppError> {
    let config = state.ctftime.as_ref()
        .ok_or_else(|| AppError::BadRequest("CTFtime OAuth is not configured".into()))?;

    // ── Step 1: verify state (CSRF check) ─────────────────────────────────────
    // Returns the user_id we embedded at redirect time, if this is a link flow.
    let linking_user_id = verify_state(&state.jwt_secret, &params.state)?;

    // ── Step 2: exchange authorization code for access token ──────────────────
    // The code is single-use and short-lived (~60s). We POST it to CTFtime's
    // token endpoint along with our client credentials.
    let token_res = state.http
        .post("https://oauth.ctftime.org/token")
        // send_form encodes the body as application/x-www-form-urlencoded,
        // which is what OAuth2 token endpoints expect (not JSON).
        .form(&[
            ("grant_type",    "authorization_code"),
            ("code",          params.code.as_str()),
            ("redirect_uri",  config.redirect_uri.as_str()),
            ("client_id",     config.client_id.as_str()),
            ("client_secret", config.client_secret.as_str()),
        ])
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("CTFtime token request failed: {e}")))?
        .json::<TokenResponse>()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("CTFtime token parse failed: {e}")))?;

    // ── Step 3: fetch CTFtime profile ──────────────────────────────────────────
    let profile = state.http
        .get("https://oauth.ctftime.org/user")
        .bearer_auth(&token_res.access_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("CTFtime user request failed: {e}")))?
        .json::<CtftimeProfile>()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("CTFtime user parse failed: {e}")))?;

    // ── Step 4: upsert team if CTFtime team data is present ───────────────────
    // ON CONFLICT (ctftime_id) DO UPDATE means:
    //   - if no row with this ctftime_id exists → INSERT
    //   - if one does → UPDATE name (in case they renamed)
    // Either way, we get back the local team UUID.
    let team_id: Option<Uuid> = if let Some(ref team) = profile.team {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO teams (name, ctftime_id)
             VALUES ($1, $2)
             ON CONFLICT (ctftime_id) DO UPDATE SET name = EXCLUDED.name
             RETURNING id",
        )
        .bind(&team.name)
        .bind(team.id)
        .fetch_one(&state.pool)
        .await?;
        Some(id)
    } else {
        None
    };

    // ── Step 5: link or upsert user ───────────────────────────────────────────
    let (user_id, is_admin) = if let Some(existing_id) = linking_user_id {
        // Linking flow: the user is already logged in and wants to attach
        // their CTFtime identity to their existing local account.
        //
        // ON CONFLICT (ctftime_id) DO NOTHING guards against someone trying
        // to link a CTFtime account that another local account already owns.
        let rows = sqlx::query(
            "UPDATE users SET ctftime_id = $1, team_id = COALESCE($2, team_id)
             WHERE id = $3 AND ctftime_id IS NULL",
        )
        .bind(profile.id)
        .bind(team_id)
        .bind(existing_id)
        .execute(&state.pool)
        .await?
        .rows_affected();

        if rows == 0 {
            // Either the user already has a ctftime_id, or this ctftime_id
            // is already claimed by another account.
            return Err(AppError::Conflict(
                "CTFtime account already linked to a different user".into(),
            ));
        }

        // Fetch is_admin for the JWT
        let is_admin: bool = sqlx::query_scalar("SELECT is_admin FROM users WHERE id = $1")
            .bind(existing_id)
            .fetch_one(&state.pool)
            .await?;

        (existing_id, is_admin)
    } else {
        // Login/register flow: upsert by ctftime_id.
        // ON CONFLICT (ctftime_id) DO UPDATE lets returning users log back in
        // while also updating their name if they renamed on CTFtime.
        //
        // username conflict: if someone already registered locally with the
        // same username, we append their ctftime_id to disambiguate.
        let username = profile.name.clone();
        let result = sqlx::query_as::<_, (Uuid, bool)>(
            "INSERT INTO users (username, ctftime_id, team_id)
             VALUES ($1, $2, $3)
             ON CONFLICT (ctftime_id) DO UPDATE
               SET username = EXCLUDED.username,
                   team_id  = COALESCE(EXCLUDED.team_id, users.team_id)
             RETURNING id, is_admin",
        )
        .bind(&username)
        .bind(profile.id)
        .bind(team_id)
        .fetch_one(&state.pool)
        .await;

        match result {
            Ok(row) => row,
            Err(sqlx::Error::Database(ref e)) if e.constraint() == Some("users_username_key") => {
                // Username collision with a password-registered account.
                // Append ctftime_id to make it unique.
                let fallback_username = format!("{}_{}", profile.name, profile.id);
                sqlx::query_as::<_, (Uuid, bool)>(
                    "INSERT INTO users (username, ctftime_id, team_id)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (ctftime_id) DO UPDATE
                       SET team_id = COALESCE(EXCLUDED.team_id, users.team_id)
                     RETURNING id, is_admin",
                )
                .bind(&fallback_username)
                .bind(profile.id)
                .bind(team_id)
                .fetch_one(&state.pool)
                .await?
            }
            Err(e) => return Err(AppError::Database(e)),
        }
    };

    // ── Step 6: issue our JWT ─────────────────────────────────────────────────
    let final_username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;

    let token = jwt::create_token(&state.jwt_secret, user_id, &final_username, is_admin)?;
    Ok(Json(AuthResponse { token }))
}

// ── CSRF state helpers ────────────────────────────────────────────────────────

// Generates a signed state token: base64url(data) + "." + base64url(hmac)
// where data = "{user_id_or_empty}|{unix_timestamp}".
//
// Embedding a timestamp lets us expire state tokens after 10 minutes,
// preventing replay attacks with old intercepted state values.
fn generate_state(jwt_secret: &str, linking_user_id: Option<Uuid>) -> String {
    let timestamp = chrono::Utc::now().timestamp();
    let user_part = linking_user_id.map(|id| id.to_string()).unwrap_or_default();
    let data = format!("{user_part}|{timestamp}");
    let data_b64 = URL_SAFE_NO_PAD.encode(data.as_bytes());

    let sig = hmac_sign(jwt_secret.as_bytes(), data_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

    format!("{data_b64}.{sig_b64}")
}

// Verifies the state token and returns the embedded linking_user_id (if any).
fn verify_state(jwt_secret: &str, state: &str) -> Result<Option<Uuid>, AppError> {
    let parts: Vec<&str> = state.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest("invalid OAuth state".into()));
    }

    // Constant-time signature verification — same reasoning as in jwt.rs.
    let expected = hmac_sign(jwt_secret.as_bytes(), parts[0].as_bytes());
    let provided = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::BadRequest("invalid state signature encoding".into()))?;

    if !expected.ct_eq(&provided).into() {
        return Err(AppError::BadRequest("state signature mismatch".into()));
    }

    let data_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| AppError::BadRequest("invalid state data encoding".into()))?;
    let data = std::str::from_utf8(&data_bytes)
        .map_err(|_| AppError::BadRequest("invalid state UTF-8".into()))?;

    let mut iter = data.splitn(2, '|');
    let user_part = iter.next().unwrap_or("");
    let ts_str = iter.next()
        .ok_or_else(|| AppError::BadRequest("malformed state data".into()))?;

    // Reject state tokens older than 10 minutes.
    let timestamp: i64 = ts_str.parse()
        .map_err(|_| AppError::BadRequest("invalid state timestamp".into()))?;
    if chrono::Utc::now().timestamp() - timestamp > 600 {
        return Err(AppError::BadRequest("OAuth state expired, please try again".into()));
    }

    let linking_user_id = if user_part.is_empty() {
        None
    } else {
        Some(Uuid::parse_str(user_part)
            .map_err(|_| AppError::BadRequest("invalid user id in state".into()))?)
    };

    Ok(linking_user_id)
}

fn hmac_sign(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC accepts any non-empty key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}
