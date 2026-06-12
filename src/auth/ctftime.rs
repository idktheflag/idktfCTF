use std::sync::Arc;

use axum::{
    extract::{Query, State},
    response::Redirect,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::{
    auth::{crypto::jwt, middleware::AuthUser},
    error::AppError,
    state::AppState,
};

type HmacSha256 = Hmac<Sha256>;
#[derive(Deserialize)]
struct CtftimeProfile {
    id: i32,
    name: String,
    team: Option<CtftimeTeamInfo>,
}

#[derive(Deserialize)]
struct CtftimeTeamInfo {
    id: i32,
    name: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

// get /auth/ctftime
// builds the ctftime authorization url
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
// Note: returns Redirect, not JSON — the browser follows this redirect to the
// frontend's /auth/callback?token=... page, which stores the JWT and continues.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(params): Query<CallbackQuery>,
) -> Result<Redirect, AppError> {
    let config = state.ctftime.as_ref()
        .ok_or_else(|| AppError::BadRequest("CTFtime OAuth is not configured".into()))?;
    let linking_user_id = verify_state(&state.jwt_secret, &params.state)?;
    let token_res = state.http
        .post("https://oauth.ctftime.org/token")
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
    let profile = state.http
        .get("https://oauth.ctftime.org/user")
        .bearer_auth(&token_res.access_token)
        .send()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("CTFtime user request failed: {e}")))?
        .json::<CtftimeProfile>()
        .await
        .map_err(|e| AppError::Internal(anyhow::anyhow!("CTFtime user parse failed: {e}")))?;

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

    let (user_id, is_admin) = if let Some(existing_id) = linking_user_id {
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

    // ── Step 6: issue our JWT and redirect to the frontend ───────────────────
    let final_username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_one(&state.pool)
        .await?;

    let token = jwt::create_token(&state.jwt_secret, user_id, &final_username, is_admin)?;
    let redirect_url = format!("{}/auth/callback?token={}", state.frontend_url, token);
    Ok(Redirect::to(&redirect_url))
}

fn generate_state(jwt_secret: &str, linking_user_id: Option<Uuid>) -> String {
    let timestamp = chrono::Utc::now().timestamp();
    let user_part = linking_user_id.map(|id| id.to_string()).unwrap_or_default();
    let data = format!("{user_part}|{timestamp}");
    let data_b64 = URL_SAFE_NO_PAD.encode(data.as_bytes());

    let sig = hmac_sign(jwt_secret.as_bytes(), data_b64.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&sig);

    format!("{data_b64}.{sig_b64}")
}

fn verify_state(jwt_secret: &str, state: &str) -> Result<Option<Uuid>, AppError> {
    let parts: Vec<&str> = state.splitn(2, '.').collect();
    if parts.len() != 2 {
        return Err(AppError::BadRequest("invalid OAuth state".into()));
    }
    let expected = hmac_sign(jwt_secret.as_bytes(), parts[0].as_bytes());
    let provided = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| AppError::BadRequest("invalid state signature encoding".into()))?;

    if !bool::from(expected.ct_eq(&provided)) {
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
