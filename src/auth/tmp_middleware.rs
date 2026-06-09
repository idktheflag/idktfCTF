// auth/middleware.rs — Axum extractors that enforce authentication.
//
// Axum's extractor pattern: if a handler declares a parameter of type T,
// Axum calls T::from_request_parts() before the handler runs. If the
// extractor returns Err, Axum short-circuits and returns that error response
// without ever calling the handler.
//
// This means authentication is enforced at the type level:
//   async fn protected(auth: AuthUser, ...) — always authenticated
//   async fn public(...)                    — no auth check at all
//
// No middleware stack to configure, no forget-to-add-a-guard bugs.

use std::sync::Arc;

use axum::{
    extract::FromRequestParts,
    http::{request::Parts, HeaderName},
};
use uuid::Uuid;

use crate::{
    auth::crypto::jwt,
    error::AppError,
    state::AppState,
};

// AuthUser is injected into any handler that needs to know who is calling.
// It holds the data we put in the JWT claims, already verified and decoded.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id:  Uuid,
    pub username: String,
    pub is_admin: bool,
}

// AdminUser wraps AuthUser and additionally enforces is_admin == true.
// Using a distinct type means "admin-only" is checked at compile time
// (the handler signature declares exactly which kind of auth it needs).
#[derive(Debug, Clone)]
pub struct AdminUser(pub AuthUser);

// ── AuthUser extractor ───────────────────────────────────────────────────────

// We implement FromRequestParts<Arc<AppState>> so the extractor can read
// jwt_secret from the shared application state.
//
// The trait signature:
//   async fn from_request_parts(parts, state) -> Result<Self, Self::Rejection>
// `parts` contains headers, URI, method — everything except the body.
// `state` is our Arc<AppState>.
impl FromRequestParts<Arc<AppState>> for AuthUser {
    // The rejection type must implement IntoResponse.
    // Our AppError does, so we use it directly.
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Extract the Authorization header value as a string.
        // and_then chains Option operations; if any step returns None we get None.
        let auth_header = parts
            .headers
            .get(HeaderName::from_static("authorization"))
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        // JWTs are sent as "Bearer <token>".
        // strip_prefix returns Some(&str) if the prefix matches, else None.
        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        // Verify the JWT signature and decode the claims.
        // If the token is expired, tampered with, or malformed, this returns
        // AppError::Unauthorized and the handler never runs.
        let claims = jwt::verify_token(&state.jwt_secret, token)?;

        let user_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::Unauthorized)?;

        Ok(AuthUser {
            user_id,
            username: claims.username,
            is_admin: claims.is_admin,
        })
    }
}

// ── AdminUser extractor ──────────────────────────────────────────────────────

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        // Re-use the AuthUser extractor — no point duplicating the JWT logic.
        let auth = AuthUser::from_request_parts(parts, state).await?;

        // A valid token for a non-admin user gets a 403, not 401.
        // 401 = "who are you?", 403 = "I know who you are, you just can't do this".
        if !auth.is_admin {
            return Err(AppError::Forbidden);
        }

        Ok(AdminUser(auth))
    }
}
