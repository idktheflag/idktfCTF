use std::{future::Future, pin::Pin, sync::Arc};

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

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthUser {
    pub user_id: Uuid,
    pub username: String,
    pub is_admin: bool,
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AdminUser(pub AuthUser);

impl FromRequestParts<Arc<AppState>> for AuthUser {
    type Rejection = AppError;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        state: &'life1 Arc<AppState>,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let auth_header = parts
                .headers
                .get(HeaderName::from_static("authorization"))
                .and_then(|v| v.to_str().ok())
                .ok_or(AppError::Unauthorized)?;
            let token = auth_header
                .strip_prefix("Bearer ")
                .ok_or(AppError::Unauthorized)?;
            let claims = jwt::verify_token(&state.jwt_secret, token)?;
            let user_id = Uuid::parse_str(&claims.sub)
                .map_err(|_| AppError::Unauthorized)?;
            Ok(AuthUser {
                user_id,
                username: claims.username,
                is_admin: claims.is_admin,
            })
        })
    }
}

impl FromRequestParts<Arc<AppState>> for AdminUser {
    type Rejection = AppError;

    fn from_request_parts<'life0, 'life1, 'async_trait>(
        parts: &'life0 mut Parts,
        state: &'life1 Arc<AppState>,
    ) -> Pin<Box<dyn Future<Output = Result<Self, Self::Rejection>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let auth_user = AuthUser::from_request_parts(parts, state).await?;
            if !auth_user.is_admin {
                return Err(AppError::Forbidden);
            }
            Ok(AdminUser(auth_user))
        })
    }
}
