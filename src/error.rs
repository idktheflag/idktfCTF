use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("not found")]
    NotFound,
    // 401 Unauthorized: no valid credentials were provided,
    #[error("unauthorized")]
    Unauthorized,
    // 403 forbidden credentials valid but no perms
    #[error("forbidden")]
    Forbidden,
    // 409 conflict violate uniqueness
    #[error("conflict: {0}")]
    Conflict(String),
    // 400 bad boy
    #[error("bad boy! {0}")]
    BadRequest(String),
    #[error("db error")]
    Database(#[from] sqlx::Error),
    #[error("internal sorvir error")]
    Internal(#[from] anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m.clone()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            // Don't leak internal DB details to the client:
            AppError::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database error".into()),
            AppError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal error".into()),
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}
