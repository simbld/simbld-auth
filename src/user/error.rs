//! User-related error types

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Standard error response format
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// User-specific errors
#[derive(Debug, Error)]
pub enum UserError {
    #[error("User not found")]
    UserNotFound,

    #[error("Username already took")]
    UsernameTaken,

    #[error("Email already in use")]
    EmailTaken,

    #[error("Invalid role: {0}")]
    InvalidRole(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("The current password is incorrect")]
    CurrentPasswordIncorrect,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Internal error: {0}")]
    InternalError(String),
}

impl UserError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            UserError::UserNotFound => StatusCode::NOT_FOUND,
            UserError::UsernameTaken => StatusCode::CONFLICT,
            UserError::EmailTaken => StatusCode::CONFLICT,
            UserError::InvalidRole(_) => StatusCode::BAD_REQUEST,
            UserError::Forbidden(_) => StatusCode::FORBIDDEN,
            UserError::ValidationError(_) => StatusCode::UNPROCESSABLE_ENTITY,
            UserError::CurrentPasswordIncorrect => StatusCode::BAD_REQUEST,
            UserError::DatabaseError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            UserError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn error_code(&self) -> Option<String> {
        match self {
            UserError::UserNotFound => Some("USER_NOT_FOUND".to_string()),
            UserError::UsernameTaken => Some("USERNAME_TAKEN".to_string()),
            UserError::EmailTaken => Some("EMAIL_TAKEN".to_string()),
            UserError::InvalidRole(_) => Some("INVALID_ROLE".to_string()),
            UserError::Forbidden(_) => Some("FORBIDDEN".to_string()),
            UserError::ValidationError(_) => Some("VALIDATION_ERROR".to_string()),
            UserError::CurrentPasswordIncorrect => Some("CURRENT_PASSWORD_INCORRECT".to_string()),
            UserError::DatabaseError(_) => Some("DATABASE_ERROR".to_string()),
            UserError::InternalError(_) => Some("INTERNAL_ERROR".to_string()),
        }
    }

    pub fn to_response(&self) -> ErrorResponse {
        ErrorResponse {
            status: self.status_code().as_u16(),
            message: self.to_string(),
            code: self.error_code(),
        }
    }
}

impl ResponseError for UserError {
    fn status_code(&self) -> StatusCode {
        self.status_code()
    }

    fn error_response(&self) -> HttpResponse {
        let error_response = self.to_response();
        HttpResponse::build(self.status_code()).json(error_response)
    }
}

impl From<sqlx::Error> for UserError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => UserError::UserNotFound,
            _ => UserError::DatabaseError(error.to_string()),
        }
    }
}

impl From<validator::ValidationErrors> for UserError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let error_messages: Vec<String> = errors
            .field_errors()
            .into_iter()
            .flat_map(|(field, errors)| {
                errors.iter().map(move |error| {
                    format!("{}: {}", field, error.message.as_ref().unwrap_or(&"Invalid".into()))
                })
            })
            .collect();

        UserError::ValidationError(error_messages.join(", "))
    }
}
