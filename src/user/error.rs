//! Error types and handling for the application
//!
//! This module provides a centralized error handling system with
//! conversions from common library errors to our application errors.
//! It also implements the necessary traits to convert errors to HTTP responses.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use thiserror::Error;

/// Standard error response format for API errors
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// User-related errors
#[derive(Debug, Error)]
pub enum UserError {
    #[error("User already exists: {0}")]
    UserAlreadyExists(String),

    #[error("Database error: {0}")]
    SqlxError(sqlx::Error),

    #[error("User not found")]
    UserNotFound,

    #[error("Username already taken")]
    UsernameTaken,

    #[error("Email already in use")]
    EmailTaken,

    #[error("Invalid role")]
    InvalidRole,

    #[error("Unexpected error: {0}")]
    Other(String),
}

impl UserError {
    /// Create a user already exists error with a specific message
    pub fn user_already_exists(message: impl ToString) -> Self {
        UserError::UserAlreadyExists(message.to_string())
    }

    /// Database error wrapper
    pub fn sqlx_error(err: sqlx::Error) -> Self {
        UserError::SqlxError(err)
    }

    /// Create a user not found error
    pub fn user_not_found() -> Self {
        UserError::UserNotFound
    }

    /// Create a username already taken error
    pub fn username_taken() -> Self {
        UserError::UsernameTaken
    }

    /// Create an email already in use error
    pub fn email_taken() -> Self {
        UserError::EmailTaken
    }

    /// Create an invalid role error
    pub fn invalid_role() -> Self {
        UserError::InvalidRole
    }

    /// Create a generic user-related error with a message
    pub fn other(message: impl ToString) -> Self {
        UserError::Other(message.to_string())
    }
}

impl From<sqlx::Error> for UserError {
    fn from(err: sqlx::Error) -> Self {
        UserError::SqlxError(err)
    }
}

/// Application-wide error types
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication error: {0}")]
    Authentication(String),

    #[error("Authorization error: {0}")]
    Authorization(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Validation error")]
    Validation {
        message: String,
        errors: serde_json::Value,
    },

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("External service error: {0}")]
    ExternalService(String),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl AppError {
    /// Create an authentication error
    pub fn authentication(message: impl ToString) -> Self {
        AppError::Authentication(message.to_string())
    }

    /// Create an authorization error
    pub fn authorization(message: impl ToString) -> Self {
        AppError::Authorization(message.to_string())
    }

    /// Create a not found error
    pub fn not_found(message: impl ToString) -> Self {
        AppError::NotFound(message.to_string())
    }

    /// Create an invalid request error
    pub fn invalid_request(message: impl ToString) -> Self {
        AppError::InvalidRequest(message.to_string())
    }

    /// Create a validation error with field-specific details
    pub fn validation(message: impl ToString, errors: serde_json::Value) -> Self {
        AppError::Validation {
            message: message.to_string(),
            errors,
        }
    }

    /// Create a conflict error (e.g., duplicate resource)
    pub fn conflict(message: impl ToString) -> Self {
        AppError::Conflict(message.to_string())
    }

    /// Create a rate limit error
    pub fn rate_limit(message: impl ToString) -> Self {
        AppError::RateLimit(message.to_string())
    }

    /// Create a database error
    pub fn database(message: impl ToString) -> Self {
        AppError::Database(message.to_string())
    }

    /// Create an external service error
    pub fn external_service(message: impl ToString) -> Self {
        AppError::ExternalService(message.to_string())
    }

    /// Create an internal server error
    pub fn internal(message: impl ToString) -> Self {
        AppError::Internal(message.to_string())
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            AppError::Authentication(_) => StatusCode::UNAUTHORIZED,
            AppError::Authorization(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Validation {
                ..
            } => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            AppError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AppError::ExternalService(_) => StatusCode::BAD_GATEWAY,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get the error code for this error (used for client-side error handling)
    pub fn error_code(&self) -> Option<String> {
        match self {
            AppError::Authentication(_) => Some("AUTHENTICATION_ERROR".to_string()),
            AppError::Authorization(_) => Some("AUTHORIZATION_ERROR".to_string()),
            AppError::NotFound(_) => Some("RESOURCE_NOT_FOUND".to_string()),
            AppError::InvalidRequest(_) => Some("INVALID_REQUEST".to_string()),
            AppError::Validation {
                ..
            } => Some("VALIDATION_ERROR".to_string()),
            AppError::Conflict(_) => Some("CONFLICT".to_string()),
            AppError::RateLimit(_) => Some("RATE_LIMIT_EXCEEDED".to_string()),
            AppError::Database(_) => Some("DATABASE_ERROR".to_string()),
            AppError::ExternalService(_) => Some("EXTERNAL_SERVICE_ERROR".to_string()),
            AppError::Internal(_) => Some("INTERNAL_SERVER_ERROR".to_string()),
        }
    }

    /// Convert the error to a standard error response
    pub fn to_response(&self) -> ErrorResponse {
        let status = self.status_code();
        let message = self.to_string();
        let code = self.error_code();
        let details = match self {
            AppError::Validation {
                errors,
                ..
            } => Some(errors.clone()),
            _ => None,
        };

        ErrorResponse {
            status: status.as_u16(),
            message,
            code,
            details,
        }
    }
}

/// Implement ResponseError for AppError to convert it to an HTTP response
impl ResponseError for AppError {
    fn status_code(&self) -> StatusCode {
        self.status_code()
    }
    fn error_response(&self) -> HttpResponse {
        let error_response = self.to_response();
        HttpResponse::build(self.status_code()).json(error_response)
    }
}

#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => AppError::not_found("Resource not found"),
            _ => AppError::database(error.to_string()),
        }
    }
}

#[cfg(feature = "argon2")]
impl From<argon2::Error> for AppError {
    fn from(error: argon2::Error) -> Self {
        AppError::internal(format!("Password hashing error: {}", error))
    }
}

#[cfg(feature = "jwt")]
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        match error.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                AppError::authentication("Token expired")
            },
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                AppError::authentication("Invalid token")
            },
            _ => AppError::authentication(format!("JWT error: {}", error)),
        }
    }
}

#[cfg(feature = "validator")]
impl From<validator::ValidationErrors> for AppError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let errors_map = errors
            .field_errors()
            .into_iter()
            .map(|(field, errors)| {
                let errors = errors
                    .iter()
                    .map(|error| {
                        let message = error
                            .message
                            .as_ref()
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| format!("{} is invalid", field));
                        serde_json::json!({ "code": error.code, "message": message })
                    })
                    .collect::<Vec<_>>();
                (field.to_string(), serde_json::json!(errors))
            })
            .collect::<serde_json::Map<_, _>>();

        AppError::validation("Validation failed", serde_json::Value::Object(errors_map))
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        AppError::internal(format!("IO error: {}", error))
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        AppError::invalid_request(format!("JSON error: {}", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[test]
    fn test_error_status_codes() {
        let auth_err = AppError::authentication("Unauthorized");
        assert_eq!(auth_err.status_code(), StatusCode::UNAUTHORIZED);

        let not_found_err = AppError::not_found("User not found");
        assert_eq!(not_found_err.status_code(), StatusCode::NOT_FOUND);

        let validation_err = AppError::validation(
            "Invalid input",
            serde_json::json!({ "field": "This field is required" }),
        );
        assert_eq!(validation_err.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn test_validation_error_details() {
        let errors = serde_json::json!({
            "email": [{"code": "email", "message": "Invalid email format"}],
            "password": [{"code": "length", "message": "Password too short"}]
        });

        let validation_err = AppError::validation("Validation failed", errors.clone());
        let response = validation_err.to_response();

        assert_eq!(response.status, 422);
        assert_eq!(response.message, "Validation failed");
        assert_eq!(response.code, Some("VALIDATION_ERROR".to_string()));
        assert_eq!(response.details, Some(errors));
    }
}
