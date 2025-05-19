//! Application error handling
//!
//! This module defines the application's error types and provides
//! conversions to HTTP responses with appropriate status codes.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};
use thiserror::Error;

/// Standard error response format returned to clients
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// HTTP status code
    pub status: u16,
    /// Error message
    pub message: String,
    /// Error code for client-side error handling
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Additional details, if any
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

/// Main application error type
#[derive(Debug, Error)]
pub enum AppError {
    /// Authentication errors
    #[error("Authentication error: {0}")]
    Authentication(String),

    /// Authorization/permission errors
    #[error("Authorization error: {0}")]
    Authorization(String),

    /// Resource not found errors
    #[error("Resource not found: {0}")]
    NotFound(String),

    /// Invalid input/request errors
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Validation errors for form inputs
    #[error("Validation error")]
    Validation {
        message: String,
        errors: serde_json::Value,
    },

    /// Conflict errors (e.g. duplicate resources)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// Rate limiting errors
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),

    /// Database errors
    #[error("Database error: {0}")]
    Database(String),

    /// External service errors
    #[error("External service error: {0}")]
    ExternalService(String),

    /// Internal server errors
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl AppError {
    /// Creates an authentication error
    pub fn authentication(message: impl ToString) -> Self {
        Self::Authentication(message.to_string())
    }

    /// Creates an authorization error
    pub fn authorization(message: impl ToString) -> Self {
        Self::Authorization(message.to_string())
    }

    /// Creates a not found error
    pub fn not_found(message: impl ToString) -> Self {
        Self::NotFound(message.to_string())
    }

    /// Creates an invalid request error
    pub fn invalid_request(message: impl ToString) -> Self {
        Self::InvalidRequest(message.to_string())
    }

    /// Creates a validation error with field-specific details
    pub fn validation(message: impl ToString, errors: serde_json::Value) -> Self {
        Self::Validation {
            message: message.to_string(),
            errors,
        }
    }

    /// Creates a conflict error
    pub fn conflict(message: impl ToString) -> Self {
        Self::Conflict(message.to_string())
    }

    /// Creates a rate limit error
    pub fn rate_limit(message: impl ToString) -> Self {
        Self::RateLimit(message.to_string())
    }

    /// Creates a database error
    pub fn database(message: impl ToString) -> Self {
        Self::Database(message.to_string())
    }

    /// Creates an external service error
    pub fn external_service(message: impl ToString) -> Self {
        Self::ExternalService(message.to_string())
    }

    /// Creates an internal server error
    pub fn internal(message: impl ToString) -> Self {
        Self::Internal(message.to_string())
    }

    /// Get the HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Authentication(_) => StatusCode::UNAUTHORIZED,
            Self::Authorization(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Validation { .. } => StatusCode::UNPROCESSABLE_ENTITY,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::RateLimit(_) => StatusCode::TOO_MANY_REQUESTS,
            Self::Database(_) | Self::ExternalService(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Get error code for client-side error handling
    pub fn error_code(&self) -> Option<String> {
        let code = match self {
            Self::Authentication(_) => "AUTH_ERROR",
            Self::Authorization(_) => "FORBIDDEN",
            Self::NotFound(_) => "NOT_FOUND",
            Self::InvalidRequest(_) => "BAD_REQUEST",
            Self::Validation { .. } => "VALIDATION_ERROR",
            Self::Conflict(_) => "CONFLICT",
            Self::RateLimit(_) => "RATE_LIMIT",
            Self::Database(_) => "DATABASE_ERROR",
            Self::ExternalService(_) => "EXTERNAL_SERVICE_ERROR",
            Self::Internal(_) => "INTERNAL_ERROR",
        };

        Some(code.to_string())
    }

    /// Convert to an error response object
    pub fn to_response(&self) -> ErrorResponse {
        let message = self.to_string();

        let details = match self {
            Self::Validation { errors, .. } => Some(errors.clone()),
            _ => None,
        };

        ErrorResponse {
            status: self.status_code().as_u16(),
            message,
            code: self.error_code(),
            details,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let error_response = self.to_response();

        // Log server errors
        if status.is_server_error() {
            // In a real app, you might want to use a proper logger here
            eprintln!("Server error: {:?}", self);
        }

        // Convert the error into a JSON response with the appropriate status code
        (status, Json(error_response)).into_response()
    }
}

/// Implement From<sqlx::Error> for AppError
#[cfg(feature = "sqlx")]
impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        match error {
            sqlx::Error::RowNotFound => Self::not_found("Resource not found in database"),
            sqlx::Error::Database(db_err) => {
                // Check for unique constraint violation (PostgreSQL)
                if let Some(code) = db_err.code() {
                    if code == "23505" {
                        return Self::conflict("A resource with these details already exists");
                    }
                }

                Self::database(format!("Database error: {}", db_err))
            }
            _ => Self::database(format!("Database error: {}", error)),
        }
    }
}

/// Implement From<argon2::Error> for AppError
#[cfg(feature = "argon2")]
impl From<argon2::Error> for AppError {
    fn from(error: argon2::Error) -> Self {
        Self::internal(format!("Password hashing error: {}", error))
    }
}

/// Implement From<jsonwebtoken::errors::Error> for AppError
#[cfg(feature = "jwt")]
impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        match error.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                Self::authentication("Token has expired")
            }
            jsonwebtoken::errors::ErrorKind::InvalidToken => {
                Self::authentication("Invalid token")
            }
            _ => Self::authentication(format!("JWT error: {}", error)),
        }
    }
}

/// Implement From<validator::ValidationErrors> for AppError
#[cfg(feature = "validator")]
impl From<validator::ValidationErrors> for AppError {
    fn from(errors: validator::ValidationErrors) -> Self {
        let validation_errors = errors
            .field_errors()
            .into_iter()
            .map(|(field, errors)| {
                let messages: Vec<String> = errors
                    .iter()
                    .map(|error| {
                        if let Some(message) = &error.message {
                            message.to_string()
                        } else {
                            format!("{} is invalid", field)
                        }
                    })
                    .collect();

                (field.to_string(), serde_json::json!(messages))
            })
            .collect::<serde_json::Map<String, serde_json::Value>>();

        Self::validation(
            "Validation failed",
            serde_json::Value::Object(validation_errors),
        )
    }
}

/// Convert std::io::Error to AppError
impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(format!("I/O error: {}", error))
    }
}

/// Convert serde_json::Error to AppError
impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::invalid_request(format!("JSON error: {}", error))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn test_error_status_codes() {
        let errors = [
            (AppError::authentication("test"), StatusCode::UNAUTHORIZED),
            (AppError::authorization("test"), StatusCode::FORBIDDEN),
            (AppError::not_found("test"), StatusCode::NOT_FOUND),
            (AppError::invalid_request("test"), StatusCode::BAD_REQUEST),
            (
                AppError::validation("test", serde_json::json!({})),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (AppError::conflict("test"), StatusCode::CONFLICT),
            (AppError::rate_limit("test"), StatusCode::TOO_MANY_REQUESTS),
            (AppError::database("test"), StatusCode::INTERNAL_SERVER_ERROR),
            (
                AppError::external_service("test"),
                StatusCode::INTERNAL_SERVER_ERROR,
            ),
            (AppError::internal("test"), StatusCode::INTERNAL_SERVER_ERROR),
        ];

        for (error, expected_status) in errors {
            assert_eq!(error.status_code(), expected_status);
        }
    }

    #[test]
    fn test_validation_error_details() {
        let validation_error = AppError::validation(
            "Validation failed",
            serde_json::json!({
                "username": ["Username is required"],
                "email": ["Invalid email format"],
            }),
        );

        let response = validation_error.to_response();

        assert_eq!(response.status, 422);
        assert_eq!(response.message, "Validation error: Validation failed");
        assert_eq!(response.code, Some("VALIDATION_ERROR".to_string()));

        if let Some(details) = response.details {
            assert!(details.is_object());
            let details_obj = details.as_object().unwrap();
            assert!(details_obj.contains_key("username"));
            assert!(details_obj.contains_key("email"));
        } else {
            panic!("Expected validation details");
        }
    }
}