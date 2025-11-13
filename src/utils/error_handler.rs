//! API Error Handler
//!
//! This module provides centralized error handling for the app.
//! It converts `ApiError` instances into appropriate HTTP responses with
//! proper status codes, user-friendly messages, and response formats.
//!
//! # Features
//! - Converts errors to appropriate HTTP status codes
//! - Provides user-friendly error titles
//! - Creates hybrid responses (JSON for API, HTML for browsers)
//! - Integrates with the ResponseHandler for consistent formatting

use crate::types::ApiError;
use crate::utils::response_handler::ResponseHandler;
use actix_web::{HttpRequest, HttpResponse};
use simbld_http::responses::{ResponsesClientCodes, ResponsesServerCodes, ResponsesTypes};
use std::time::Duration;

/// Error handler for API responses
pub struct ApiErrorHandler;

impl ApiErrorHandler {
    /// Convert ApiError to ResponsesTypes
    pub fn convert_to_response_type(error: &ApiError) -> ResponsesTypes {
        match error {
            // Server errors (5xx)
            ApiError::Internal {
                ..
            }
            | ApiError::Database(_)
            | ApiError::Config {
                ..
            }
            | ApiError::InternalServerError(_) => {
                ResponsesTypes::ServerError(ResponsesServerCodes::InternalServerError)
            },

            // Client errors (4xx)
            ApiError::Auth(_) | ApiError::InvalidCredentials | ApiError::SessionExpired => {
                ResponsesTypes::ClientError(ResponsesClientCodes::Unauthorized)
            },

            ApiError::PermissionDenied => {
                ResponsesTypes::ClientError(ResponsesClientCodes::Forbidden)
            },

            ApiError::UserNotFound => ResponsesTypes::ClientError(ResponsesClientCodes::NotFound),

            ApiError::EmailAlreadyExists => {
                ResponsesTypes::ClientError(ResponsesClientCodes::Conflict)
            },

            ApiError::Validation(_)
            | ApiError::Password(_)
            | ApiError::Mfa(_)
            | ApiError::Jwt(_)
            | ApiError::BadRequest(_) => {
                ResponsesTypes::ClientError(ResponsesClientCodes::BadRequest)
            },

            ApiError::RateLimit => {
                ResponsesTypes::ClientError(ResponsesClientCodes::TooManyRequests)
            },

            ApiError::AccountLocked => ResponsesTypes::ClientError(ResponsesClientCodes::Locked),
        }
    }

    /// Get user-friendly error title
    pub fn get_error_title(error: &ApiError) -> String {
        match error {
            ApiError::Internal {
                ..
            } => "Internal Server Error".to_string(),
            ApiError::InternalServerError(_) => "Internal Server Error".to_string(),
            ApiError::Database(_) => "Database Error".to_string(),
            ApiError::Auth(_) => "Authentication Error".to_string(),
            ApiError::Config {
                ..
            } => "Configuration Error".to_string(),
            ApiError::Validation(_) => "Validation Error".to_string(),
            ApiError::Password(_) => "Password Error".to_string(),
            ApiError::UserNotFound => "User Not Found".to_string(),
            ApiError::EmailAlreadyExists => "Email Already Exists".to_string(),
            ApiError::InvalidCredentials => "Invalid Credentials".to_string(),
            ApiError::Mfa(_) => "MFA Error".to_string(),
            ApiError::Jwt(_) => "JWT Error".to_string(),
            ApiError::RateLimit => "Rate Limit Exceeded".to_string(),
            ApiError::PermissionDenied => "Permission Denied".to_string(),
            ApiError::AccountLocked => "Account Locked".to_string(),
            ApiError::SessionExpired => "Session Expired".to_string(),
            ApiError::BadRequest(_) => "Bad Request".to_string(),
        }
    }

    /// Create a hybrid response from ApiError
    pub fn create_hybrid_response(
        error: &ApiError,
        req: &HttpRequest,
        duration: Duration,
    ) -> HttpResponse {
        let response_type = Self::convert_to_response_type(error);
        let title = Self::get_error_title(error);
        let description = error.to_string();

        ResponseHandler::create_hybrid_response(
            req,
            response_type,
            Some(&title),
            Some(&description),
            duration,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[test]
    async fn test_convert_to_response_type_server_errors() {
        let error = ApiError::Internal {
            message: "Test".to_string(),
        };
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 500);

        let error = ApiError::Database("Connection failed".to_string());
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 500);

        let error = ApiError::Config {
            message: "Invalid config".to_string(),
        };
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 500);
    }

    #[test]
    async fn test_convert_to_response_type_client_errors() {
        let error = ApiError::UserNotFound;
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 404);

        let error = ApiError::InvalidCredentials;
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 401);

        let error = ApiError::EmailAlreadyExists;
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 409);

        let error = ApiError::RateLimit;
        let response_type = ApiErrorHandler::convert_to_response_type(&error);
        assert_eq!(response_type.get_code(), 429);
    }

    #[test]
    async fn test_get_error_title() {
        let error = ApiError::UserNotFound;
        assert_eq!(ApiErrorHandler::get_error_title(&error), "User Not Found");

        let error = ApiError::Database("Connection failed".to_string());
        assert_eq!(ApiErrorHandler::get_error_title(&error), "Database Error");

        let error = ApiError::Internal {
            message: "Something went wrong".to_string(),
        };
        assert_eq!(ApiErrorHandler::get_error_title(&error), "Internal Server Error");

        let error = ApiError::Validation("Invalid input".to_string());
        assert_eq!(ApiErrorHandler::get_error_title(&error), "Validation Error");

        let error = ApiError::RateLimit;
        assert_eq!(ApiErrorHandler::get_error_title(&error), "Rate Limit Exceeded");
    }

    #[test]
    async fn test_error_categories() {
        // Test authentication errors
        let auth_errors = vec![
            ApiError::Auth("Failed".to_string()),
            ApiError::InvalidCredentials,
            ApiError::SessionExpired,
        ];

        for error in auth_errors {
            let response_type = ApiErrorHandler::convert_to_response_type(&error);
            assert_eq!(response_type.get_code(), 401);
        }

        // Test validation errors
        let validation_errors = vec![
            ApiError::Validation("Invalid".to_string()),
            ApiError::Password("Too weak".to_string()),
            ApiError::Mfa("Invalid code".to_string()),
            ApiError::Jwt("Invalid token".to_string()),
        ];

        for error in validation_errors {
            let response_type = ApiErrorHandler::convert_to_response_type(&error);
            assert_eq!(response_type.get_code(), 400);
        }
    }

    #[tokio::test]
    async fn test_create_hybrid_response() {
        let req = test::TestRequest::default()
            .insert_header(("Accept", "application/json"))
            .to_http_request();

        let error = ApiError::UserNotFound;
        let duration = Duration::from_millis(100);

        let response = ApiErrorHandler::create_hybrid_response(&error, &req, duration);
        assert_eq!(response.status(), 404);
    }
}
