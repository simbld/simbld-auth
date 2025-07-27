//! Trait extension for ApiError to add response methods
//!
//! This trait adds convenient methods to ApiError for creating HTTP responses
//! without having to use the ApiErrorHandler directly.

use crate::types::ApiError;
use crate::utils::error_handler::ApiErrorHandler;
use actix_web::{HttpRequest, HttpResponse};
use simbld_http::responses::{CustomResponse, ResponsesTypes};
use std::time::Duration;

/// Extension trait for ApiError to add response methods
pub trait ApiErrorResponseExt {
    /// Convert ApiError to hybrid HTTP response (JSON for API, HTML for browser)
    fn to_response(&self, req: &HttpRequest, duration: Duration) -> HttpResponse;

    /// Get user-friendly error title
    fn get_title(&self) -> String;

    /// Get ResponsesTypes for this error
    fn get_response_type(&self) -> ResponsesTypes;

    /// Get legacy CustomResponse (for backward compatibility)
    fn to_custom_response(&self) -> CustomResponse;
}

impl ApiErrorResponseExt for ApiError {
    /// Convert ApiError to hybrid HTTP response
    ///
    /// # Arguments
    /// * `req`–- The HTTP request for context detection
    /// * `duration`–- Request processing duration for metrics
    ///
    /// # Returns
    /// * JSON response for API clients
    /// * HTML response for browser clients
    fn to_response(&self, req: &HttpRequest, duration: Duration) -> HttpResponse {
        ApiErrorHandler::create_hybrid_response(self, req, duration)
    }

    /// Get user-friendly error title
    fn get_title(&self) -> String {
        ApiErrorHandler::get_error_title(self)
    }

    /// Get ResponsesTypes for this error
    fn get_response_type(&self) -> ResponsesTypes {
        ApiErrorHandler::convert_to_response_type(self)
    }

    /// Get legacy CustomResponse (for backward compatibility)
    fn to_custom_response(&self) -> CustomResponse {
        match self {
            // Server errors
            ApiError::Internal {
                ..
            }
            | ApiError::Database(_)
            | ApiError::Config {
                ..
            } => {
                use simbld_http::responses::server::ResponsesServerCodes;
                ResponsesServerCodes::InternalServerError.into_response()
            },

            // Client errors
            ApiError::Auth(_) | ApiError::InvalidCredentials | ApiError::SessionExpired => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::Unauthorized.into_response()
            },

            ApiError::PermissionDenied => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::Forbidden.into_response()
            },

            ApiError::Validation(_) | ApiError::Password(_) => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::BadRequest.into_response()
            },

            ApiError::UserNotFound => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::NotFound.into_response()
            },

            ApiError::EmailAlreadyExists => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::Conflict.into_response()
            },

            ApiError::Mfa(_) => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::BadRequest.into_response()
            },

            ApiError::Jwt(_) => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::Unauthorized.into_response()
            },

            ApiError::RateLimit => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::TooManyRequests.into_response()
            },

            ApiError::AccountLocked => {
                use simbld_http::responses::client::ResponsesClientCodes;
                ResponsesClientCodes::Locked.into_response()
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;

    #[test]
    async fn test_error_titles() {
        let error = ApiError::UserNotFound;
        assert_eq!(error.get_title(), "User Not Found");

        let error = ApiError::Database("Connection failed".to_string());
        assert_eq!(error.get_title(), "Database Error");

        let error = ApiError::Internal {
            message: "Something went wrong".to_string(),
        };
        assert_eq!(error.get_title(), "Internal Server Error");
    }

    #[test]
    async fn test_response_types() {
        let error = ApiError::UserNotFound;
        let response_type = error.get_response_type();
        assert_eq!(response_type.get_code(), 404);

        let error = ApiError::InvalidCredentials;
        let response_type = error.get_response_type();
        assert_eq!(response_type.get_code(), 401);

        let error = ApiError::Database("Failed".to_string());
        let response_type = error.get_response_type();
        assert_eq!(response_type.get_code(), 500);
    }
}
