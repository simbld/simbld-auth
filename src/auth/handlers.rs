//! Authentication HTTP handlers
//!
//! Contains all HTTP request handlers for authentication endpoints including
//! registration, login, MFA verification, token refresh, and password management.

use actix_web::{web, HttpResponse};
use serde_json::json;
use validator::Validate;

use crate::auth::dto::{
    LoginRequest, MfaVerifyRequest, PasswordResetConfirm, PasswordResetRequest,
    RefreshTokenRequest, RegisterRequest, SessionResponse,
};
use crate::auth::jwt::Claims;
use crate::auth::service::AuthService;
use crate::auth::AuthError;

/// Helper function to handle validation errors
fn handle_validation_error(validation_errors: validator::ValidationErrors) -> HttpResponse {
    HttpResponse::BadRequest().json(json!({
        "error": "Validation failed",
        "details": format!("{:?}", validation_errors)
    }))
}

/// User registration endpoint
pub async fn register(
    payload: web::Json<RegisterRequest>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    // Validate custom password requirements
    if let Err(validation_errors) = payload.validate_all() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Password validation failed",
            "details": format!("{:?}", validation_errors)
        })));
    }

    // Register user
    match auth_service
        .register_user(
            &payload.email,
            &payload.password,
            &payload.username,
            &payload.firstname,
            &payload.lastname,
        )
        .await
    {
        Ok(registration_result) => {
            if registration_result.success {
                Ok(HttpResponse::Created().json(json!({
                    "message": "User registered successfully",
                    "data": registration_result
                })))
            } else {
                Ok(HttpResponse::Conflict().json(json!({
                    "error": registration_result.message
                })))
            }
        },
        Err(e) => match e {
            AuthError::EmailAlreadyExists => Ok(HttpResponse::Conflict().json(json!({
                "error": "Email already exists"
            }))),
            AuthError::UsernameAlreadyExists => Ok(HttpResponse::Conflict().json(json!({
                "error": "Username already exists"
            }))),
            _ => Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Registration failed",
                "details": e.to_string()
            }))),
        },
    }
}

/// User login endpoint
pub async fn login(
    payload: web::Json<LoginRequest>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    // Get device information for session tracking
    let device_info = payload.device_info.clone();

    // Authenticate user
    match auth_service.authenticate_user(&payload.email, &payload.password, device_info).await {
        Ok(auth_result) => {
            if auth_result.requires_mfa {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "MFA verification required",
                    "data": auth_result
                })))
            } else {
                Ok(HttpResponse::Ok().json(json!({
                    "message": "Login successful",
                    "data": auth_result
                })))
            }
        },
        Err(e) => match e {
            AuthError::InvalidCredentials => Ok(HttpResponse::Unauthorized().json(json!({
                "error": "Invalid credentials"
            }))),
            AuthError::UserLocked => Ok(HttpResponse::Forbidden().json(json!({
                "error": "Account is locked"
            }))),
            AuthError::AccountNotVerified => Ok(HttpResponse::Forbidden().json(json!({
                "error": "Email verification required"
            }))),
            _ => Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Login failed",
                "details": e.to_string()
            }))),
        },
    }
}

/// MFA verification endpoint
pub async fn verify_mfa(
    payload: web::Json<MfaVerifyRequest>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    // Verify MFA code
    match auth_service.verify_mfa_code(payload.user_id, &payload.code, &payload.mfa_type).await {
        Ok(mfa_result) => {
            if mfa_result.success {
                if let Some(tokens) = mfa_result.tokens {
                    let response = SessionResponse {
                        token: tokens.access_token,
                        refresh_token: tokens.refresh_token,
                        expires_at: tokens.access_expires_at.timestamp(),
                    };

                    Ok(HttpResponse::Ok().json(json!({
                        "message": "MFA verification successful",
                        "data": response
                    })))
                } else {
                    Ok(HttpResponse::InternalServerError().json(json!({
                        "error": "Token generation failed"
                    })))
                }
            } else {
                Ok(HttpResponse::Unauthorized().json(json!({
                    "error": mfa_result.error.unwrap_or_else(|| "MFA verification failed".to_string())
                })))
            }
        },
        Err(e) => Ok(HttpResponse::InternalServerError().json(json!({
            "error": "MFA verification error",
            "details": e.to_string()
        }))),
    }
}

/// Token refresh endpoint
pub async fn refresh_token(
    payload: web::Json<RefreshTokenRequest>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    match auth_service.refresh_access_token(&payload.refresh_token).await {
        Ok(token_pair) => {
            let response = SessionResponse {
                token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                expires_at: token_pair.access_expires_at.timestamp(),
            };

            Ok(HttpResponse::Ok().json(json!({
                "message": "Token refreshed successfully",
                "data": response
            })))
        },
        Err(e) => match e {
            AuthError::InvalidToken | AuthError::TokenExpired => Ok(HttpResponse::Unauthorized()
                .json(json!({
                    "error": "Invalid or expired refresh token"
                }))),
            _ => Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Token refresh failed",
                "details": e.to_string()
            }))),
        },
    }
}

/// User logout endpoint
pub async fn logout(
    payload: web::Json<RefreshTokenRequest>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    match auth_service.logout(&payload.refresh_token).await {
        Ok(_) => Ok(HttpResponse::Ok().json(json!({
            "message": "Logged out successfully"
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(json!({
            "error": "Logout failed",
            "details": e.to_string()
        }))),
    }
}

/// Password reset request endpoint
pub async fn request_password_reset(
    payload: web::Json<PasswordResetRequest>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    match auth_service.request_password_reset(&payload.email).await {
        Ok(reset_result) => Ok(HttpResponse::Ok().json(json!({
            "message": "Password reset instructions sent",
            "data": reset_result
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(json!({
            "error": "Password reset request failed",
            "details": e.to_string()
        }))),
    }
}

/// Password reset confirmation endpoint
pub async fn confirm_password_reset(
    payload: web::Json<PasswordResetConfirm>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    // Validate request
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    // Validate custom password requirements
    if let Err(validation_errors) = payload.validate_all() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Password reset validation failed",
            "details": format!("{:?}", validation_errors)
        })));
    }

    match auth_service.confirm_password_reset(&payload.token, &payload.new_password).await {
        Ok(reset_result) => Ok(HttpResponse::Ok().json(json!({
            "message": "Password reset successfully",
            "data": reset_result
        }))),
        Err(e) => match e {
            AuthError::InvalidToken | AuthError::TokenExpired => Ok(HttpResponse::BadRequest()
                .json(json!({
                    "error": "Invalid or expired reset token"
                }))),
            _ => Ok(HttpResponse::InternalServerError().json(json!({
                "error": "Password reset failed",
                "details": e.to_string()
            }))),
        },
    }
}

/// Get current user profile endpoint
pub async fn get_me(
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
) -> Result<HttpResponse, actix_web::Error> {
    match auth_service.get_user_profile(claims.user_id).await {
        Ok(profile) => Ok(HttpResponse::Ok().json(json!({
            "message": "User profile retrieved",
            "data": profile
        }))),
        Err(e) => Ok(HttpResponse::InternalServerError().json(json!({
            "error": "Failed to retrieve a user profile",
            "details": e.to_string()
        }))),
    }
}

#[cfg(test)]
mod tests {
    #[actix_web::test]
    async fn test_register_validation() {
        // Test would verify validation logic
    }

    #[actix_web::test]
    async fn test_login_flow() {
        // Test would verify login flow
    }

    #[actix_web::test]
    async fn test_mfa_verification() {
        // Test would verify MFA flow
    }

    #[actix_web::test]
    async fn test_token_refresh() {
        // Test would verify token refresh
    }
}
