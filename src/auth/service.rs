//! Authentication service implementation
//!
//! Core business logic for user authentication, session management,
//! and security operations using simbld_http API responses.

use crate::auth::dto::RegisterRequest;
use crate::auth::password::security::{PasswordService, SecurePassword};
use crate::postgres::database::UserRecord;
use crate::postgres::Database;
use crate::types::{ApiError, LoginRequest};
use serde_json::json;
use simbld_http::responses::{CustomResponse, ResponsesClientCodes, ResponsesSuccessCodes};
use simbld_http::ResponsesServerCodes;
use std::sync::Arc;
use uuid::Uuid;

/// Authentication service for handling all auth operations
pub struct AuthService {
    database: Arc<Database>,
}

impl AuthService {
    /// Create new auth service with database connection
    pub fn new(database: Arc<Database>) -> Self {
        Self {
            database,
        }
    }

    /// Register a new user with secure password handling
    pub async fn register_user(&self, request: RegisterRequest) -> CustomResponse {
        // Check if a user already exists
        match self.database.user_exists(&request.email).await {
            Ok(true) => {
                return CustomResponse::new(
                    ResponsesClientCodes::Conflict.get_code(),
                    "Email already registered",
                    json!({
                        "error": "Email already registered",
                        "email": request.email
                    })
                    .to_string(),
                    "User with this email already exists",
                );
            },
            Ok(false) => {}, // Continue registration
            Err(e) => {
                return CustomResponse::new(
                    ResponsesServerCodes::InternalServerError.get_code(),
                    "Database error during registration",
                    json!({
                        "error": "Database error during registration",
                        "details": e.to_string()
                    })
                    .to_string(),
                    "Internal server error while processing registration",
                );
            },
        }

        // Validate password strength
        let secure_password = SecurePassword::new(request.password.clone());
        if let Err(e) = PasswordService::validate_password_strength(&request.password) {
            return CustomResponse::new(
                ResponsesClientCodes::BadRequest.get_code(),
                "Password validation failed",
                json!({
                    "error": "Password doesn't meet security requirements",
                    "details": e.to_string()
                })
                .to_string(),
                "Password doesn't meet minimum security requirements",
            );
        }

        // Create a user in a database
        match self
            .database
            .create_user(
                &request.email,
                &secure_password,
                &request.username,
                &request.firstname,
                &request.lastname,
            )
            .await
        {
            Ok(user_id) => CustomResponse::new(
                ResponsesSuccessCodes::Created.get_code(),
                "User registered successfully",
                json!({
                    "message": "User registered successfully",
                    "user_id": user_id,
                    "email": request.email,
                    "username": request.username
                })
                .to_string(),
                "New user account created successfully",
            ),
            Err(e) => CustomResponse::new(
                ResponsesServerCodes::InternalServerError.get_code(),
                "Failed to create a user",
                json!({
                    "error": "Failed to create a user",
                    "details": e.to_string()
                })
                .to_string(),
                "Internal server error during user creation",
            ),
        }
    }

    /// Authenticate user login
    pub async fn login_user(&self, request: LoginRequest) -> CustomResponse {
        // Get user by email
        let user = match self.database.get_user_by_email(&request.email).await {
            Ok(Some(user)) => user,
            Ok(None) => {
                return CustomResponse::new(
                    ResponsesClientCodes::Unauthorized.get_code(),
                    "Invalid credentials",
                    json!({
                        "error": "Invalid credentials",
                        "message": "Email or password incorrect"
                    })
                    .to_string(),
                    "Authentication failed: invalid email or password",
                );
            },
            Err(e) => {
                return CustomResponse::new(
                    ResponsesServerCodes::InternalServerError.get_code(),
                    "Database error during login",
                    json!({
                        "error": "Database error during login",
                        "details": e.to_string()
                    })
                    .to_string(),
                    "Internal server error during authentication",
                );
            },
        };

        // Check account status
        if user.account_locked {
            return CustomResponse::new(
                ResponsesClientCodes::Forbidden.get_code(),
                "Account locked",
                json!({
                    "error": "Account locked",
                    "message": "Account is temporarily locked due to multiple failed attempts"
                })
                .to_string(),
                "Account access is restricted due to security measures",
            );
        }

        if user.status != "active" {
            return CustomResponse::new(
                ResponsesClientCodes::Forbidden.get_code(),
                "Account inactive",
                json!({
                    "error": "Account inactive",
                    "message": "Account is not active",
                    "status": user.status
                })
                .to_string(),
                "Account is not in active status",
            );
        }

        // Verify password
        let password_valid =
            match PasswordService::verify_password(&request.password, &user.password_hash) {
                Ok(valid) => valid,
                Err(e) => {
                    return CustomResponse::new(
                        ResponsesServerCodes::InternalServerError.get_code(),
                        "Password verification failed",
                        json!({
                            "error": "Password verification failed",
                            "details": e.to_string()
                        })
                        .to_string(),
                        "Internal error during password verification",
                    );
                },
            };

        if !password_valid {
            return CustomResponse::new(
                ResponsesClientCodes::Unauthorized.get_code(),
                "Invalid credentials",
                json!({
                    "error": "Invalid credentials",
                    "message": "Email or password incorrect"
                })
                .to_string(),
                "Authentication failed: invalid email or password",
            );
        }

        // Check if MFA is required
        if user.mfa_enabled {
            return CustomResponse::new(
                ResponsesSuccessCodes::Ok.get_code(),
                "MFA required",
                json!({
                    "message": "MFA required",
                    "mfa_required": true,
                    "user_id": user.id,
                    "next_step": "verify_mfa"
                })
                .to_string(),
                "Multi-factor authentication required to complete login",
            );
        }

        // Generate session token (simplified for now)
        let session_token = format!("session_{}", Uuid::new_v4());

        CustomResponse::new(
            ResponsesSuccessCodes::Ok.get_code(),
            "Login successful",
            json!({
                "message": "Login successful",
                "user_id": user.id,
                "email": user.email,
                "username": user.username,
                "session_token": session_token,
                "mfa_enabled": user.mfa_enabled
            })
            .to_string(),
            "User authentication completed successfully",
        )
    }

    /// Validate user credentials without a full login
    pub async fn validate_credentials(
        &self,
        email: &str,
        password: &str,
    ) -> Result<UserRecord, ApiError> {
        let user =
            self.database.get_user_by_email(email).await?.ok_or(ApiError::InvalidCredentials)?;

        let valid = PasswordService::verify_password(password, &user.password_hash)
            .map_err(|e| ApiError::Auth(format!("Password verification failed: {e}")))?;

        if !valid {
            return Err(ApiError::InvalidCredentials);
        }

        Ok(user)
    }

    /// Check user existence by email
    pub async fn user_exists(&self, email: &str) -> Result<bool, ApiError> {
        self.database.user_exists(email).await
    }
}
