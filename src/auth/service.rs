//! Authentication service layer
//!
//! Contains the business logic for authentication operations including
//! user registration, login, MFA, token management, and password operations.

use crate::auth::dto::{MfaType, UserResponse};
use crate::auth::jwt::{Claims, JwtService};
use crate::auth::password::security::SecurePassword;
use crate::auth::{
    AuthError, AuthResult, MfaVerificationResult, PasswordResetResult, RegistrationResult,
    TokenPair, UserStatus,
};
use crate::sqlx::Database;
use chrono::Utc;
use std::sync::Arc;
use uuid::Uuid;

pub struct AuthService {
    database: Database,
    jwt_service: Arc<JwtService>,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("database", &"<database>")
            .field("jwt_service", &self.jwt_service)
            .finish()
    }
}

impl Clone for AuthService {
    fn clone(&self) -> Self {
        Self {
            database: self.database.clone(),
            jwt_service: Arc::clone(&self.jwt_service),
        }
    }
}

impl AuthService {
    pub fn new(database: Database, jwt_service: JwtService) -> Self {
        Self {
            database,
            jwt_service: Arc::new(jwt_service),
        }
    }

    /// Register a new user
    pub async fn register_user(
        &self,
        email: &str,
        password: &SecurePassword,
        username: &str,
        firstname: &str,
        lastname: &str,
    ) -> Result<RegistrationResult, AuthError> {
        // Check if the user already exists
        if self
            .database
            .user_exists(email)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
        {
            return Ok(RegistrationResult {
                success: false,
                user_id: None,
                message: "Email already exists".to_string(),
                requires_email_verification: false,
            });
        }

        // Create the user in the database
        match self.database.create_user(email, password, username, firstname, lastname).await {
            Ok(user_id) => Ok(RegistrationResult {
                success: true,
                user_id: Some(user_id),
                message: "User registered successfully".to_string(),
                requires_email_verification: true,
            }),
            Err(e) => Err(AuthError::DatabaseError(e.to_string())),
        }
    }

    /// Authenticate user credentials
    pub async fn authenticate_user(
        &self,
        email: &str,
        password: &SecurePassword,
        _device_info: Option<crate::auth::dto::DeviceInfo>,
    ) -> Result<AuthResult, AuthError> {
        // Verify the user login
        let is_valid = self
            .database
            .verify_user_login(email, password.expose_secret())
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        if !is_valid {
            return Err(AuthError::InvalidCredentials);
        }

        // Get the user details
        let user = self
            .database
            .get_user_by_email(email)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?
            .ok_or(AuthError::UserNotFound)?;

        // Check if the user is locked
        if user.account_locked {
            return Err(AuthError::UserLocked);
        }

        // Check if the email is verified
        if !user.email_verified {
            return Err(AuthError::AccountNotVerified);
        }

        // Check if MFA is enabled
        if user.mfa_enabled {
            Ok(AuthResult::requires_mfa(user.id, vec![MfaType::Totp]))
        } else {
            // Generate the tokens
            let token_pair = self.generate_tokens(user.id)?;

            // Pour l'instant, on utilise un profil basique - TODO: ajouter to_profile() à UserRecord
            let user_profile = crate::auth::entities::UserProfile {
                id: user.id,
                email: user.email.clone(),
                username: user.username.clone(),
                firstname: user.firstname.clone(),
                lastname: user.lastname.clone(),
                email_verified: user.email_verified,
                mfa_enabled: user.mfa_enabled,
                created_at: user.created_at,
                last_login: user.last_login,
                status: UserStatus::from(user.status),
            };

            Ok(AuthResult {
                user_id: user.id,
                requires_mfa: false,
                mfa_methods: vec![],
                session_token: Some(token_pair.access_token),
                refresh_token: Some(token_pair.refresh_token),
                expires_at: Some(token_pair.access_expires_at.timestamp()),
                user: Some(user_profile),
            })
        }
    }

    /// Verify MFA code
    pub async fn verify_mfa_code(
        &self,
        user_id: Uuid,
        code: &str,
        _mfa_type: &MfaType,
    ) -> Result<MfaVerificationResult, AuthError> {
        // TODO: Implement actual MFA verification logic
        // For now, simple validation
        if code == "123456" {
            let token_pair = self.generate_tokens(user_id)?;
            Ok(MfaVerificationResult {
                success: true,
                tokens: Some(token_pair),
                user: None,
                error: None,
            })
        } else {
            Ok(MfaVerificationResult {
                success: false,
                tokens: None,
                user: None,
                error: Some("Invalid MFA code".to_string()),
            })
        }
    }

    /// Generate access and refresh tokens
    fn generate_tokens(&self, user_id: Uuid) -> Result<TokenPair, AuthError> {
        let claims = Claims::new(user_id);

        let access_token = self
            .jwt_service
            .generate_access_token(&claims)
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        let refresh_token = self
            .jwt_service
            .generate_refresh_token(&claims)
            .map_err(|e| AuthError::TokenError(e.to_string()))?;

        Ok(TokenPair::new(
            access_token,
            refresh_token,
            Utc::now() + chrono::Duration::hours(1),
            Utc::now() + chrono::Duration::days(30),
        ))
    }

    /// Refresh access token
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let claims = self
            .jwt_service
            .validate_refresh_token(refresh_token)
            .map_err(|_| AuthError::InvalidToken)?;

        self.generate_tokens(claims.user_id)
    }

    /// Logout user (invalidate refresh token)
    pub async fn logout(&self, _refresh_token: &str) -> Result<(), AuthError> {
        // TODO: Add refresh token to the blacklist or remove from the database
        Ok(())
    }

    /// Request password reset
    pub async fn request_password_reset(
        &self,
        _email: &str,
    ) -> Result<PasswordResetResult, AuthError> {
        // TODO: Implement password reset logic
        Ok(PasswordResetResult {
            success: true,
            message: "Password reset instructions sent".to_string(),
            #[cfg(test)]
            reset_token: Some("dummy_token".to_string()),
        })
    }

    /// Confirm password reset
    pub async fn confirm_password_reset(
        &self,
        _token: &str,
        _new_password: &SecurePassword,
    ) -> Result<PasswordResetResult, AuthError> {
        // TODO: Implement password reset confirmation logic
        Ok(PasswordResetResult {
            success: true,
            message: "Password reset successful".to_string(),
            #[cfg(test)]
            reset_token: None,
        })
    }

    /// Validate JWT token
    pub async fn validate_token(&self, token: &str) -> Result<Claims, AuthError> {
        self.jwt_service.validate_access_token(token).map_err(|_| AuthError::InvalidToken)
    }

    /// Get user profile
    pub async fn get_user_profile(&self, user_id: Uuid) -> Result<UserResponse, AuthError> {
        // TODO: Fix this - add get_user_by_id method to Database
        // For now, return a dummy response
        Ok(UserResponse {
            id: user_id.to_string(),
            username: "username".to_string(),
            email: "email@example.com".to_string(),
            display_name: Some("Display Name".to_string()),
            profile_image: None,
            created_at: Utc::now().to_rfc3339(),
            updated_at: Utc::now().to_rfc3339(),
        })
    }
}
