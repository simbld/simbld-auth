//! Authentication module
//!
//! This module provides comprehensive authentication capability including
//! - User registration and login
//! - Password security with SecurePassword wrapper
//! - Multi-factor authentication (MFA)
//! - JWT token management
//! - Session management
//! - OAuth integration
//! - Middleware for route protection

pub mod dto;
pub mod entities;
pub mod handlers;
pub mod jwt;
pub mod mfa;
pub mod middleware;
// TODO: OAuth module temporarily disabled - needs proper implementation with oauth2 crate
// pub mod oauth;
// mod oauth;
pub mod password;
pub mod routes;
pub mod service;
pub mod session;

// Re-export commonly used types
pub use dto::*;
pub use entities::*;
pub use mfa::dto::MfaType;
pub use password::security::PasswordError;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Authentication errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Password error: {0}")]
    PasswordError(#[from] PasswordError),

    #[error("MFA error: {0}")]
    MfaError(#[from] mfa::MfaError),

    #[error("User not found")]
    UserNotFound,

    #[error("User account is locked")]
    UserLocked,

    #[error("Account email isn't verified")]
    AccountNotVerified,

    #[error("MFA verification required")]
    MfaRequired,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Token error: {0}")]
    TokenError(String),

    #[error("Session expired")]
    SessionExpired,

    #[error("Email already exists")]
    EmailAlreadyExists,

    #[error("Username already exists")]
    UsernameAlreadyExists,

    #[error("Invalid email format")]
    InvalidEmail,

    #[error("Account suspended")]
    AccountSuspended,

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("MFA not enabled")]
    MfaNotEnabled,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,
}

/// Authentication result after successful login
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// User ID
    pub user_id: Uuid,
    /// Whether MFA is required to complete authentication
    pub requires_mfa: bool,
    /// Available MFA methods for the user
    pub mfa_methods: Vec<MfaType>,
    /// Session token (JWT access token)
    pub session_token: Option<String>,
    /// Refresh token for getting new access tokens
    pub refresh_token: Option<String>,
    /// Token expiration timestamp
    pub expires_at: Option<i64>,
    /// User profile information
    pub user: Option<UserProfile>,
}

/// Token pair for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPair {
    /// JWT access token
    pub access_token: String,
    /// Refresh token
    pub refresh_token: String,
    /// Access token expiration timestamp
    pub access_expires_at: DateTime<Utc>,
    /// Refresh token expiration timestamp
    pub refresh_expires_at: DateTime<Utc>,
}

/// MFA verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaVerificationResult {
    /// Whether MFA verification was successful
    pub success: bool,
    /// Tokens if verification was successful
    pub tokens: Option<TokenPair>,
    /// User profile if verification was successful
    pub user: Option<UserProfile>,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Password reset request result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetResult {
    /// Whether the reset request was successful
    pub success: bool,
    /// Message for the user
    pub message: String,
    /// Reset token (only for testing, not sent in production)
    #[cfg(test)]
    pub reset_token: Option<String>,
}

/// Email verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationResult {
    /// Whether email verification was successful
    pub success: bool,
    /// Message for the user
    pub message: String,
    /// User profile if verification was successful
    pub user: Option<UserProfile>,
}

/// Registration result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationResult {
    /// Whether registration was successful
    pub success: bool,
    /// User ID if registration was successful
    pub user_id: Option<Uuid>,
    /// Message for the user
    pub message: String,
    /// Whether email verification is required
    pub requires_email_verification: bool,
}

/// Login attempt information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginAttempt {
    /// User ID
    pub user_id: Uuid,
    /// IP address
    pub ip_address: Option<String>,
    /// User personal digital assistant
    pub user_agent: Option<String>,
    /// Whether the attempt was successful
    pub success: bool,
    /// Timestamp of the attempt
    pub timestamp: DateTime<Utc>,
    /// Failure reason if unsuccessful
    pub failure_reason: Option<String>,
}

impl AuthResult {
    /// Create a successful authentication result without MFA
    pub fn success_without_mfa(
        user_id: Uuid,
        session_token: String,
        refresh_token: String,
        expires_at: i64,
        user: Option<UserProfile>,
    ) -> Self {
        Self {
            user_id,
            requires_mfa: false,
            mfa_methods: vec![],
            session_token: Some(session_token),
            refresh_token: Some(refresh_token),
            expires_at: Some(expires_at),
            user,
        }
    }

    /// Create an authentication result that requires MFA
    pub fn requires_mfa(user_id: Uuid, mfa_methods: Vec<MfaType>) -> Self {
        Self {
            user_id,
            requires_mfa: true,
            mfa_methods,
            session_token: None,
            refresh_token: None,
            expires_at: None,
            user: None,
        }
    }

    /// Create a successful authentication result after MFA verification
    pub fn success_with_mfa(
        user_id: Uuid,
        session_token: String,
        refresh_token: String,
        expires_at: i64,
        user: Option<UserProfile>,
    ) -> Self {
        Self {
            user_id,
            requires_mfa: false,
            mfa_methods: vec![],
            session_token: Some(session_token),
            refresh_token: Some(refresh_token),
            expires_at: Some(expires_at),
            user,
        }
    }
}

impl TokenPair {
    /// Create a new token pair
    pub fn new(
        access_token: String,
        refresh_token: String,
        access_expires_at: DateTime<Utc>,
        refresh_expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            access_token,
            refresh_token,
            access_expires_at,
            refresh_expires_at,
        }
    }

    /// Check if the access token is expired
    pub fn is_access_expired(&self) -> bool {
        Utc::now() >= self.access_expires_at
    }

    /// Check if the refresh token is expired
    pub fn is_refresh_expired(&self) -> bool {
        Utc::now() >= self.refresh_expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_result_success_without_mfa() {
        let user_id = Uuid::new_v4();
        let result = AuthResult::success_without_mfa(
            user_id,
            "access_token".to_string(),
            "refresh_token".to_string(),
            1_234_567_890,
            None,
        );

        assert_eq!(result.user_id, user_id);
        assert!(!result.requires_mfa);
        assert!(result.mfa_methods.is_empty());
        assert!(result.session_token.is_some());
        assert!(result.refresh_token.is_some());
        assert!(result.expires_at.is_some());
    }

    #[test]
    fn test_auth_result_requires_mfa() {
        let user_id = Uuid::new_v4();
        let mfa_methods = vec![MfaType::Totp, MfaType::Email];
        let result = AuthResult::requires_mfa(user_id, mfa_methods.clone());

        assert_eq!(result.user_id, user_id);
        assert!(result.requires_mfa);
        assert_eq!(result.mfa_methods.len(), 2);
        assert!(result.session_token.is_none());
        assert!(result.refresh_token.is_none());
        assert!(result.expires_at.is_none());
    }

    #[test]
    fn test_token_pair_expiration() {
        let access_expires = Utc::now() + chrono::Duration::minutes(15);
        let refresh_expires = Utc::now() + chrono::Duration::days(7);

        let token_pair = TokenPair::new(
            "access".to_string(),
            "refresh".to_string(),
            access_expires,
            refresh_expires,
        );

        assert!(!token_pair.is_access_expired());
        assert!(!token_pair.is_refresh_expired());
    }

    #[test]
    fn test_auth_error_display() {
        let error = AuthError::InvalidCredentials;
        assert_eq!(error.to_string(), "Invalid credentials");

        let password_error = PasswordError::TooWeak(1);
        let auth_error = AuthError::from(password_error);
        assert!(auth_error.to_string().contains("Password error"));
    }

    #[test]
    fn test_password_error_conversion() {
        let password_error = PasswordError::TooWeak(1);
        let auth_error = AuthError::from(password_error);
        assert!(matches!(auth_error, AuthError::PasswordError(_)));
    }
}
