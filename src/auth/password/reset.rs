//! Password reset capability
//!
//! This module provides secure password reset capabilities including
//! - Token generation and validation
//! - Secure storage of reset tokens
//! - Email-based password reset flow
//! - Token expiration and cleanup

use crate::auth::password::security::{PasswordService, SecurePassword};
use crate::types::ApiError;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Password reset token length in bytes
const RESET_TOKEN_LENGTH: usize = 32;

/// Default token expiration time (15 minutes)
const DEFAULT_TOKEN_EXPIRY: i64 = 15 * 60;

/// Password reset token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResetToken {
    /// Token ID
    pub id: Uuid,
    /// User ID this token belongs to
    pub user_id: Uuid,
    /// Hashed token value
    pub token_hash: String,
    /// Token expiration time
    pub expires_at: DateTime<Utc>,
    /// Whether the token has been used
    pub used: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Password reset request
#[derive(Debug, Clone, Deserialize)]
pub struct ResetPasswordRequest {
    /// User's email address
    pub email: String,
}

/// Password reset confirmation
#[derive(Debug, Clone, Deserialize)]
pub struct ResetPasswordConfirmation {
    /// Reset token from email
    pub token: String,
    /// New password
    pub new_password: String,
}

/// Password reset response
#[derive(Debug, Clone, Serialize)]
pub struct ResetPasswordResponse {
    /// Success message
    pub message: String,
    /// Request ID for tracking
    pub request_id: String,
}

/// Password reset service
pub struct PasswordResetService;

impl PasswordResetService {
    /// Generate a new password reset token
    pub fn generate_reset_token(user_id: Uuid) -> Result<(String, ResetToken), ApiError> {
        // Generate a cryptographically secure random token
        let mut token_bytes = [0u8; RESET_TOKEN_LENGTH];
        let mut rng = rand::rng();
        RngCore::fill_bytes(&mut rng, &mut token_bytes);

        // Convert to hex string for transmission
        let token_string = hex::encode(&token_bytes);

        // Hash the token for secure storage
        let token_hash = Self::hash_token(&token_string)?;

        let reset_token = ResetToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash,
            expires_at: Utc::now() + Duration::minutes(DEFAULT_TOKEN_EXPIRY),
            used: false,
            created_at: Utc::now(),
        };

        Ok((token_string, reset_token))
    }

    /// Hash a reset token using SHA-256
    fn hash_token(token: &str) -> Result<String, ApiError> {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    /// Verify a reset token against a stored hash
    pub fn verify_token(token: &str, stored_hash: &str) -> Result<bool, ApiError> {
        let token_hash = Self::hash_token(token)?;
        Ok(token_hash == stored_hash)
    }

    /// Check if a token is expired
    pub fn is_token_expired(token: &ResetToken) -> bool {
        Utc::now() > token.expires_at
    }

    /// Check if a token is valid (not expired, not used)
    pub fn is_token_valid(token: &ResetToken) -> bool {
        !token.used && !Self::is_token_expired(token)
    }

    /// Reset password using a valid token
    pub fn reset_password_with_token(
        token: &str,
        new_password: &str,
        stored_token: &ResetToken,
    ) -> Result<String, ApiError> {
        // Verify token is valid
        if !Self::is_token_valid(stored_token) {
            return Err(ApiError::Auth("Reset token is expired or already used".to_string()));
        }

        // Verify token matches
        if !Self::verify_token(token, &stored_token.token_hash)? {
            return Err(ApiError::Auth("Invalid reset token".to_string()));
        }

        // Create a secure password and hash it
        let secure_password = SecurePassword::new(new_password.to_string());
        let password_hash = PasswordService::hash_secure_password(&secure_password)
            .map_err(|e| ApiError::Password(e.to_string()))?;

        Ok(password_hash)
    }

    /// Generate a secure reset URL
    pub fn generate_reset_url(base_url: &str, token: &str) -> String {
        format!("{}/auth/reset-password?token={}", base_url, token)
    }

    /// Validate reset password request
    pub fn validate_reset_request(request: &ResetPasswordRequest) -> Result<(), ApiError> {
        if request.email.is_empty() {
            return Err(ApiError::Validation("Email is required".to_string()));
        }

        // Basic email validation
        if !request.email.contains('@') {
            return Err(ApiError::Validation("Invalid email format".to_string()));
        }

        Ok(())
    }

    /// Validate reset password confirmation
    pub fn validate_reset_confirmation(
        confirmation: &ResetPasswordConfirmation,
    ) -> Result<(), ApiError> {
        if confirmation.token.is_empty() {
            return Err(ApiError::Validation("Reset token is required".to_string()));
        }

        if confirmation.new_password.is_empty() {
            return Err(ApiError::Validation("A new password is required".to_string()));
        }

        // Validate password strength
        PasswordService::validate_password_strength(&confirmation.new_password)
            .map_err(|e| ApiError::Password(e.to_string()))?;

        Ok(())
    }

    /// Clean up expired tokens (returns the number of tokens that would be deleted)
    pub fn get_cleanup_info() -> (String, String) {
        let query =
            "DELETE FROM password_reset_tokens WHERE expires_at < NOW() OR used = true".to_string();
        let description = "Cleanup expired or used password reset tokens".to_string();
        (query, description)
    }

    /// Execute token cleanup (for database integration)
    pub async fn execute_cleanup_query() -> Result<u64, ApiError> {
        // This function would be connected to the database
        Ok(0) // Return the number of tokens deleted
    }
}

/// Password reset email template data
#[derive(Debug, Clone, Serialize)]
pub struct ResetEmailTemplate {
    /// User's name
    pub name: String,
    /// Reset URL
    pub reset_url: String,
    /// Expiration time in minutes
    pub expiry_minutes: i64,
    /// Service name
    pub service_name: String,
}

impl ResetEmailTemplate {
    /// Create a new reset email template
    pub fn new(name: String, reset_url: String, service_name: String) -> Self {
        Self {
            name,
            reset_url,
            expiry_minutes: DEFAULT_TOKEN_EXPIRY,
            service_name,
        }
    }

    /// Generate email subject
    pub fn get_subject(&self) -> String {
        format!("Password Reset Request - {}", self.service_name)
    }

    /// Generate email body (HTML)
    pub fn get_html_body(&self) -> String {
        format!(
            r#"
            <html>
            <body>
                <h2>Password Reset Request</h2>
                <p>Hello {},</p>
                <p>You have requested to reset your password for {}. Click the link below to reset your password:</p>
                <p><a href="{}" style="background-color: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Reset Password</a></p>
                <p>This link will expire in {} minutes.</p>
                <p>If you didn't request this password reset, please ignore this email.</p>
                <p>Best regards,<br>The {} Team</p>
            </body>
            </html>
            "#,
            self.name, self.service_name, self.reset_url, self.expiry_minutes, self.service_name
        )
    }

    /// Generate email body (plain text)
    pub fn get_text_body(&self) -> String {
        format!(
			"Password Reset Request\n\
            \n\
            Hello {},\n\
            \n\
            You have requested to reset your password for {}. Visit the following URL to reset your password:\n\
            \n\
            {}\n\
            \n\
            This link expires in {} minutes.\n\
            \n\
            If you didn't request this password reset, ignore this email.\n\
            \n\
            Best regards,\n\
            The {} Team",
			self.name, self.service_name, self.reset_url, self.expiry_minutes, self.service_name
		)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_reset_token() {
        let user_id = Uuid::new_v4();
        let result = PasswordResetService::generate_reset_token(user_id);

        assert!(result.is_ok());
        let (token, reset_token) = result.unwrap();

        assert_eq!(token.len(), RESET_TOKEN_LENGTH * 2); // Hex encoded
        assert_eq!(reset_token.user_id, user_id);
        assert!(!reset_token.used);
        assert!(reset_token.expires_at > Utc::now());
    }

    #[test]
    fn test_hash_token() {
        let token = "test_token_123";
        let hash1 = PasswordResetService::hash_token(token).unwrap();
        let hash2 = PasswordResetService::hash_token(token).unwrap();

        assert_eq!(hash1, hash2); // Same token should produce same hash
        assert_ne!(hash1, token); // Hash should be different from the original
    }

    #[test]
    fn test_verify_token() {
        let token = "test_token_123";
        let hash = PasswordResetService::hash_token(token).unwrap();

        assert!(PasswordResetService::verify_token(token, &hash).unwrap());
        assert!(!PasswordResetService::verify_token("wrong_token", &hash).unwrap());
    }

    #[test]
    fn test_token_expiration() {
        let user_id = Uuid::new_v4();
        let mut reset_token = ResetToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash: "hash".to_string(),
            expires_at: Utc::now() - Duration::minutes(1),
            used: false,
            created_at: Utc::now() - Duration::minutes(5),
        };

        assert!(PasswordResetService::is_token_expired(&reset_token));
        assert!(!PasswordResetService::is_token_valid(&reset_token));

        // Test valid token
        reset_token.expires_at = Utc::now() + Duration::minutes(5);
        assert!(!PasswordResetService::is_token_expired(&reset_token));
        assert!(PasswordResetService::is_token_valid(&reset_token));
    }

    #[test]
    fn test_used_token() {
        let user_id = Uuid::new_v4();
        let reset_token = ResetToken {
            id: Uuid::new_v4(),
            user_id,
            token_hash: "hash".to_string(),
            expires_at: Utc::now() + Duration::minutes(5),
            used: true,
            created_at: Utc::now(),
        };

        assert!(!PasswordResetService::is_token_valid(&reset_token));
    }

    #[test]
    fn test_validate_reset_request() {
        let valid_request = ResetPasswordRequest {
            email: "test@example.com".to_string(),
        };
        assert!(PasswordResetService::validate_reset_request(&valid_request).is_ok());

        let invalid_request = ResetPasswordRequest {
            email: "".to_string(),
        };
        assert!(PasswordResetService::validate_reset_request(&invalid_request).is_err());

        let invalid_email = ResetPasswordRequest {
            email: "nonmilitant".to_string(),
        };
        assert!(PasswordResetService::validate_reset_request(&invalid_email).is_err());
    }

    #[test]
    fn test_generate_reset_url() {
        let base_url = "https://example.com";
        let token = "abc123";
        let url = PasswordResetService::generate_reset_url(base_url, token);

        assert_eq!(url, "https://example.com/auth/reset-password?token=abc123");
    }

    #[test]
    fn test_reset_email_template() {
        let template = ResetEmailTemplate::new(
            "John Doe".to_string(),
            "https://example.com/reset?token=abc123".to_string(),
            "MyService".to_string(),
        );

        let subject = template.get_subject();
        assert!(subject.contains("MyService"));

        let html_body = template.get_html_body();
        assert!(html_body.contains("John Doe"));
        assert!(html_body.contains("https://example.com/reset?token=abc123"));

        let text_body = template.get_text_body();
        assert!(text_body.contains("John Doe"));
        assert!(text_body.contains("https://example.com/reset?token=abc123"));
    }
}
