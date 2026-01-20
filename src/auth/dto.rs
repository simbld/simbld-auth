//! Data Transfer Objects (DTOs) for authentication module
//!
//! Contains all the request and response structures for auth APIs

use crate::auth::password::security::SecurePassword;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use uuid::Uuid;
use validator::{Validate, ValidationError, ValidationErrors};

static PASSWORD_LENGTH_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^.{12,}$").unwrap());

pub fn is_strong_password(password: &str) -> bool {
    let has_uppercase = password.chars().any(char::is_uppercase);
    let has_lowercase = password.chars().any(char::is_lowercase);
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());
    let has_length = PASSWORD_LENGTH_REGEX.is_match(password);

    has_uppercase && has_lowercase && has_digit && has_special && has_length
}

/// User registration request
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[serde(deserialize_with = "deserialize_secure_password")]
    pub password: SecurePassword,

    #[validate(length(min = 8, max = 50))]
    pub username: String,

    #[validate(length(min = 3, max = 100))]
    pub firstname: String,

    #[validate(length(min = 3, max = 100))]
    pub lastname: String,
}

impl RegisterRequest {
    /// Validate all fields of the registration request
    ///
    /// # Errors
    ///
    /// Returns [`ValidationErrors`] if any field fails automatic validation
    /// or if the password doesn't meet the strength requirements.
    pub fn validate_all(&self) -> Result<(), ValidationErrors> {
        // 1. Automatic validation of normal fields
        self.validate()?;

        // 2. Manual validation of the Password
        let mut errors = ValidationErrors::new();

        if let Err(password_error) = validate_strong_password(&self.password) {
            errors.add("password", password_error);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// MFA verification request
#[derive(Debug, Deserialize, Validate)]
pub struct MfaVerifyRequest {
    pub user_id: Uuid,
    pub mfa_type: MfaType,

    /// The code provided by the user for MFA verification
    #[validate(length(min = 6, max = 8))]
    pub code: String,
    pub remember_me: Option<bool>,
    /// Client device information for tracking sessions
    pub device_info: Option<DeviceInfo>,
}

/// Device information
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Login request
#[derive(Debug, Deserialize, Validate)]
pub struct LoginRequest {
    #[validate(email)]
    pub email: String,

    /// Secure password with validation
    pub password: SecurePassword,

    /// Indicates if the user wants to stay logged in
    pub remember_me: Option<bool>,

    /// Client device information for tracking sessions
    pub device_info: Option<DeviceInfo>,
}

/// Login response
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub requires_mfa: bool,
    pub mfa_methods: Vec<MfaType>,
    pub session_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

/// Session refresh request
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Session response
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

/// Password reset request
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// Password reset confirmation
#[derive(Debug, Deserialize, Validate)]
pub struct PasswordResetConfirm {
    pub token: String,

    #[serde(deserialize_with = "deserialize_secure_password")]
    pub new_password: SecurePassword,
}

impl PasswordResetConfirm {
    /// Validate all fields of the password reset confirmation
    ///
    /// # Errors
    ///
    /// Returns [`ValidationErrors`] if the token is invalid or if the new password
    /// doesn't meet the strength requirements.
    pub fn validate_all(&self) -> Result<(), ValidationErrors> {
        // 1. Automatic validation of normal fields
        self.validate()?;

        // 2. Manual validation of the Password
        let mut errors = ValidationErrors::new();

        if let Err(password_error) = validate_strong_password(&self.new_password) {
            errors.add("new_password", password_error);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Session information response
#[derive(Debug, Serialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub device_info: Option<DeviceInfo>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
}

/// User response data
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: Option<String>,
    pub profile_image: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// User role information
#[derive(Debug, Serialize)]
pub struct UserRoleInfo {
    pub role: String,
    pub permissions: Vec<String>,
}

/// Role assignment request
#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub role: String,
}

/// `WebAuthn` verification request
#[derive(Debug, Deserialize)]
pub struct WebAuthnVerifyRequest {
    pub setup_token: String,
    pub registration_data: String,
}

/// MFA type enumeration
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum MfaType {
    Totp,
    Sms,
    Email,
    Push,
    BackupCode,
    WebAuthn,
}

impl std::fmt::Display for MfaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MfaType::Totp => write!(f, "totp"),
            MfaType::Sms => write!(f, "sms"),
            MfaType::Email => write!(f, "email"),
            MfaType::Push => write!(f, "push"),
            MfaType::BackupCode => write!(f, "backup_code"),
            MfaType::WebAuthn => write!(f, "webauthn"),
        }
    }
}

/// Validation function for strong passwords
///
/// # Errors
///
/// Returns `ValidationError` if the password is too short, too long, or weak.
fn validate_strong_password(password: &SecurePassword) -> Result<(), ValidationError> {
    let password_str = password.expose_secret();

    if password_str.len() < 12 {
        return Err(ValidationError::new("password_too_short"));
    }
    if password_str.len() > 128 {
        return Err(ValidationError::new("password_too_long"));
    }

    // On remplace le Regex look-ahead par des vérifications Rust natives
    let has_uppercase = password_str.chars().any(|c| c.is_uppercase());
    let has_lowercase = password_str.chars().any(|c| c.is_lowercase());
    let has_digit = password_str.chars().any(|c| c.is_ascii_digit());
    let has_special = password_str.chars().any(|c| !c.is_alphanumeric());

    if has_uppercase && has_lowercase && has_digit && has_special {
        Ok(())
    } else {
        Err(ValidationError::new("weak_password"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;
    use validator::Validate;

    #[test]
    fn test_strong_password_regex() {
        // Valid passwords
        assert!(PASSWORD_LENGTH_REGEX.is_match("MyStrongPass123!"));
        assert!(PASSWORD_LENGTH_REGEX.is_match("Tr0ub4dor&3@"));
        assert!(PASSWORD_LENGTH_REGEX.is_match("ComplexPassword2024#"));

        // Invalid passwords
        assert!(!PASSWORD_LENGTH_REGEX.is_match("short"));
        assert!(!PASSWORD_LENGTH_REGEX.is_match("no_uppercase123!"));
        assert!(!PASSWORD_LENGTH_REGEX.is_match("NO_LOWERCASE123!"));
        assert!(!PASSWORD_LENGTH_REGEX.is_match("No_Numbers!"));
        assert!(!PASSWORD_LENGTH_REGEX.is_match("NoSpecialChars123"));
        assert!(!PASSWORD_LENGTH_REGEX.is_match("TooShort1!"));
    }

    #[test]
    fn test_register_request_construction() {
        // Direct construction test (business logic)
        let request = RegisterRequest {
            email: "tester@example.com".to_string(),
            password: SecurePassword::new("StrongPassword123!".to_string()),
            username: "testuser".to_string(),
            firstname: "Test".to_string(),
            lastname: "User".to_string(),
        };

        assert!(request.validate_all().is_ok());
    }

    #[test]
    fn test_register_request_deserialization() {
        // JSON deserialization test (real API)
        let json = r#"{
            "email": "test@example.com",
            "password": "StrongPassword123!",
            "username": "testuser",
            "firstname": "John",
            "lastname": "Doe"
        }"#;

        let request: RegisterRequest = serde_json::from_str(json).unwrap();
        assert!(request.validate_all().is_ok());
    }

    #[test]
    fn test_register_request_weak_password() {
        let weak_request = RegisterRequest {
            email: "test@example.com".to_string(),
            password: SecurePassword::new("weak".to_string()),
            username: "testuser".to_string(),
            firstname: "John".to_string(),
            lastname: "Doe".to_string(),
        };

        let validation_result = weak_request.validate();
        assert!(validation_result.is_err());

        let errors = validation_result.unwrap_err();
        assert!(errors.field_errors().contains_key("password"));
    }

    #[test]
    fn test_password_reset_validation() {
        let valid_reset = PasswordResetConfirm {
            token: "valid_token".to_string(),
            new_password: SecurePassword::new("NewStrongPassword123!".to_string()),
        };

        assert!(valid_reset.validate_all().is_ok());

        let invalid_reset = PasswordResetConfirm {
            token: "valid_token".to_string(),
            new_password: SecurePassword::new("weak".to_string()),
        };

        assert!(invalid_reset.validate_all().is_err());
    }
}
