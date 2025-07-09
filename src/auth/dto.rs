//! Data Transfer Objects (DTOs) for authentication module
//!
//! Contains all the request and response structures for auth APIs

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// User registration request
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    #[validate(email)]
    pub email: String,

    #[validate(length(min = 8, max = 128))]
    pub password: String,

    #[validate(length(min = 8, max = 50))]
    pub username: String,

    #[validate(length(min = 3, max = 100))]
    pub firstname: String,

    #[validate(length(min = 3, max = 100))]
    pub lastname: String,
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
#[derive(Debug, Serialize, Deserialize)]
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

    #[validate(length(min = 1))]
    pub password: String,

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
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirm {
    pub token: String,
    pub new_password: String,
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

/// WebAuthn verification request
#[derive(Debug, Deserialize)]
pub struct WebAuthnVerifyRequest {
    pub setup_token: String,
    pub registration_data: String,
}

/// MFA type enumeration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MfaType {
    Totp,
    Sms,
    Email,
    Push,
    BackupCode,
}
