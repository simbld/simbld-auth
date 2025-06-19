//! Data Transfer Objects (DTOs) for authentication module
//!
//! Contains all the request and response structures for auth APIs

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::mfa::MfaType;

/// Login request DTO
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username_or_email: String,
    pub password: String,
    pub remember_me: Option<bool>,
    /// Client device information for tracking sessions
    pub device_info: Option<DeviceInfoDto>,
}

/// MFA verification request DTO
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    pub user_id: Uuid,
    pub mfa_type: MfaType,
    pub code: String,
    pub remember_me: Option<bool>,
    /// Client device information for tracking sessions
    pub device_info: Option<DeviceInfoDto>,
}

/// Device information DTO
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfoDto {
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Login response DTO
#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub user_id: Uuid,
    pub requires_mfa: bool,
    pub mfa_methods: Vec<MfaType>,
    pub session_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

/// Session refresh request DTO
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

/// Session response DTO
#[derive(Debug, Serialize)]
pub struct SessionResponseDto {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

/// Password reset request DTO
#[derive(Debug, Deserialize)]
pub struct PasswordResetRequestDto {
    pub email: String,
}

/// Password reset confirmation DTO
#[derive(Debug, Deserialize)]
pub struct PasswordResetConfirmDto {
    pub token: String,
    pub new_password: String,
}

/// Session info response DTO
#[derive(Debug, Serialize)]
pub struct SessionInfoDto {
    pub id: Uuid,
    pub device_info: Option<DeviceInfoDto>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
}
