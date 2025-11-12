//! User Data Transfer Objects
//!
//! DTOs for user profile operations and responses.

use crate::user::models::{UserRole, UserStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use validator::Validate;

/// User profile response
#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub firstname: String,
    pub lastname: String,
    pub display_name: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub status: UserStatus,
    pub last_login: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Update user profile request
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateProfileRequest {
    #[validate(length(min = 3, max = 100))]
    pub firstname: Option<String>,

    #[validate(length(min = 3, max = 100))]
    pub lastname: Option<String>,

    #[validate(length(min = 3, max = 50))]
    pub username: Option<String>,
}

/// Change password request
#[derive(Debug, Deserialize, Validate)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 8))]
    pub current_password: String,

    #[validate(length(min = 8, max = 128))]
    pub new_password: String,
}

/// Admin: Update user status request
#[derive(Debug, Deserialize, Validate)]
pub struct UpdateUserStatusRequest {
    pub status: UserStatus,
    pub reason: Option<String>,
}

/// Admin: Assign role request
#[derive(Debug, Deserialize, Validate)]
pub struct AssignRoleRequest {
    pub role: UserRole,
}

/// List users query parameters
#[derive(Debug, Deserialize, Validate)]
pub struct ListUsersQuery {
    #[validate(range(min = 1, max = 100))]
    pub limit: Option<i64>,

    #[validate(range(min = 0))]
    pub offset: Option<i64>,

    pub status: Option<UserStatus>,
    pub role: Option<UserRole>,
    pub email_verified: Option<bool>,
    pub search: Option<String>,
}

impl Default for ListUsersQuery {
    fn default() -> Self {
        Self {
            limit: Some(50),
            offset: Some(0),
            status: None,
            role: None,
            email_verified: None,
            search: None,
        }
    }
}

/// User list response
#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserSummary>,
    pub total: i64,
    pub limit: i64,
    pub offset: i64,
}

/// User summary for lists
#[derive(Debug, Serialize)]
pub struct UserSummary {
    pub id: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub status: UserStatus,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub roles: Vec<UserRole>,
    pub last_login: Option<String>,
    pub created_at: String,
}

/// User statistics response
#[derive(Debug, Serialize)]
pub struct UserStatsResponse {
    pub total_users: i64,
    pub active_users: i64,
    pub pending_users: i64,
    pub suspended_users: i64,
    pub verified_emails: i64,
    pub mfa_enabled: i64,
    pub recent_logins: i64,
}

/// Convert DateTime to RFC3339 string
pub fn datetime_to_string(dt: Option<DateTime<Utc>>) -> Option<String> {
    dt.map(|d| d.to_rfc3339())
}

/// Convert DateTime to RFC3339 string (required)
pub fn datetime_to_string_required(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339()
}
