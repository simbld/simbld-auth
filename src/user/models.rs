//! User domain models
//!
//! Core user models are aligned with the database schema.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use uuid::Uuid;

/// User role enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, sqlx::Type)]
#[sqlx(type_name = "user_role", rename_all = "lowercase")]
pub enum UserRole {
    User,
    Admin,
    Moderator,
}

impl Default for UserRole {
    fn default() -> Self {
        UserRole::User
    }
}

impl fmt::Display for UserRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UserRole::User => write!(f, "user"),
            UserRole::Admin => write!(f, "admin"),
            UserRole::Moderator => write!(f, "moderator"),
        }
    }
}

/// User account status
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "user_status", rename_all = "lowercase")]
pub enum UserStatus {
    Pending,
    Active,
    Suspended,
    Deactivated,
}

impl Default for UserStatus {
    fn default() -> Self {
        UserStatus::Pending
    }
}

/// User profile model
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub firstname: String,
    pub lastname: String,

    #[serde(skip_serializing)]
    pub password: String,

    pub email_verified: bool,
    pub mfa_enabled: bool,

    #[serde(skip_serializing)]
    pub mfa_secret: Option<String>,

    pub account_locked: bool,
    pub failed_login_attempts: i32,
    pub last_login: Option<DateTime<Utc>>,
    pub password_changed_at: Option<DateTime<Utc>>,

    #[serde(skip_serializing)]
    pub password_history: Option<Value>,

    pub password_expires_at: Option<DateTime<Utc>>,
    pub require_password_change: bool,
    pub status: UserStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Get a user's display name
    pub fn display_name(&self) -> String {
        format!("{} {}", self.firstname, self.lastname)
    }

    /// Check if the user is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active) && !self.account_locked
    }

    /// Check if a user can log in
    pub fn can_login(&self) -> bool {
        self.is_active() && self.email_verified
    }
}

/// User role assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRoleAssignment {
    pub user_id: Uuid,
    pub role: UserRole,
    pub assigned_at: DateTime<Utc>,
    pub assigned_by: Option<Uuid>,
}

/// User profile summary for listings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSummary {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub display_name: String,
    pub status: UserStatus,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserSummary {
    fn from(user: User) -> Self {
        let display_name = user.display_name();
        Self {
            id: user.id,
            username: user.username,
            email: user.email,
            display_name,
            status: user.status,
            email_verified: user.email_verified,
            mfa_enabled: user.mfa_enabled,
            last_login: user.last_login,
            created_at: user.created_at,
        }
    }
}
