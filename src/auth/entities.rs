//! Authentication entities
//!
//! This module contains centralized entity definitions for authentication:
//! - User entities and profiles
//! - Authentication tokens
//! - Session management
//! - MFA entities
//! - Audit logging

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// User entity - core user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Unique user, identifier
    pub id: Uuid,
    /// User's email address
    pub email: String,
    /// Username
    pub username: String,
    /// User's first name
    pub firstname: String,
    /// User's last name
    pub lastname: String,
    /// Hashed password
    #[serde(skip_serializing)]
    pub password_hash: String,
    /// Email verification status
    pub email_verified: bool,
    /// MFA enabled status
    pub mfa_enabled: bool,
    /// Account locked status
    pub account_locked: bool,
    /// Failed login attempts counter
    pub failed_login_attempts: i32,
    /// Last successful login
    pub last_login: Option<DateTime<Utc>>,
    /// Account status
    pub status: UserStatus,
    /// Account creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
}

/// User status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    /// Account is active and can be used
    Active,
    /// Account is inactive (temporarily disabled)
    Inactive,
    /// Account is suspended (administrator action)
    Suspended,
    /// Account is pending email verification
    Pending,
    /// Account is permanently deleted
    Deleted,
}

/// Public user profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// User ID
    pub id: Uuid,
    /// Email address
    pub email: String,
    /// Username
    pub username: String,
    /// First name
    pub firstname: String,
    /// Last name
    pub lastname: String,
    /// Email verification status
    pub email_verified: bool,
    /// MFA enabled status
    pub mfa_enabled: bool,
    /// Account creation date
    pub created_at: DateTime<Utc>,
    /// Last login date
    pub last_login: Option<DateTime<Utc>>,
    /// Account status
    pub status: UserStatus,
}

/// Authentication session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    /// Session ID
    pub id: Uuid,
    /// User ID this session belongs to
    pub user_id: Uuid,
    /// Session token
    pub token_hash: String,
    /// Session expiration time
    pub expires_at: DateTime<Utc>,
    /// Session creation time
    pub created_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// IP address of the session
    pub ip_address: Option<String>,
    /// User personal digital assistant string
    pub user_agent: Option<String>,
    /// Whether the session is active
    pub active: bool,
}

/// JWT token claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    /// Subject (user ID)
    pub sub: String,
    /// Email
    pub email: String,
    /// Username
    pub username: String,
    /// Issued at
    pub iat: i64,
    /// Expiration time
    pub exp: i64,
    /// JWT ID
    pub jti: String,
    /// Token type
    pub token_type: TokenType,
    /// MFA verified
    pub mfa_verified: bool,
}

/// Token type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TokenType {
    /// Access token for API access
    Access,
    /// Refresh token for getting new access tokens
    Refresh,
    /// Email verification token
    EmailVerification,
    /// Password reset token
    PasswordReset,
}

/// MFA device information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaDevice {
    /// Device ID
    pub id: Uuid,
    /// User ID this device belongs to
    pub user_id: Uuid,
    /// Device type
    pub device_type: MfaDeviceType,
    /// Device name
    pub name: String,
    /// Device encrypted secret
    #[serde(skip_serializing)]
    pub secret: String,
    /// Whether a device is active
    pub active: bool,
    /// Backup codes
    #[serde(skip_serializing)]
    pub backup_codes: Option<Vec<String>>,
    /// Device creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// MFA device type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MfaDeviceType {
    /// TOTP (Time-based One-Time Password)
    Totp,
    /// SMS-based verification
    Sms,
    /// Email-based verification
    Email,
    /// Hardware security key
    SecurityKey,
    /// Backup codes
    BackupCodes,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLog {
    /// Log entry ID
    pub id: Uuid,
    /// User ID
    pub user_id: Option<Uuid>,
    /// Action performed
    pub action: AuditAction,
    /// Resource affected
    pub resource: String,
    /// Additional details
    pub details: Option<serde_json::Value>,
    /// IP address
    pub ip_address: Option<String>,
    /// User personal digital assistant
    pub user_agent: Option<String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Success status
    pub success: bool,
    /// Error message
    pub error: Option<String>,
}

/// Audit action enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// User registration
    UserRegistration,
    /// User login
    UserLogin,
    /// User logout
    UserLogout,
    /// Password change
    PasswordChange,
    /// Password reset request
    PasswordResetRequest,
    /// Password reset completion
    PasswordResetComplete,
    /// Email verification
    EmailVerification,
    /// MFA setup
    MfaSetup,
    /// MFA removal
    MfaRemoval,
    /// MFA verification
    MfaVerification,
    /// Account lock
    AccountLock,
    /// Account unlock
    AccountUnlock,
    /// Account suspension
    AccountSuspension,
    /// Account deletion
    AccountDeletion,
    /// Session creation
    SessionCreation,
    /// Session termination
    SessionTermination,
    /// Profile update
    ProfileUpdate,
    /// Permission change
    PermissionChange,
}

/// Email verification token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailVerificationToken {
    /// Token ID
    pub id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Token hash
    pub token_hash: String,
    /// Email to verify
    pub email: String,
    /// Token expiration
    pub expires_at: DateTime<Utc>,
    /// Whether a token is used
    pub used: bool,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Rate limiting entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    /// Rate limit ID
    pub id: Uuid,
    /// Identifier for the rate limit (for example, user ID, IP address)
    pub identifier: String,
    /// Rate limit type
    pub limit_type: RateLimitType,
    /// Current count
    pub count: i32,
    /// Window start time
    pub window_start: DateTime<Utc>,
    /// Window duration in seconds
    pub window_duration: i32,
    /// Maximum allowed requests
    pub max_requests: i32,
}

/// Rate limit type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitType {
    /// Login attempts
    LoginAttempts,
    /// Password reset requests
    PasswordReset,
    /// Registration attempts
    Registration,
    /// Email verification requests
    EmailVerification,
    /// MFA verification attempts
    MfaVerification,
    /// General API requests
    ApiRequests,
}

impl User {
    /// Create a new user
    pub fn new(
        email: String,
        username: String,
        firstname: String,
        lastname: String,
        password_hash: String,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            email,
            username,
            firstname,
            lastname,
            password_hash,
            email_verified: false,
            mfa_enabled: false,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            status: UserStatus::Pending,
            created_at: now,
            updated_at: now,
        }
    }

    /// Convert to public profile
    pub fn to_profile(&self) -> UserProfile {
        UserProfile {
            id: self.id,
            email: self.email.clone(),
            username: self.username.clone(),
            firstname: self.firstname.clone(),
            lastname: self.lastname.clone(),
            email_verified: self.email_verified,
            mfa_enabled: self.mfa_enabled,
            created_at: self.created_at,
            last_login: self.last_login,
            status: self.status.clone(),
        }
    }

    /// Check if the user is active
    pub fn is_active(&self) -> bool {
        matches!(self.status, UserStatus::Active) && !self.account_locked
    }

    /// Check if a user can log in
    pub fn can_login(&self) -> bool {
        self.is_active() && self.email_verified
    }

    /// Get the full name
    pub fn full_name(&self) -> String {
        format!("{} {}", self.firstname, self.lastname)
    }
}

impl AuthSession {
    /// Create a new session
    pub fn new(
        user_id: Uuid,
        token_hash: String,
        expires_at: DateTime<Utc>,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            user_id,
            token_hash,
            expires_at,
            created_at: now,
            last_activity: now,
            ip_address,
            user_agent,
            active: true,
        }
    }

    /// Check if the session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if the session is valid
    pub fn is_valid(&self) -> bool {
        self.active && !self.is_expired()
    }

    /// Update last activity
    pub fn update_activity(&mut self) {
        self.last_activity = Utc::now();
    }
}

impl TokenClaims {
    /// Create new token claims
    pub fn new(
        user_id: Uuid,
        email: String,
        username: String,
        token_type: TokenType,
        expires_in: i64,
        mfa_verified: bool,
    ) -> Self {
        let now = Utc::now().timestamp();
        Self {
            sub: user_id.to_string(),
            email,
            username,
            iat: now,
            exp: now + expires_in,
            jti: Uuid::new_v4().to_string(),
            token_type,
            mfa_verified,
        }
    }

    /// Check if the token is expired
    pub fn is_expired(&self) -> bool {
        Utc::now().timestamp() > self.exp
    }
}

impl MfaDevice {
    /// Create a new MFA device
    pub fn new(user_id: Uuid, device_type: MfaDeviceType, name: String, secret: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            device_type,
            name,
            secret,
            active: true,
            backup_codes: None,
            created_at: Utc::now(),
            last_used: None,
        }
    }

    /// Mark the device as used
    pub fn mark_used(&mut self) {
        self.last_used = Some(Utc::now());
    }
}

impl AuditLog {
    /// Create a new audit log entry
    pub fn new(
        user_id: Option<Uuid>,
        action: AuditAction,
        resource: String,
        success: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            user_id,
            action,
            resource,
            details: None,
            ip_address,
            user_agent,
            timestamp: Utc::now(),
            success,
            error: None,
        }
    }

    /// Add details to the log entry
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    /// Add error to log entry
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self.success = false;
        self
    }
}

impl From<String> for UserStatus {
    fn from(status: String) -> Self {
        match status.to_lowercase().as_str() {
            "active" => UserStatus::Active,
            "inactive" => UserStatus::Inactive,
            "suspended" => UserStatus::Suspended,
            "pending" => UserStatus::Pending,
            "deleted" => UserStatus::Deleted,
            _ => UserStatus::Inactive, // Default fallback
        }
    }
}

impl From<UserStatus> for String {
    fn from(status: UserStatus) -> Self {
        match status {
            UserStatus::Active => "active".to_string(),
            UserStatus::Inactive => "inactive".to_string(),
            UserStatus::Suspended => "suspended".to_string(),
            UserStatus::Pending => "pending".to_string(),
            UserStatus::Deleted => "deleted".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "test@example.com".to_string(),
            "tester".to_string(),
            "Test".to_string(),
            "User".to_string(),
            "hashed_password".to_string(),
        );

        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.username, "tester");
        assert!(!user.email_verified);
        assert!(!user.mfa_enabled);
        assert_eq!(user.status, UserStatus::Pending);
        assert!(!user.can_login()); // Can't login without email verification
    }

    #[test]
    fn test_user_profile_conversion() {
        let user = User::new(
            "test@example.com".to_string(),
            "tester".to_string(),
            "Test".to_string(),
            "User".to_string(),
            "hashed_password".to_string(),
        );

        let profile = user.to_profile();
        assert_eq!(profile.email, user.email);
        assert_eq!(profile.username, user.username);
        // Password hash shouldn't be in the profile
    }

    #[test]
    fn test_user_full_name() {
        let user = User::new(
            "test@example.com".to_string(),
            "tester".to_string(),
            "John".to_string(),
            "Doe".to_string(),
            "hashed_password".to_string(),
        );

        assert_eq!(user.full_name(), "John Doe");
    }

    #[test]
    fn test_session_creation() {
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let session = AuthSession::new(
            user_id,
            "token_hash".to_string(),
            expires_at,
            Some("127.0.0.1".to_string()),
            Some("Test Personal digital assistant".to_string()),
        );

        assert_eq!(session.user_id, user_id);
        assert!(session.is_valid());
        assert!(!session.is_expired());
    }

    #[test]
    fn test_token_claims_creation() {
        let user_id = Uuid::new_v4();
        let claims = TokenClaims::new(
            user_id,
            "test@example.com".to_string(),
            "tester".to_string(),
            TokenType::Access,
            3600, // 1 hour
            false,
        );

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, TokenType::Access);
        assert!(!claims.is_expired());
    }

    #[test]
    fn test_audit_log_creation() {
        let user_id = Uuid::new_v4();
        let log = AuditLog::new(
            Some(user_id),
            AuditAction::UserLogin,
            "user_login".to_string(),
            true,
            Some("127.0.0.1".to_string()),
            Some("Test Personal digital assistant".to_string()),
        );

        assert_eq!(log.user_id, Some(user_id));
        assert_eq!(log.action, AuditAction::UserLogin);
        assert!(log.success);
        assert!(log.error.is_none());
    }

    #[test]
    fn test_mfa_device_creation() {
        let user_id = Uuid::new_v4();
        let device = MfaDevice::new(
            user_id,
            MfaDeviceType::Totp,
            "Phone App".to_string(),
            "secret_key".to_string(),
        );

        assert_eq!(device.user_id, user_id);
        assert_eq!(device.device_type, MfaDeviceType::Totp);
        assert!(device.active);
        assert!(device.last_used.is_none());
    }
}
