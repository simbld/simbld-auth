//! # Authentication Models
//!
//! This module defines the data models used in the authentication system.
//! These models represent users, tokens, sessions, and other related entities.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Represents the type of Multi-Factor Authentication (MFA)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaType {
    Totp,
    WebAuthn,
    BackupCode,
    Sms,
}

/// Represents a user in the system
#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub profile_image: Option<String>,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub account_locked: bool,
    pub failed_login_attempts: i32,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub password_changed_at: Option<DateTime<Utc>>,
    pub password_history: Vec<String>,
    pub password_expires_at: Option<DateTime<Utc>>,
    pub require_password_change: bool,
}

/// Represents a database role with associated permissions
#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseRole {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
}

/// Represents a user's role in the system
#[derive(Debug, Serialize, Deserialize)]
pub struct UserRole {
    pub user_id: Uuid,
    pub role_id: Uuid,
}

/// A user's refresh token for obtaining new access tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub token: String,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub created_at: DateTime<Utc>,
}

/// Represents a user session
#[derive(Debug, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub ip_address: String,
    pub user_agent: String,
    pub expires_at: DateTime<Utc>,
    pub is_revoked: bool,
    pub last_activity: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl Session {
    /// Implementation to check if a session is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }
}

/// MFA setup information for a user
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaSetup {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret: String,
    pub is_verified: bool,
    pub created_at: DateTime<Utc>,
}

/// User role for authorization
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum Role {
    User,
    Admin,
    Moderator,
}

/// Represents a user's login attempt for security monitoring
#[derive(Debug, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub email: String,
    pub ip_address: String,
    pub user_agent: String,
    pub successful: bool,
    pub failure_reason: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Represents a password reset request
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordReset {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

/// Represents an OAuth provider linked to a user
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub id: Uuid,
    pub provider_name: String,
    pub provider_user_id: String,
    pub user_id: Uuid,
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    #[test]
    fn test_user_serialization_deserialization() {
        // Create a test user
        let user = User {
            id: Uuid::new_v4(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "".to_string(),
            display_name: None,
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
        };

        // Serialize to JSON
        let serialized = serde_json::to_string(&user).expect("Failed to serialize User");

        // Deserialize back to User
        let deserialized: User =
            serde_json::from_str(&serialized).expect("Failed to deserialize User");

        // Verify the round trip
        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.username, deserialized.username);
        assert_eq!(user.email, deserialized.email);

        // Timestamp comparison might be slightly off due to precision issues in JSON serialization
        assert!(
            (user.created_at - deserialized.created_at).num_milliseconds().abs() < 10,
            "created_at timestamps should be close"
        );
        assert!(
            (user.updated_at - deserialized.updated_at).num_milliseconds().abs() < 10,
            "updated_at timestamps should be close"
        );
    }

    #[test]
    fn test_refresh_token_serialization_deserialization() {
        // Create a test refresh token
        let refresh_token = RefreshToken {
            id: Uuid::new_v4(),
            token: "test_token_string".to_string(),
            user_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            expires_at: Utc::now() + Duration::days(7),
            is_revoked: false,
            created_at: Utc::now(),
        };

        // Serialize to JSON
        let serialized =
            serde_json::to_string(&refresh_token).expect("Failed to serialize RefreshToken");

        // Deserialize back to RefreshToken
        let deserialized: RefreshToken =
            serde_json::from_str(&serialized).expect("Failed to deserialize RefreshToken");

        // Verify the round trip
        assert_eq!(refresh_token.id, deserialized.id);
        assert_eq!(refresh_token.token, deserialized.token);
        assert_eq!(refresh_token.user_id, deserialized.user_id);
        assert_eq!(refresh_token.session_id, deserialized.session_id);
        assert_eq!(refresh_token.is_revoked, deserialized.is_revoked);

        // Timestamp comparison
        assert!(
            (refresh_token.expires_at - deserialized.expires_at).num_milliseconds().abs() < 10,
            "expires_at timestamps should be close"
        );
        assert!(
            (refresh_token.created_at - deserialized.created_at).num_milliseconds().abs() < 10,
            "created_at timestamps should be close"
        );
    }

    #[test]
    fn test_session_serialization_deserialization() {
        // Create a test session
        let session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string(),
            expires_at: Utc::now() + Duration::days(30),
            is_revoked: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
        };

        // Serialize to JSON
        let serialized = serde_json::to_string(&session).expect("Failed to serialize Session");

        // Deserialize back to Session
        let deserialized: Session =
            serde_json::from_str(&serialized).expect("Failed to deserialize Session");

        // Verify the round trip
        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.user_id, deserialized.user_id);
        assert_eq!(session.ip_address, deserialized.ip_address);
        assert_eq!(session.user_agent, deserialized.user_agent);
        assert_eq!(session.is_revoked, deserialized.is_revoked);

        // Timestamp comparison
        assert!(
            (session.expires_at - deserialized.expires_at).num_milliseconds().abs() < 10,
            "expires_at timestamps should be close"
        );
        assert!(
            (session.last_activity - deserialized.last_activity).num_milliseconds().abs() < 10,
            "last_activity timestamps should be close"
        );
        assert!(
            (session.created_at - deserialized.created_at).num_milliseconds().abs() < 10,
            "created_at timestamps should be close"
        );
    }

    #[test]
    fn test_session_is_expired() {
        // Create a non-expired session
        let future_time = Utc::now() + Duration::hours(1);
        let valid_session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Agent".to_string(),
            expires_at: future_time,
            is_revoked: false,
            last_activity: Utc::now(),
            created_at: Utc::now() - Duration::days(1),
        };

        // The session should not be expired
        assert!(!valid_session.is_expired());

        // Create an expired session
        let past_time = Utc::now() - Duration::hours(1);
        let expired_session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Agent".to_string(),
            expires_at: past_time,
            is_revoked: false,
            last_activity: Utc::now() - Duration::hours(2),
            created_at: Utc::now() - Duration::days(1),
        };

        // The session should be expired
        assert!(expired_session.is_expired());

        // Test a revoked session (should be considered expired regardless of time)
        let revoked_session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Agent".to_string(),
            expires_at: future_time, // Even with future expiration
            is_revoked: true,        // But it's revoked
            last_activity: Utc::now(),
            created_at: Utc::now() - Duration::days(1),
        };

        // The session should be considered expired because it's revoked
        assert!(revoked_session.is_expired());
    }

    #[test]
    fn test_mfa_setup_serialization_deserialization() {
        // Create a test MFA setup
        let mfa_setup = MfaSetup {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            secret: "AAABBBCCCDDDEEEFFFGGG".to_string(),
            is_verified: true,
            created_at: Utc::now(),
        };

        // Serialize to JSON
        let serialized = serde_json::to_string(&mfa_setup).expect("Failed to serialize MfaSetup");

        // Deserialize back to MfaSetup
        let deserialized: MfaSetup =
            serde_json::from_str(&serialized).expect("Failed to deserialize MfaSetup");

        // Verify the round trip
        assert_eq!(mfa_setup.id, deserialized.id);
        assert_eq!(mfa_setup.user_id, deserialized.user_id);
        assert_eq!(mfa_setup.secret, deserialized.secret);
        assert_eq!(mfa_setup.is_verified, deserialized.is_verified);

        // Timestamp comparison
        assert!(
            (mfa_setup.created_at - deserialized.created_at).num_milliseconds().abs() < 10,
            "created_at timestamps should be close"
        );
    }

    #[test]
    fn test_role_serialization_deserialization() {
        // Test all role variants
        let roles = vec![Role::User, Role::Admin, Role::Moderator];

        for role in roles {
            // Serialize to JSON
            let serialized = serde_json::to_string(&role).expect("Failed to serialize Role");

            // Deserialize back to Role
            let deserialized: Role =
                serde_json::from_str(&serialized).expect("Failed to deserialize Role");

            // Verify the round trip
            assert_eq!(role, deserialized);
        }
    }

    #[test]
    fn test_role_equality() {
        // Test equality and inequality for roles
        assert_eq!(Role::User, Role::User);
        assert_eq!(Role::Admin, Role::Admin);
        assert_eq!(Role::Moderator, Role::Moderator);

        assert_ne!(Role::User, Role::Admin);
        assert_ne!(Role::User, Role::Moderator);
        assert_ne!(Role::Admin, Role::Moderator);
    }

    #[test]
    fn test_login_attempt_serialization_deserialization() {
        // Create a successful login attempt
        let successful_attempt = LoginAttempt {
            id: Uuid::new_v4(),
            user_id: Some(Uuid::new_v4()),
            email: "user@example.com".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Browser".to_string(),
            successful: true,
            failure_reason: None,
            created_at: Utc::now(),
        };

        // Serialize to JSON
        let serialized =
            serde_json::to_string(&successful_attempt).expect("Failed to serialize LoginAttempt");

        // Deserialize back to LoginAttempt
        let deserialized: LoginAttempt =
            serde_json::from_str(&serialized).expect("Failed to deserialize LoginAttempt");

        // Verify the round trip
        assert_eq!(successful_attempt.id, deserialized.id);
        assert_eq!(successful_attempt.user_id, deserialized.user_id);
        assert_eq!(successful_attempt.email, deserialized.email);
        assert_eq!(successful_attempt.ip_address, deserialized.ip_address);
        assert_eq!(successful_attempt.user_agent, deserialized.user_agent);
        assert_eq!(successful_attempt.successful, deserialized.successful);
        assert_eq!(successful_attempt.failure_reason, deserialized.failure_reason);

        // Create a failed login attempt
        let failed_attempt = LoginAttempt {
            id: Uuid::new_v4(),
            user_id: None,
            email: "nonexistent@example.com".to_string(),
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Browser".to_string(),
            successful: false,
            failure_reason: Some("Invalid credentials".to_string()),
            created_at: Utc::now(),
        };

        // Serialize to JSON
        let serialized =
            serde_json::to_string(&failed_attempt).expect("Failed to serialize LoginAttempt");

        // Deserialize back to LoginAttempt
        let deserialized: LoginAttempt =
            serde_json::from_str(&serialized).expect("Failed to deserialize LoginAttempt");

        // Verify the round trip for failed attempt
        assert_eq!(failed_attempt.id, deserialized.id);
        assert_eq!(failed_attempt.user_id, deserialized.user_id);
        assert_eq!(failed_attempt.email, deserialized.email);
        assert_eq!(failed_attempt.ip_address, deserialized.ip_address);
        assert_eq!(failed_attempt.user_agent, deserialized.user_agent);
        assert_eq!(failed_attempt.successful, deserialized.successful);
        assert_eq!(failed_attempt.failure_reason, deserialized.failure_reason);
    }

    #[test]
    fn test_password_reset_serialization_deserialization() {
        // Create a test password reset
        let password_reset = PasswordReset {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token: "reset_token_123456".to_string(),
            expires_at: Utc::now() + Duration::hours(24),
            used: false,
            created_at: Utc::now(),
        };

        // Serialize to JSON
        let serialized =
            serde_json::to_string(&password_reset).expect("Failed to serialize PasswordReset");

        // Deserialize back to PasswordReset
        let deserialized: PasswordReset =
            serde_json::from_str(&serialized).expect("Failed to deserialize PasswordReset");

        // Verify the round trip
        assert_eq!(password_reset.id, deserialized.id);
        assert_eq!(password_reset.user_id, deserialized.user_id);
        assert_eq!(password_reset.token, deserialized.token);
        assert_eq!(password_reset.used, deserialized.used);

        // Timestamp comparison
        assert!(
            (password_reset.expires_at - deserialized.expires_at).num_milliseconds().abs() < 10,
            "expires_at timestamps should be close"
        );
        assert!(
            (password_reset.created_at - deserialized.created_at).num_milliseconds().abs() < 10,
            "created_at timestamps should be close"
        );
    }

    #[test]
    fn test_json_structure() {
        // Test that JSON structure matches expected format
        let user = User {
            id: Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "".to_string(),
            display_name: None,
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
        };

        let json = serde_json::to_string(&user).unwrap();

        // Make sure JSON contains all expected fields
        assert!(json.contains("\"id\":\"00000000-0000-0000-0000-000000000001\""));
        assert!(json.contains("\"username\":\"testuser\""));
        assert!(json.contains("\"email\":\"test@example.com\""));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains("\"updated_at\":"));
    }

    #[test]
    fn test_model_relationships() {
        // Create a user and related entities to test relationships
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();

        // Create user
        let user = User {
            id: user_id,
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "".to_string(),
            display_name: None,
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
        };

        // Create session for user
        let session = Session {
            id: session_id,
            user_id, // Reference to user
            ip_address: "192.168.1.1".to_string(),
            user_agent: "Test Agent".to_string(),
            expires_at: Utc::now() + Duration::days(7),
            is_revoked: false,
            last_activity: Utc::now(),
            created_at: Utc::now(),
        };

        // Create refresh token for user and session
        let refresh_token = RefreshToken {
            id: Uuid::new_v4(),
            token: "refresh_token_123456".to_string(),
            user_id,    // Reference to user
            session_id, // Reference to session
            expires_at: Utc::now() + Duration::days(30),
            is_revoked: false,
            created_at: Utc::now(),
        };

        // Create MFA setup for user
        let mfa_setup = MfaSetup {
            id: Uuid::new_v4(),
            user_id, // Reference to user
            secret: "TOTP_SECRET_KEY".to_string(),
            is_verified: true,
            created_at: Utc::now(),
        };

        // Verify relationships
        assert_eq!(session.user_id, user.id);
        assert_eq!(refresh_token.user_id, user.id);
        assert_eq!(refresh_token.session_id, session.id);
        assert_eq!(mfa_setup.user_id, user.id);
    }
}
