use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub mfa_enabled: bool,
    pub mfa_secret: Option<String>,
    pub account_locked: bool,
    pub failed_login_attempts: i32,
    pub last_login: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Role {
    pub id: Uuid,
    pub name: String,
    pub permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserRole {
    pub user_id: Uuid,
    pub role_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginAttempt {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub ip_address: String,
    pub user_agent: String,
    pub success: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,         // Subject (user ID)
    pub exp: usize,          // Expiration time
    pub iat: usize,          // Issued at
    pub roles: Vec<String>,  // User roles
    pub permissions: Vec<String>, // User permissions
}
