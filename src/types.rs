//! Type definitions for simbld_auth
//!
//! Contains all shared data structures, error types, and configuration models
//! used throughout the app.

use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::Duration;
use thiserror::Error;

/// Application startup errors
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("Configuration error: {0}")]
    Config(String),
    #[error("Database connection error: {0}")]
    Database(String),
    #[error("Server binding error: {0}")]
    ServerBind(String),
}

/// Runtime API errors
#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    Internal {
        message: String,
    },
    Database(String),
    Auth(String),
    Config {
        message: String,
    },
    Validation(String),
    Password(String),
    UserNotFound,
    EmailAlreadyExists,
    InvalidCredentials,
    Mfa(String),
    Jwt(String),
    RateLimit,
    PermissionDenied,
    AccountLocked,
    SessionExpired,
    BadRequest(String),
    InternalServerError(String),
}

impl ApiError {
    pub fn new(status: u16, message: String) -> Self {
        match status {
            400 => ApiError::BadRequest(message),
            401 => ApiError::Auth(message),
            403 => ApiError::PermissionDenied,
            404 => ApiError::UserNotFound,
            429 => ApiError::RateLimit,
            _ => ApiError::Internal {
                message,
            },
        }
    }
}

/// Complete app configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub server: ServerConfig,
    pub mfa: MfaConfig,
    pub webauthn: WebauthnConfig,
    pub jwt_secret: String,
    pub cors_origins: Vec<String>,
    pub rate_limit: usize,
    pub log_level: String,
    pub base_url: String,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
    pub facebook_client_id: Option<String>,
    pub facebook_client_secret: Option<String>,
    pub microsoft_client_id: Option<String>,
    pub microsoft_client_secret: Option<String>,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub keep_alive: Duration,
}

/// Multi-Factor Authentication configuration
#[derive(Debug, Clone)]
pub struct MfaConfig {
    pub recovery_code_count: usize,
    pub recovery_code_length: usize,
    pub use_separators: bool,
    pub totp_window: u32,
    pub max_backup_codes: usize,
    pub email_code_expiration_seconds: u64,
    pub email_code_length: usize,
    pub email_subject: String,
    pub sender_email: String,
    pub sms_code_expiration_seconds: u64,
    pub sms_code_length: usize,
    pub push_expiration_seconds: u64,
}

/// WebAuthn configuration
#[derive(Debug, Clone)]
pub struct WebauthnConfig {
    pub rp_id: Option<String>,
    pub rp_name: Option<String>,
    pub rp_origin: Option<String>,
}

impl Default for WebauthnConfig {
    fn default() -> Self {
        Self {
            rp_id: None,
            rp_name: None,
            rp_origin: None,
        }
    }
}

/// User registration data
#[derive(Debug, Clone, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub username: String,
    pub firstname: String,
    pub lastname: String,
}

/// Authentication response
#[derive(Debug, Clone, Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub user_id: String,
}

/// User profile data
#[derive(Debug, Clone, Serialize)]
pub struct UserProfile {
    pub id: String,
    pub email: String,
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database_url: "postgresql://localhost/simbld_auth".to_string(),
            server: ServerConfig::default(),
            mfa: MfaConfig::default(),
            webauthn: WebauthnConfig::default(),
            jwt_secret: "change_me_in_production".to_string(),
            cors_origins: vec!["*".to_string()],
            rate_limit: 100,
            log_level: "info".to_string(),
            base_url: "http://localhost:8080".to_string(),
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            facebook_client_id: None,
            facebook_client_secret: None,
            microsoft_client_id: None,
            microsoft_client_secret: None,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8080,
            workers: num_cpus::get(),
            keep_alive: Duration::from_secs(30),
        }
    }
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            recovery_code_count: 8,
            recovery_code_length: 10,
            use_separators: true,
            totp_window: 1,
            max_backup_codes: 10,
            email_code_expiration_seconds: 600,
            email_code_length: 6,
            email_subject: "Your verification code".to_string(),
            sender_email: "noreply@example.com".to_string(),
            sms_code_expiration_seconds: 600,
            sms_code_length: 6,
            push_expiration_seconds: 300,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Internal {
                message,
            } => write!(f, "Internal error: {}", message),
            ApiError::Database(err) => write!(f, "Database error: {}", err),
            ApiError::Auth(msg) => write!(f, "Authentication error: {}", msg),
            ApiError::Config {
                message,
            } => write!(f, "Configuration error: {}", message),
            ApiError::Validation(err) => write!(f, "Validation error: {}", err),
            ApiError::Password(msg) => write!(f, "Password error: {}", msg),
            ApiError::UserNotFound => write!(f, "User not found"),
            ApiError::EmailAlreadyExists => write!(f, "Email already exists"),
            ApiError::InvalidCredentials => write!(f, "Invalid credentials"),
            ApiError::Mfa(err) => write!(f, "MFA error: {}", err),
            ApiError::Jwt(err) => write!(f, "JWT error: {}", err),
            ApiError::RateLimit => write!(f, "Rate limit exceeded"),
            ApiError::PermissionDenied => write!(f, "Permission denied"),
            ApiError::AccountLocked => write!(f, "Account locked"),
            ApiError::SessionExpired => write!(f, "Session expired"),
            ApiError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            ApiError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
        }
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        match self {
            ApiError::Internal {
                ..
            } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Auth(_) => StatusCode::UNAUTHORIZED,
            ApiError::Config {
                ..
            } => StatusCode::INTERNAL_SERVER_ERROR,
            ApiError::Validation(_) => StatusCode::BAD_REQUEST,
            ApiError::Password(_) => StatusCode::BAD_REQUEST,
            ApiError::UserNotFound => StatusCode::NOT_FOUND,
            ApiError::EmailAlreadyExists => StatusCode::CONFLICT,
            ApiError::InvalidCredentials => StatusCode::UNAUTHORIZED,
            ApiError::Mfa(_) => StatusCode::BAD_REQUEST,
            ApiError::Jwt(_) => StatusCode::UNAUTHORIZED,
            ApiError::RateLimit => StatusCode::TOO_MANY_REQUESTS,
            ApiError::PermissionDenied => StatusCode::FORBIDDEN,
            ApiError::AccountLocked => StatusCode::FORBIDDEN,
            ApiError::SessionExpired => StatusCode::UNAUTHORIZED,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::InternalServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(serde_json::json!({
            "status": self.status_code().as_u16(),
            "message": self.to_string(),
        }))
    }
}
