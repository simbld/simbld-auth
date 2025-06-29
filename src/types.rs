//! Type definitions for simbld_auth
//!
//! Contains all shared data structures, error types, and configuration models
//! used throughout the app.

use serde::{Deserialize, Serialize};
use simbld_http::responses::{ResponsesClientCodes, ResponsesServerCodes};
use std::time::Duration;
use thiserror::Error;

/// Application-wide error types
#[derive(Debug, Error, Clone)]
pub enum ApiError {
    #[error("Internal server error: {message}")]
    Internal {
        message: String,
    },

    #[error("Database error: {0}")]
    Database(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {message}")]
    Config {
        message: String,
    },

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Password error: {0}")]
    Password(String),

    #[error("User not found")]
    UserNotFound,

    #[error("Email already exists")]
    EmailAlreadyExists,

    #[error("Invalid credentials")]
    InvalidCredentials,
}

impl ApiError {
    pub fn new(message: String) -> Self {
        Self::Internal {
            message,
        }
    }

    /// Convert to appropriate HTTP response
    pub fn to_response(&self) -> simbld_http::responses::CustomResponse {
        match self {
            ApiError::Internal {
                ..
            } => ResponsesServerCodes::InternalServerError.into_response(),
            ApiError::Database(_) => ResponsesServerCodes::InternalServerError.into_response(),
            ApiError::Config {
                ..
            } => ResponsesServerCodes::InternalServerError.into_response(),

            ApiError::Auth(_) => ResponsesClientCodes::Unauthorized.into_response(),
            ApiError::InvalidCredentials => ResponsesClientCodes::Unauthorized.into_response(),

            ApiError::Validation(_) => ResponsesClientCodes::BadRequest.into_response(),
            ApiError::Password(_) => ResponsesClientCodes::BadRequest.into_response(),

            ApiError::UserNotFound => ResponsesClientCodes::NotFound.into_response(),
            ApiError::EmailAlreadyExists => ResponsesClientCodes::Conflict.into_response(),
        }
    }
}

/// Complete app configuration
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub server: ServerConfig,
    pub mfa: MfaConfig,
    pub jwt_secret: String,
    pub cors_origins: Vec<String>,
    pub rate_limit: usize,
    pub log_level: String,
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
}

/// User registration data
#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: String,
    pub username: String,
    pub firstname: String,
    pub lastname: String,
}

/// User login credentials
#[derive(Debug, Clone, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
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
            jwt_secret: "change_me_in_production".to_string(),
            cors_origins: vec!["*".to_string()],
            rate_limit: 100,
            log_level: "info".to_string(),
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
        }
    }
}
