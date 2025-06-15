use thiserror::Error;

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Internal server error: {message}")]
    Internal {
        message: String,
    },

    #[error("Database error: {0}")]
    Database(String),

    #[error("Authentication error: {0}")]
    Auth(String),
}

impl ApiError {
    pub fn new(message: String) -> Self {
        Self::Internal {
            message,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub mfa: MfaConfig,
}

#[derive(Debug, Clone)]
pub struct MfaConfig {
    pub recovery_code_count: Option<usize>,
    pub recovery_code_length: Option<usize>,
    pub recovery_code_use_separators: Option<bool>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            database_url: String::from("postgresql://localhost/simbld_auth"),
            mfa: MfaConfig::default(),
        }
    }
}

impl Default for MfaConfig {
    fn default() -> Self {
        Self {
            recovery_code_count: Some(8),
            recovery_code_length: Some(10),
            recovery_code_use_separators: Some(true),
        }
    }
}
