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
    pub count: Option<usize>,
    pub length: Option<usize>,
    pub use_separators: Option<bool>,
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
            count: Some(8),
            length: Some(10),
            use_separators: Some(true),
        }
    }
}
