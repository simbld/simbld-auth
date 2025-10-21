//! Configuration management for simbld_auth
//!
//! Handles loading and validation of app configuration from environment variables
//! with sensible defaults and comprehensive error handling.

use crate::types::{ApiError, AppConfig, MfaConfig, ServerConfig};
use crate::utils::response_handler::ResponseHandler;
use actix_web::{HttpRequest, HttpResponse};
use simbld_http::responses::ResponsesTypes;
use simbld_http::ResponsesServerCodes;
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::time::Duration;

///  Get a PostgreSQL connection pool
pub async fn get_pg_pool(config: &str) -> Result<sqlx::PgPool, sqlx::Error> {
    PgPoolOptions::new().max_connections(5).connect(config).await
}

/// Load complete app configuration
pub fn load_config() -> Result<AppConfig, ApiError> {
    let config = AppConfig {
        database_url: load_database_url(),
        server: load_server_config(),
        mfa: load_mfa_config(),
        jwt_secret: load_jwt_secret()?,
        cors_origins: load_cors_origins(),
        rate_limit: load_rate_limit(),
        log_level: load_log_level(),
    };

    validate_config(&config)?;
    Ok(config)
}

/// Load database configuration
fn load_database_url() -> String {
    env::var("DATABASE_URL").unwrap_or_else(|_| "postgresql://localhost/simbld_auth".to_string())
}

/// Load server configuration
fn load_server_config() -> ServerConfig {
    ServerConfig {
        host: env::var("SERVER_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
        port: env::var("SERVER_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(8080),
        workers: env::var("SERVER_WORKERS")
            .ok()
            .and_then(|w| w.parse().ok())
            .unwrap_or(num_cpus::get()),
        keep_alive: Duration::from_secs(
            env::var("SERVER_KEEP_ALIVE").ok().and_then(|ka| ka.parse().ok()).unwrap_or(30),
        ),
    }
}

/// Load MFA configuration
fn load_mfa_config() -> MfaConfig {
    MfaConfig {
        recovery_code_count: env::var("MFA_RECOVERY_CODE_COUNT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(8),
        recovery_code_length: env::var("MFA_RECOVERY_CODE_LENGTH")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10),
        use_separators: env::var("MFA_USE_SEPARATORS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(true),
        totp_window: env::var("MFA_TOTP_WINDOW").ok().and_then(|s| s.parse().ok()).unwrap_or(1),
        max_backup_codes: env::var("MFA_MAX_BACKUP_CODES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10),
    }
}

/// Load JWT secret (required)
fn load_jwt_secret() -> Result<String, ApiError> {
    env::var("JWT_SECRET").map_err(|_| ApiError::Config {
        message: "JWT_SECRET environment variable is required".to_string(),
    })
}

/// Load CORS origins
fn load_cors_origins() -> Vec<String> {
    env::var("CORS_ORIGINS")
        .unwrap_or_else(|_| "*".to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .collect()
}

/// Load rate limiting configuration
fn load_rate_limit() -> usize {
    env::var("RATE_LIMIT").ok().and_then(|s| s.parse().ok()).unwrap_or(100)
}

/// Load log level
fn load_log_level() -> String {
    env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string())
}

/// Validate configuration values
fn validate_config(config: &AppConfig) -> Result<(), ApiError> {
    // Validate database URL
    if config.database_url.is_empty() {
        return Err(ApiError::Config {
            message: "Database URL can't be empty".to_string(),
        });
    }

    // Validate JWT secret
    if config.jwt_secret.len() < 32 {
        return Err(ApiError::Config {
            message: "JWT secret must be at least 32 characters long".to_string(),
        });
    }

    // Validate server configuration
    if config.server.port == 0 || config.server.port > 65535 {
        return Err(ApiError::Config {
            message: "Server port must be between 1 and 65,535".to_string(),
        });
    }

    // Validate MFA configuration
    if config.mfa.recovery_code_count == 0 || config.mfa.recovery_code_count > 20 {
        return Err(ApiError::Config {
            message: "MFA recovery code count must be between 1 and 20".to_string(),
        });
    }

    if config.mfa.recovery_code_length < 8 || config.mfa.recovery_code_length > 32 {
        return Err(ApiError::Config {
            message: "MFA recovery code length must be between 8 and 32".to_string(),
        });
    }

    println!("✅ Configuration validated successfully");
    Ok(())
}

/// Get bind address from configuration
pub fn get_bind_address(config: &AppConfig) -> String {
    format!("{}:{}", config.server.host, config.server.port)
}

pub fn create_config_error_response(
    req: &HttpRequest,
    error_message: &str,
    duration: Duration,
) -> HttpResponse {
    ResponseHandler::create_hybrid_response(
        req,
        ResponsesTypes::ServerError(ResponsesServerCodes::InternalServerError),
        Some("Configuration Error"),
        Some(error_message),
        duration,
    )
}

pub fn load_config_with_error_handling(
    req: &HttpRequest,
    duration: Duration,
) -> Result<AppConfig, HttpResponse> {
    match load_config() {
        Ok(config) => Ok(config),
        Err(api_error) => {
            let error_message = format!("Failed to load configuration: {}", api_error);
            Err(create_config_error_response(req, &error_message, duration))
        },
    }
}
pub fn validate_config_on_startup() -> Result<AppConfig, String> {
    match load_config() {
        Ok(config) => {
            println!("🔧 Configuration loaded successfully");
            println!("   Database: {}", mask_sensitive_url(&config.database_url));
            println!("   Server: {}:{}", config.server.host, config.server.port);
            println!("   Workers: {}", config.server.workers);
            println!("   CORS Origins: {:?}", config.cors_origins);
            println!("   Rate Limit: {}/min", config.rate_limit);
            println!("   Log Level: {}", config.log_level);
            Ok(config)
        },
        Err(api_error) => {
            eprintln!("❌ Configuration error: {}", api_error);
            Err(format!("Configuration validation failed: {}", api_error))
        },
    }
}

fn mask_sensitive_url(url: &str) -> String {
    if let Some(at_pos) = url.find('@') {
        let (before_at, after_at) = url.split_at(at_pos);
        if let Some(protocol_end) = before_at.find("://") {
            let protocol = &before_at[..protocol_end + 3];
            format!("{}***@{}", protocol, after_at)
        } else {
            "***".to_string()
        }
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_load_config_with_defaults() {
        // Set required environment variables
        env::set_var("JWT_SECRET", "test_secret_key_that_is_long_enough_32_chars");

        let config = load_config().expect("Config should load with defaults");

        assert!(!config.database_url.is_empty());
        assert_eq!(config.server.host, "127.0.0.1");
        assert_eq!(config.server.port, 8080);
        assert_eq!(config.mfa.recovery_code_count, 8);
    }

    #[test]
    fn test_validate_config_invalid_jwt_secret() {
        let config = AppConfig {
            database_url: "postgresql://localhost/test".to_string(),
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                workers: 1,
                keep_alive: Duration::from_secs(30),
            },
            mfa: MfaConfig {
                recovery_code_count: 8,
                recovery_code_length: 10,
                use_separators: true,
                totp_window: 1,
                max_backup_codes: 10,
            },
            jwt_secret: "too_short".to_string(), // Too short
            cors_origins: vec!["*".to_string()],
            rate_limit: 100,
            log_level: "info".to_string(),
        };

        let result = validate_config(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_mask_sensitive_url() {
        let url = "postgresql://username:password@localhost:5432/database";
        let masked = mask_sensitive_url(url);
        assert_eq!(masked, "postgresql://***@localhost:5432/database");
    }

    #[test]
    fn test_mask_sensitive_url_no_auth() {
        let url = "postgresql://localhost:5432/database";
        let masked = mask_sensitive_url(url);
        assert_eq!(masked, "postgresql://localhost:5432/database");
    }
}
