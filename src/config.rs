use crate::types::{ApiError, AppConfig, MfaConfig};
use std::env;

pub fn load_config() -> Result<AppConfig, ApiError> {
    // 1. Load the database URL
    let database_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/simbld_auth".to_string());

    // 2. Load the MFA config
    let mfa_config = load_mfa_config();

    // 3. Create the final config
    let config = AppConfig {
        database_url,
        mfa: mfa_config,
    };

    // 4. Validate the config
    validate_config(&config)?;

    Ok(config)
}

fn load_mfa_config() -> MfaConfig {
    MfaConfig {
        count: env::var("MFA_RECOVERY_CODE_COUNT").ok().and_then(|s| s.parse().ok()).or(Some(8)),

        length: env::var("MFA_RECOVERY_CODE_LENGTH").ok().and_then(|s| s.parse().ok()).or(Some(10)),

        use_separators: env::var("MFA_USE_SEPARATORS")
            .ok()
            .and_then(|s| s.parse().ok())
            .or(Some(true)),
    }
}

fn validate_config(config: &AppConfig) -> Result<(), ApiError> {
    // Check that the DB URL is not empty
    if config.database_url.is_empty() {
        return Err(ApiError::Internal {
            message: "Database URL can't be empty".to_string(),
        });
    }

    Ok(())
}
