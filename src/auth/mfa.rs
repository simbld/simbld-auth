use thiserror::Error;
use totp_rs::{Algorithm, TOTP};

#[derive(Error, Debug)]
pub enum MfaError {
    #[error("Failed to generate TOTP secret: {0}")]
    SecretGenerationError(String),
    #[error("Failed to validate TOTP code: {0}")]
    ValidationError(String),
    #[error("Invalid TOTP code")]
    InvalidCode,
}

pub struct MfaService;

impl MfaService {
    pub fn generate_secret() -> Result<String, MfaError> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Vec::from_hex("4f6e636520436c61757365").unwrap(),
        )
            .map_err(|e| MfaError::SecretGenerationError(e.to_string()))?;

        Ok(base32::encode(base32::Alphabet::RFC4648 { padding: true }, &totp.secret))
    }

    pub fn generate_provisioning_uri(secret: &str, username: &str, issuer: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}",
            issuer, username, secret, issuer
        )
    }

    pub fn verify_code(secret: &str, code: &str) -> Result<bool, MfaError> {
        let secret_bytes = base32::decode(base32::Alphabet::RFC4648 { padding: true }, secret)
            .ok_or_else(|| MfaError::ValidationError("Invalid secret format".into()))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
        )
            .map_err(|e| MfaError::ValidationError(e.to_string()))?;

        Ok(totp.check_current(code))
    }
}
