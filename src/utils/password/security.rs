use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;
use zxcvbn::zxcvbn;

#[derive(Error, Debug)]
pub enum PasswordError {
    #[error("Failed to hash password: {0}")]
    HashingError(String),
    #[error("Failed to verify password: {0}")]
    VerificationError(String),
    #[error("Password too weak: score {0}/4, feedback: {1}")]
    TooWeak(u8, String),
}

pub struct PasswordService;

impl PasswordService {
    pub fn hash_password(password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| PasswordError::HashingError(e.to_string()))
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|e| PasswordError::VerificationError(e.to_string()))?;

        let argon2 = Argon2::default();
        Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    pub fn validate_password_strength(password: &str, user_inputs: &[&str]) -> Result<(), PasswordError> {
        let estimate = zxcvbn(password, user_inputs)
            .map_err(|e| PasswordError::VerificationError(e.to_string()))?;

        if estimate.score() < 3 {
            let feedback = estimate.feedback().unwrap_or_default();
            let warning = feedback.warning().unwrap_or_default();
            let suggestions = feedback.suggestions().join(", ");
            let feedback_str = format!("{} Suggestions: {}", warning, suggestions);

            return Err(PasswordError::TooWeak(estimate.score(), feedback_str));
        }

        Ok(())
    }
}
