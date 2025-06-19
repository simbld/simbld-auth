//! Password security and cryptography utilities.
//!
//! Provides functions for secure password handling:
//! - Password hashing with Argon2id
//! - Password verification
//! - Password strength estimation
//! - Password breach checking (HIBP integration)

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use thiserror::Error;
use zxcvbn::zxcvbn;

/// Number of iterations for Argon2id
const ARGON2_TIME_COST: u32 = 3;
/// Memory cost parameter (in KB)
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
/// Parallelism parameter
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Failed to hash password: {0}")]
    HashingError(String),

    #[error("Failed to verify password: {0}")]
    VerificationError(String),

    #[error("Password too weak (score: {0}/4)")]
    TooWeak(u8),

    #[error("Password has been previously compromised")]
    Compromised,
}

/// Password strength level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PasswordStrength {
    VeryWeak = 0,
    Weak = 1,
    Medium = 2,
    Strong = 3,
    VeryStrong = 4,
}

impl From<u8> for PasswordStrength {
    fn from(score: u8) -> Self {
        match score {
            0 => PasswordStrength::VeryWeak,
            1 => PasswordStrength::Weak,
            2 => PasswordStrength::Medium,
            3 => PasswordStrength::Strong,
            _ => PasswordStrength::VeryStrong,
        }
    }
}

/// Service for password-related security operations
pub struct PasswordService;

impl PasswordService {
    /// Hash a password using Argon2id with secure parameters
    pub fn hash_password(password: &str) -> Result<String, PasswordError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(ARGON2_MEMORY_COST, ARGON2_TIME_COST, ARGON2_PARALLELISM, None)
                .unwrap(),
        );

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|e| PasswordError::HashingError(e.to_string()))
    }

    /// Verify a password against a previously generated hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| PasswordError::VerificationError(e.to_string()))?;

        // Argon2id verification
        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    /// Estimate the strength of a password using zxcvbn
    pub fn estimate_strength(password: &str, user_inputs: &[&str]) -> PasswordStrength {
        let result = zxcvbn(password, user_inputs).unwrap_or_else(|_| {
            // Fallback for very long passwords (which zxcvbn might reject)
            // Long passwords are generally strong
            zxcvbn::feedback::Feedback {
                score: 4,
                ..Default::default()
            }
            .into()
        });

        PasswordStrength::from(result.score())
    }

    /// Check if a password meets minimum strength requirements
    pub fn meets_strength_requirements(
        password: &str,
        user_inputs: &[&str],
        minimum_strength: PasswordStrength,
    ) -> Result<(), PasswordError> {
        let strength = Self::estimate_strength(password, user_inputs);
        if strength >= minimum_strength {
            Ok(())
        } else {
            Err(PasswordError::TooWeak(strength as u8))
        }
    }

    /// Check if a password has been compromised in known data breaches
    ///
    /// Uses the k-anonymity model to check against the HaveIBeenPwned API
    #[cfg(feature = "hibp-check")]
    pub async fn check_password_breach(password: &str) -> Result<bool, PasswordError> {
        use reqwest::Client;
        use sha1::{Digest, Sha1};

        // Generate SHA-1 hash of the password
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let hash = hasher.finalize();

        // Convert to uppercase hex string
        let hash_hex = format!("{:X}", hash);
        let (prefix, suffix) = hash_hex.split_at(5);

        // Query the HIBP API
        let client = Client::new();
        let url = format!("https://api.pwnedpasswords.com/range/{}", prefix);

        match client.get(&url).send().await {
            Ok(response) => {
                if let Ok(body) = response.text().await {
                    // Check if our hash suffix is in the response
                    for line in body.lines() {
                        if let Some(idx) = line.find(':') {
                            let hash_suffix = &line[0..idx];
                            if hash_suffix.eq_ignore_ascii_case(suffix) {
                                return Ok(true); // Password has been compromised
                            }
                        }
                    }
                    Ok(false) // Not found in breached passwords
                } else {
                    Err(PasswordError::VerificationError(
                        "Failed to parse API response".to_string(),
                    ))
                }
            },
            Err(e) => Err(PasswordError::VerificationError(format!("API request failed: {}", e))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "secure_password_123!";

        let hash = PasswordService::hash_password(password).expect("Failed to hash password");

        // Verify correct password
        let is_valid =
            PasswordService::verify_password(password, &hash).expect("Failed to verify password");
        assert!(is_valid, "Password verification should succeed");

        // Verify incorrect password
        let is_valid = PasswordService::verify_password("wrong_password", &hash)
            .expect("Failed to verify password");
        assert!(!is_valid, "Wrong password verification should fail");
    }

    #[test]
    fn test_password_strength() {
        // Very weak password
        let strength = PasswordService::estimate_strength("password", &[]);
        assert!(matches!(strength, PasswordStrength::VeryWeak | PasswordStrength::Weak));

        // Medium password
        let strength = PasswordService::estimate_strength("Tr0ub4dour", &[]);
        assert!(matches!(strength, PasswordStrength::Medium));

        // Strong password
        let strength = PasswordService::estimate_strength("CorrectHorseBatteryStaple!42", &[]);
        assert!(matches!(strength, PasswordStrength::Strong | PasswordStrength::VeryStrong));
    }

    #[test]
    fn test_strength_requirements() {
        let weak_pass = "password123";
        let result =
            PasswordService::meets_strength_requirements(weak_pass, &[], PasswordStrength::Strong);
        assert!(result.is_err());

        let strong_pass = "xkT5$p!7ZQm@2LnP";
        let result = PasswordService::meets_strength_requirements(
            strong_pass,
            &[],
            PasswordStrength::Medium,
        );
        assert!(result.is_ok());
    }
}
