//! Password security and cryptography utilities
//!
//! Provides functions for secure password handling:
//! - Password hashing with Argon2id
//! - Password verification  
//! - Password strength estimation
//! - Password breach checking integration ready

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// 🔒 Secure password wrapper with automatic redaction
#[derive(Clone, Deserialize)]
pub struct SecurePassword {
    #[serde(skip_serializing)]
    password: String,
}

impl SecurePassword {
    /// Create a new secure password
    pub fn new(password: String) -> Self {
        Self {
            password,
        }
    }

    /// Expose the secret for hashing/verification
    pub fn expose_secret(&self) -> &str {
        &self.password
    }
}

/// 🔒 Mask in JSON serialization
impl Serialize for SecurePassword {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

// 🔒 Mask in Println.("{:}", password)
impl fmt::Debug for SecurePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecurePassword").field("password", &"[REDACTED]").finish()
    }
}

// 🔒 Mask in Println.("{}", password)
impl fmt::Display for SecurePassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

/// Password security configuration
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_MEMORY_COST: u32 = 65536; // 64 MB
const ARGON2_PARALLELISM: u32 = 4;

/// Password-related errors
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
    #[error("Password doesn't meet complexity requirements")]
    InsufficientComplexity,
}

/// Password strength levels
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
    /// Hash a SecurePassword using Argon2id
    pub fn hash_secure_password(password: &SecurePassword) -> Result<String, PasswordError> {
        Self::hash_password(password.expose_secret())
    }

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

    /// Verify a SecurePassword against hash
    pub fn verify_secure_password(
        password: &SecurePassword,
        hash: &str,
    ) -> Result<bool, PasswordError> {
        Self::verify_password(password.expose_secret(), hash)
    }

    /// Verify a password against hash
    pub fn verify_password(password: &str, hash: &str) -> Result<bool, PasswordError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| PasswordError::VerificationError(e.to_string()))?;

        Ok(Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }

    /// Validate password strength
    pub fn validate_password_strength(password: &str) -> Result<(), PasswordError> {
        if password.len() < 12 {
            return Err(PasswordError::TooWeak(0));
        }

        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));

        if !(has_lowercase && has_uppercase && has_digit && has_special) {
            return Err(PasswordError::InsufficientComplexity);
        }

        Ok(())
    }

    /// Estimate password strength (0-4 scale)
    pub fn estimate_strength(password: &str, user_inputs: &[&str]) -> PasswordStrength {
        let mut score = 0u8;

        // Length check
        if password.len() >= 8 {
            score += 1;
        }
        if password.len() >= 12 {
            score += 1;
        }

        // Character variety
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());

        if has_lower && has_upper {
            score += 1;
        }
        if has_digit && has_special {
            score += 1;
        }

        // Penalize common patterns
        if user_inputs.iter().any(|&input| password.to_lowercase().contains(&input.to_lowercase()))
        {
            score = score.saturating_sub(1);
        }

        PasswordStrength::from(score)
    }

    /// Check if password meets minimum strength requirements
    pub fn meets_strength_requirements(
        password: &str,
        user_inputs: &[&str],
        min_strength: PasswordStrength,
    ) -> Result<(), PasswordError> {
        let strength = Self::estimate_strength(password, user_inputs);

        if strength < min_strength {
            return Err(PasswordError::TooWeak(strength as u8));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_hash_and_verify() {
        let password = "secure_password_123!";

        let hash = PasswordService::hash_password(password).expect("Failed to hash password");

        // Verify the correct password
        let is_valid =
            PasswordService::verify_password(password, &hash).expect("Failed to verify password");
        assert!(is_valid, "Password verification should succeed");

        // Verify incorrect password
        let is_valid = PasswordService::verify_password("wrong_password", &hash)
            .expect("Failed to verify password");
        assert!(!is_valid, "Wrong password verification should fail");
    }

    #[test]
    fn test_secure_password_wrapper() {
        let password = SecurePassword::new("test_password".to_string());
        let hash = PasswordService::hash_secure_password(&password)
            .expect("Failed to hash secure password");

        let is_valid = PasswordService::verify_secure_password(&password, &hash)
            .expect("Failed to verify a secure password");
        assert!(is_valid, "Secure password verification should succeed");
    }

    #[test]
    fn test_password_strength() {
        // Weak password
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

    #[test]
    fn test_password_validation() {
        // Too short
        let result = PasswordService::validate_password_strength("short");
        assert!(matches!(result, Err(PasswordError::TooWeak(_))));

        // Missing complexity
        let result = PasswordService::validate_password_strength("only lowercase123");
        assert!(matches!(result, Err(PasswordError::InsufficientComplexity)));

        // Valid password
        let result = PasswordService::validate_password_strength("ValidPassword123!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_password_serialization() {
        let password = SecurePassword::new("secret123".to_string());
        let serialized = serde_json::to_string(&password).unwrap();
        assert_eq!(serialized, r#""[REDACTED]""#);
    }

    #[test]
    fn test_no_password_leaks() {
        let password = SecurePassword::new("supersecret123".to_string());

        // Test Debug
        let debug_str = format!("{:?}", password);
        assert!(!debug_str.contains("supersecret123"));
        assert!(debug_str.contains("[REDACTED]"));

        // Test Display
        let display_str = format!("{}", password);
        assert_eq!(display_str, "[REDACTED]");

        // Test Serialize
        let json = serde_json::to_string(&password).unwrap();
        assert_eq!(json, "\"[REDACTED]\"");
    }
}
