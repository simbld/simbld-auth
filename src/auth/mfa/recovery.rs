//! # Recovery Codes for Multi-Factor Authentication
//!
//! This module provides recovery codes for when users lose access to their MFA devices.
//! It generates, stores, and validates recovery codes.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, Config as Argon2Config, Variant,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::mfa::totp::MfaMethod;

/// Provider for recovery codes
#[derive(Debug, Clone)]
pub struct RecoveryCodeProvider {
    /// Number of recovery codes to generate
    code_count: usize,

    /// Length of each recovery code
    code_length: usize,

    /// Whether to separate code into chunks with hyphens
    use_separators: bool,

    /// Character set to use for codes
    character_set: RecoveryCodeCharset,

    /// Argon2 configuration for hashing codes
    argon2_config: Argon2<'static>,
}

/// Recovery code character set options
#[derive(Debug, Clone, Copy)]
pub enum RecoveryCodeCharset {
    /// Uppercase letters only (A-Z)
    AlphaUpper,

    /// Lowercase letters only (a-z)
    AlphaLower,

    /// Uppercase and lowercase letters (A-Z, a-z)
    AlphaMixed,

    /// Numbers only (0-9)
    Numeric,

    /// Alphanumeric (A-Z, a-z, 0-9)
    Alphanumeric,
}

/// Recovery code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCode {
    /// Unique identifier
    pub id: Uuid,

    /// Hashed value of the code
    pub code_hash: String,

    /// User ID the code belongs to
    pub user_id: Uuid,

    /// Whether the code has been used
    pub used: bool,

    /// When the code was created
    pub created_at: DateTime<Utc>,

    /// When the code was used (if applicable)
    pub used_at: Option<DateTime<Utc>>,
}

/// Settings for recovery codes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryCodeSettings {
    /// User ID
    pub user_id: Uuid,

    /// Whether recovery codes are enabled
    pub enabled: bool,

    /// Number of remaining codes
    pub remaining_codes: usize,

    /// When codes were last generated
    pub last_generated: DateTime<Utc>,
}

impl RecoveryCodeProvider {
    /// Create a new recovery code provider
    pub fn new(config: &AppConfig) -> Self {
        // Create Argon2 config
        let argon2_config = Argon2Config::default();

        Self {
            code_count: config.mfa.recovery_code_count.unwrap_or(8),
            code_length: config.mfa.recovery_code_length.unwrap_or(10),
            use_separators: config.mfa.recovery_code_use_separators.unwrap_or(true),
            character_set: RecoveryCodeCharset::Alphanumeric,
            argon2_config,
        }
    }

    /// Generate a set of recovery codes for a user
    pub async fn generate_codes(&self, user_id: Uuid) -> Result<Vec<String>, ApiError> {
        let mut codes = Vec::with_capacity(self.code_count);

        // Generate the specified number of codes
        for _ in 0..self.code_count {
            let code = self.generate_single_code();
            codes.push(code);
        }

        // Store hashed versions of the codes
        self.store_codes(user_id, &codes).await?;

        // Return the plain text codes to be shown to the user
        // This is the only time they will be available in plain text
        Ok(codes)
    }

    /// Generate a single recovery code
    fn generate_single_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let chunk_size = if self.use_separators {
            4
        } else {
            self.code_length
        };
        let num_chunks = (self.code_length + chunk_size - 1) / chunk_size;

        let mut code = String::new();

        for i in 0..num_chunks {
            // For the last chunk, calculate remaining characters
            let remaining = if i == num_chunks - 1 && self.code_length % chunk_size != 0 {
                self.code_length % chunk_size
            } else {
                chunk_size
            };

            // Generate chunk based on chosen character set
            let chunk = match self.character_set {
                RecoveryCodeCharset::AlphaUpper => (0..remaining)
                    .map(|_| {
                        let idx = rng.gen_range(0..26);
                        (b'A' + idx) as char
                    })
                    .collect::<String>(),
                RecoveryCodeCharset::AlphaLower => (0..remaining)
                    .map(|_| {
                        let idx = rng.gen_range(0..26);
                        (b'a' + idx) as char
                    })
                    .collect::<String>(),
                RecoveryCodeCharset::AlphaMixed => (0..remaining)
                    .map(|_| {
                        if rng.gen_bool(0.5) {
                            let idx = rng.gen_range(0..26);
                            (b'A' + idx) as char
                        } else {
                            let idx = rng.gen_range(0..26);
                            (b'a' + idx) as char
                        }
                    })
                    .collect::<String>(),
                RecoveryCodeCharset::Numeric => (0..remaining)
                    .map(|_| char::from_digit(rng.gen_range(0..10), 10).unwrap())
                    .collect::<String>(),
                RecoveryCodeCharset::Alphanumeric => {
                    (0..remaining).map(|_| rng.sample(Alphanumeric) as char).collect::<String>()
                },
            };

            code.push_str(&chunk);

            // Add separator if not the last chunk and separators are enabled
            if self.use_separators && i < num_chunks - 1 {
                code.push('-');
            }
        }

        code
    }

    /// Store hashed versions of the recovery codes
    async fn store_codes(&self, user_id: Uuid, codes: &[String]) -> Result<(), ApiError> {
        // In a real application, you would hash and store these codes in your database
        // For this example, we'll log that we're storing them but not actually do it
        log::debug!("Storing {} recovery codes for user {}", codes.len(), user_id);

        // Create hashed versions of codes
        let now = Utc::now();
        let mut hashed_codes = Vec::with_capacity(codes.len());

        for code in codes {
            let code_hash = self.hash_code(code)?;

            let recovery_code = RecoveryCode {
                id: Uuid::new_v4(),
                code_hash,
                user_id,
                used: false,
                created_at: now,
                used_at: None,
            };

            hashed_codes.push(recovery_code);
        }

        // In a real app, you would store these in your database
        // For this example, we'll just pretend they're stored

        // Update settings to reflect new codes
        let settings = RecoveryCodeSettings {
            user_id,
            enabled: true,
            remaining_codes: codes.len(),
            last_generated: now,
        };

        // In a real app, you would store these settings in your database

        Ok(())
    }

    /// Hash a recovery code
    fn hash_code(&self, code: &str) -> Result<String, ApiError> {
        let salt = rand::thread_rng().gen::<[u8; 32]>();

        argon2::hash_encoded(code.as_bytes(), &salt, &self.argon2_config)
            .map_err(|e| ApiError::new(500, format!("Failed to hash recovery code: {}", e)))
    }

    /// Verify a recovery code
    pub async fn verify_code(&self, user_id: Uuid, code: &str) -> Result<bool, ApiError> {
        // In a real application, you would:
        // 1. Retrieve all unused recovery codes for the user from your database
        // 2. Verify the provided code against each of the hashed codes
        // 3. If a match is found, mark that code as used

        // For this example, we'll just pretend to do that
        log::debug!("Verifying recovery code for user {}", user_id);

        // Simulate checking against stored codes
        let verified = false; // In a real app, this would be the result of verification

        // If verified, we would mark the code as used in the database
        if verified {
            // Update the code to mark it as used
            // Update remaining_codes count in settings
        }

        Ok(verified)
    }

    /// Get recovery code settings for a user
    pub async fn get_settings(
        &self,
        user_id: Uuid,
    ) -> Result<Option<RecoveryCodeSettings>, ApiError> {
        // In a real application, you would retrieve these settings from your database
        // For this example, we return None
        Ok(None)
    }

    /// Create or update recovery code settings for a user
    pub async fn update_settings(&self, settings: &RecoveryCodeSettings) -> Result<(), ApiError> {
        // In a real application, you would update these settings in your database
        // For this example, we just pretend they're updated
        Ok(())
    }
}

/// Recovery code verification result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryVerification {
    /// User ID
    pub user_id: Uuid,

    /// Whether verification succeeded
    pub success: bool,

    /// Verification timestamp
    pub timestamp: DateTime<Utc>,

    /// Recovery code ID that was used (if successful)
    pub code_id: Option<Uuid>,

    /// Number of remaining codes (if successful)
    pub remaining_codes: Option<usize>,
}

/// Implementation of MfaMethod for recovery codes
#[async_trait]
impl MfaMethod for RecoveryCodeProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        // For recovery codes, there's no initiation step like sending a code
        // We just return a placeholder since the user already has the codes
        Ok("recovery_verification".to_string())
    }

    async fn complete_verification(
        &self,
        user_id: Uuid,
        _verification_id: &str,
        code: &str,
    ) -> Result<bool, ApiError> {
        // Verify the recovery code
        self.verify_code(user_id, code).await
    }

    fn get_method_name(&self) -> &'static str {
        "recovery_code"
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    // Test the recovery code provider creation
    #[test]
    fn test_recovery_provider_creation() {
        let provider = RecoveryCodeProvider {
            code_count: 10,
            code_length: 8,
            use_separators: true,
            character_set: RecoveryCodeCharset::Alphanumeric,
            argon2_config: Argon2Config {
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::V0x13,
                mem_cost: 16 * 1024,
                time_cost: 3,
                lanes: 4,
                secret: &[],
                ad: &[],
                hash_length: 32,
            },
        };

        assert_eq!(provider.code_count, 10);
        assert_eq!(provider.code_length, 8);
        assert!(provider.use_separators);
    }

    // Test the method name
    #[test]
    fn test_method_name() {
        let provider = RecoveryCodeProvider {
            code_count: 10,
            code_length: 8,
            use_separators: true,
            character_set: RecoveryCodeCharset::Alphanumeric,
            argon2_config: Argon2Config {
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::V0x13,
                mem_cost: 16 * 1024,
                time_cost: 3,
                lanes: 4,
                secret: &[],
                ad: &[],
                hash_length: 32,
            },
        };

        assert_eq!(provider.get_method_name(), "recovery");
    }

    // Test single code generation
    #[test]
    fn test_generate_single_code() {
        let provider = RecoveryCodeProvider {
            code_count: 10,
            code_length: 8,
            use_separators: false,
            character_set: RecoveryCodeCharset::Alphanumeric,
            argon2_config: Argon2Config {
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::V0x13,
                mem_cost: 16 * 1024,
                time_cost: 3,
                lanes: 4,
                secret: &[],
                ad: &[],
                hash_length: 32,
            },
        };

        let code = provider.generate_single_code();

        // Check code length
        assert_eq!(code.len(), 8);

        // Check that the code contains only alphanumeric characters
        for c in code.chars() {
            assert!(c.is_alphanumeric(), "Character '{}' is not alphanumeric", c);
        }
    }

    // Test code generation with separators
    #[test]
    fn test_generate_code_with_separators() {
        let provider = RecoveryCodeProvider {
            code_count: 10,
            code_length: 8,
            use_separators: true,
            character_set: RecoveryCodeCharset::Alphanumeric,
            argon2_config: Argon2Config {
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::V0x13,
                mem_cost: 16 * 1024,
                time_cost: 3,
                lanes: 4,
                secret: &[],
                ad: &[],
                hash_length: 32,
            },
        };

        let code = provider.generate_single_code();

        // Check that the code has separators (length should be greater with separators)
        assert!(code.len() > 8, "Code should have separators");

        // Check that the code contains separators (dashes or spaces)
        assert!(code.contains('-') || code.contains(' '), "Code should contain separators");
    }

    // Test code hashing
    #[test]
    fn test_hash_code() {
        let provider = RecoveryCodeProvider {
            code_count: 10,
            code_length: 8,
            use_separators: true,
            character_set: RecoveryCodeCharset::Alphanumeric,
            argon2_config: Argon2Config {
                variant: argon2::Variant::Argon2id,
                version: argon2::Version::V0x13,
                mem_cost: 16 * 1024,
                time_cost: 3,
                lanes: 4,
                secret: &[],
                ad: &[],
                hash_length: 32,
            },
        };

        let code = "ABCD1234";
        let hash_result = provider.hash_code(code);

        // Hash function should succeed
        assert!(hash_result.is_ok());

        // Resulting hash should be a non-empty string
        let hash = hash_result.unwrap();
        assert!(!hash.is_empty());

        // Hash should be different from the original code
        assert_ne!(hash, code);
    }

    // Test recovery code settings
    #[test]
    fn test_recovery_code_settings() {
        let user_id = Uuid::new_v4();
        let settings = RecoveryCodeSettings {
            user_id,
            enabled: true,
            remaining_codes: 8,
            last_generated: Utc::now(),
        };

        assert_eq!(settings.user_id, user_id);
        assert!(settings.enabled);
        assert_eq!(settings.remaining_codes, 8);
    }
}
