//! Backup codes for account recovery when MFA devices are lost or unavailable.
//!
//! These single-use codes allow users to authenticate when they cannot access their
//! primary MFA method (TOTP app, WebAuthn device, etc).

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use thiserror::Error;
use uuid::Uuid;

/// Default length of backup codes
const BACKUP_CODE_LENGTH: usize = 10;

/// Default number of backup codes to generate
const DEFAULT_BACKUP_CODE_COUNT: usize = 10;

#[derive(Debug, Error)]
pub enum BackupCodeError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("No backup codes available")]
    NoCodesAvailable,

    #[error("Invalid backup code")]
    InvalidCode,

    #[error("Hashing error: {0}")]
    HashingError(String),
}

/// Backup codes database record
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct BackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub code_index: i32,
    pub batch_id: Uuid,
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

/// Service for managing backup codes
pub struct BackupCodeService;

impl BackupCodeService {
    /// Generate a set of backup codes for a user
    pub async fn generate_codes(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        count: Option<usize>,
        invalidate_old: bool,
    ) -> Result<Vec<String>, BackupCodeError> {
        let count = count.unwrap_or(DEFAULT_BACKUP_CODE_COUNT);
        let codes = Self::create_random_codes(count);
        let batch_id = Uuid::new_v4();

        // Start a transaction
        let mut tx =
            pool.begin().await.map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        // Optionally invalidate old codes
        if invalidate_old {
            sqlx::query!(
                "UPDATE backup_codes
                 SET used = true, used_at = $1
                 WHERE user_id = $2 AND used = false",
                Utc::now(),
                user_id
            )
            .execute(&mut tx)
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;
        }

        let now = Utc::now();

        // Insert new codes
        for (i, code) in codes.iter().enumerate() {
            let code_hash = hash_code(code)?;

            sqlx::query!(
                "INSERT INTO backup_codes
                 (id, user_id, code_hash, code_index, batch_id, used, created_at)
                 VALUES ($1, $2, $3, $4, $5, false, $6)",
                Uuid::new_v4(),
                user_id,
                code_hash,
                i as i32,
                batch_id,
                now
            )
            .execute(&mut tx)
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;
        }

        // Commit the transaction
        tx.commit().await.map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        Ok(codes)
    }

    /// Verify a backup code during authentication
    pub async fn verify_code(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, BackupCodeError> {
        let rows = sqlx::query!(
            "SELECT id, code_hash FROM backup_codes
         WHERE user_id = $1 AND used = false",
            user_id
        )
        .fetch_all(pool)
        .await
        .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        // Check each code
        for row in rows {
            if verify_code_hash(code, &row.code_hash)? {
                // Mark code as used
                sqlx::query!(
                    "UPDATE backup_codes SET used = true, used_at = $1 WHERE id = $2",
                    Utc::now(),
                    row.id
                )
                .execute(pool)
                .await
                .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Get the number of remaining backup codes for a user
    pub async fn get_remaining_code_count(
        pool: &Pool<Postgres>,
        user_id: Uuid,
    ) -> Result<usize, BackupCodeError> {
        let row = sqlx::query!(
            "SELECT COUNT(*) as count FROM backup_codes
             WHERE user_id = $1 AND used = false",
            user_id
        )
        .fetch_one(pool)
        .await
        .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        Ok(row.count.unwrap_or(0) as usize)
    }

    /// Clear all backup codes for a user
    pub async fn clear_codes(pool: &Pool<Postgres>, user_id: Uuid) -> Result<(), BackupCodeError> {
        sqlx::query!("DELETE FROM backup_codes WHERE user_id = $1", user_id)
            .execute(pool)
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Generate random backup codes
    fn create_random_codes(count: usize) -> Vec<String> {
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = rand::rng();

        (0..count)
            .map(|_| {
                (0..BACKUP_CODE_LENGTH)
                    .map(|_| {
                        let idx = rng.random_range(0..CHARSET.len());
                        CHARSET[idx] as char
                    })
                    .collect()
            })
            .collect()
    }
}

// Helper function to hash a code using Argon2
fn hash_code(code: &str) -> Result<String, BackupCodeError> {
    let salt = SaltString::generate(&mut OsRng);

    // Configure Argon2 with default parameters
    let argon2 = Argon2::default();

    // Hash the password
    argon2
        .hash_password(code.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| BackupCodeError::HashingError(e.to_string()))
}

// Helper function to verify a code against its hash
fn verify_code_hash(code: &str, hash: &str) -> Result<bool, BackupCodeError> {
    let parsed_hash =
        PasswordHash::new(hash).map_err(|e| BackupCodeError::HashingError(e.to_string()))?;

    // Verify the password against the hash
    Ok(Argon2::default().verify_password(code.as_bytes(), &parsed_hash).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_random_codes() {
        let codes = BackupCodeService::create_random_codes(5);

        assert_eq!(codes.len(), 5);

        for code in codes {
            assert_eq!(code.len(), BACKUP_CODE_LENGTH);
            // Ensure code only contains alphanumeric characters
            assert!(code.chars().all(|c| c.is_ascii_alphanumeric()));
        }
    }

    #[test]
    fn test_hash_and_verify() {
        let code = "ABCDEF1234";
        let hash = hash_code(code).unwrap();

        // Verify correct code works
        assert!(verify_code_hash(code, &hash).unwrap());

        // Verify incorrect code fails
        assert!(!verify_code_hash("WRONG12345", &hash).unwrap());
    }
}
