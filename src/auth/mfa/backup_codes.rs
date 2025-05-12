//! Backup codes for account recovery when MFA devices are lost or unavailable.
//!
//! These single-use codes allow users to authenticate when they cannot access their
//! primary MFA method (TOTP app, WebAuthn device, etc).

use chrono::{DateTime, Utc};
use deadpool_postgres::Client;
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_pg_mapper::PostgresMapper;
use tokio_pg_mapper_derive::PostgresMapper;
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
}

/// Backup codes database record
#[derive(Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user_backup_codes")]
pub struct UserBackupCodes {
    pub id: Uuid,
    pub user_id: Uuid,
    pub codes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Service for managing backup codes
pub struct BackupCodeService;

impl BackupCodeService {
    /// Generate a set of backup codes for a user
    pub async fn generate_codes(
        client: &Client,
        user_id: Uuid,
        count: Option<usize>,
    ) -> Result<Vec<String>, BackupCodeError> {
        let count = count.unwrap_or(DEFAULT_BACKUP_CODE_COUNT);
        let codes = Self::create_random_codes(count);

        // Check if user already has backup codes
        let existing = client
            .query_opt(
                "SELECT id FROM user_backup_codes WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        let now = Utc::now();

        if let Some(row) = existing {
            let id = row.get::<_, Uuid>("id");

            // Update existing record
            client
                .execute(
                    "UPDATE user_backup_codes SET codes = $1, created_at = $2, last_used_at = NULL WHERE id = $3",
                    &[&codes, &now, &id],
                )
                .await
                .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;
        } else {
            // Create new record
            client
                .execute(
                    "INSERT INTO user_backup_codes (id, user_id, codes, created_at) VALUES ($1, $2, $3, $4)",
                    &[&Uuid::new_v4(), &user_id, &codes, &now],
                )
                .await
                .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;
        }

        Ok(codes)
    }

    /// Verify a backup code during authentication
    pub async fn verify_code(
        client: &Client,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, BackupCodeError> {
        // Get backup codes for user
        let row = client
            .query_opt(
                "SELECT id, codes FROM user_backup_codes WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        let (id, mut codes) = match row {
            Some(row) => (row.get::<_, Uuid>("id"), row.get::<_, Vec<String>>("codes")),
            None => return Err(BackupCodeError::NoCodesAvailable),
        };

        // Check if the provided code matches any backup code
        if let Some(index) = codes.iter().position(|c| c == code) {
            // Remove the used code
            codes.remove(index);

            // Update the database
            let now = Utc::now();
            client
                .execute(
                    "UPDATE user_backup_codes SET codes = $1, last_used_at = $2 WHERE id = $3",
                    &[&codes, &now, &id],
                )
                .await
                .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get the number of remaining backup codes for a user
    pub async fn get_remaining_code_count(
        client: &Client,
        user_id: Uuid,
    ) -> Result<usize, BackupCodeError> {
        let row = client
            .query_opt(
                "SELECT codes FROM user_backup_codes WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        match row {
            Some(row) => {
                let codes: Vec<String> = row.get("codes");
                Ok(codes.len())
            },
            None => Ok(0),
        }
    }

    /// Clear all backup codes for a user
    pub async fn clear_codes(
        client: &Client,
        user_id: Uuid,
    ) -> Result<(), BackupCodeError> {
        client
            .execute(
                "DELETE FROM user_backup_codes WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| BackupCodeError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Generate random backup codes
    fn create_random_codes(count: usize) -> Vec<String> {
        let mut rng = rand::thread_rng();
        let mut codes = Vec::with_capacity(count);

        for _ in 0..count {
            // Format: XXXX-XXXX-XXXX (where X is alphanumeric)
            let code: String = (0..3)
                .map(|section| {
                    (0..4)
                        .map(|_| {
                            let idx = rng.gen_range(0..36);
                            if idx < 10 {
                                (b'0' + idx) as char
                            } else {
                                (b'A' + (idx - 10)) as char
                            }
                        })
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("-");

            codes.push(code);
        }

        codes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_random_codes() {
        let codes = BackupCodeService::create_random_codes(10);

        assert_eq!(codes.len(), 10);

        // Check format: XXXX-XXXX-XXXX
        for code in &codes {
            assert_eq!(code.len(), 14); // 12 chars + 2 hyphens

            let parts: Vec<&str> = code.split('-').collect();
            assert_eq!(parts.len(), 3);

            for part in parts {
                assert_eq!(part.len(), 4);
                assert!(part.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
            }
        }

        // Check uniqueness
        let mut unique_codes = codes.clone();
        unique_codes.sort();
        unique_codes.dedup();
        assert_eq!(unique_codes.len(), codes.len());
    }
}