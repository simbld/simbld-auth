//! TOTP (Time-based One-Time Password) implementation for Multi-Factor Authentication.
//! This module provides functionality for generating, verifying, and managing TOTP-based
//! authentication, including backup code generation and QR code generation for easy setup.

use base32::Alphabet;
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use qrcode::{render::svg, QrCode};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sqlx::{FromRow, Pool, Postgres};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

// Constants for TOTP configuration
const SECRET_LENGTH: usize = 32;
const DEFAULT_DIGITS: usize = 6;
const DEFAULT_PERIOD: u64 = 30;
const DEFAULT_TIME_WINDOWS: u64 = 1;

#[derive(Debug, Error)]
pub enum TotpError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Secret generation error")]
    SecretGenerationError,

    #[error("Invalid TOTP code")]
    InvalidCode,

    #[error("TOTP is not set up for user")]
    NotSetup,

    #[error("TOTP is already set up for user")]
    AlreadySetup,

    #[error("QR code generation error: {0}")]
    QrCodeGenerationError(String),
}

impl From<sqlx::Error> for TotpError {
    fn from(error: sqlx::Error) -> Self {
        TotpError::DatabaseError(error.to_string())
    }
}

/// MFA method record in the database
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct MfaMethod {
    pub id: Uuid,
    pub user_id: Uuid,
    pub method_type: String, // Will contain "totp"
    pub is_primary: bool,    // Indicates if this is the primary MFA method
    pub enabled: bool,
    pub secret: Option<String>,              // Optional secret for TOTP
    pub verified: Option<bool>,              // Optional verification status
    pub last_used_at: Option<DateTime<Utc>>, // Optional last-used timestamp
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// TOTP specific data (stored as a backup code with special type)
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct TotpData {
    pub id: Uuid,
    pub mfa_method_id: Uuid,
    pub code: String, // Will store the TOTP secret
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Backup codes for TOTP recovery
#[derive(Debug, Serialize, Deserialize, FromRow)]
pub struct BackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

/// Service for handling TOTP-based MFA operations
pub struct TotpService;

impl TotpService {
    /// Generates a new random TOTP secret
    pub fn generate_secret() -> Result<String, TotpError> {
        let mut bytes = vec![0u8; SECRET_LENGTH];
        let mut rng = rand::rng();

        RngCore::fill_bytes(&mut rng, &mut bytes);

        // Encode the random bytes using base32 (standard for TOTP)
        let secret = base32::encode(
            Alphabet::Rfc4648 {
                padding: false,
            },
            &bytes,
        );

        Ok(secret)
    }

    /// Sets up TOTP for a user, optionally using a provided secret
    pub async fn setup_totp(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        secret: Option<String>,
    ) -> Result<(String, Vec<String>), TotpError> {
        // Check if TOTP is already set up
        let existing = sqlx::query_as::<_, MfaMethod>(
            "SELECT * FROM mfa_methods WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        if existing.is_some() {
            return Err(TotpError::AlreadySetup);
        }

        // Use provided secret or generate a new one
        let secret = match secret {
            Some(s) => s,
            None => Self::generate_secret()?,
        };

        // Start a transaction
        let mut tx = pool.begin().await.map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Insert MFA method
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "INSERT INTO mfa_methods (user_id, method_type, secret, enabled, verified, is_primary)
     VALUES ($1, 'totp', $2, false, false, false) RETURNING *",
        )
        .bind(user_id)
        .bind(&secret)
        .fetch_one(pool)
        .await?;

        // Store the TOTP secret as a special "backup code"
        sqlx::query(
            "INSERT INTO backup_codes (mfa_method_id, code, used)
             VALUES ($1, $2, false)",
        )
        .bind(mfa_method.id)
        .bind(&secret)
        .execute(&mut *tx)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Generate backup codes
        let backup_codes = Self::generate_backup_codes(10);

        // Store backup codes
        for code in &backup_codes {
            sqlx::query(
                "INSERT INTO backup_codes (mfa_method_id, code, used)
                 VALUES ($1, $2, false)",
            )
            .bind(mfa_method.id)
            .bind(code)
            .execute(&mut *tx)
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;
        }

        // Commit transaction
        tx.commit().await.map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        Ok((secret, backup_codes))
    }

    /// Verifies a TOTP code and activates TOTP for the user if valid
    pub async fn verify_and_activate_totp(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, TotpError> {
        // Get the MFA method
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "SELECT * FROM mfa_methods WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let mfa_method = match mfa_method {
            Some(m) => m,
            None => return Err(TotpError::NotSetup),
        };

        // Get the TOTP secret
        let totp_data = sqlx::query_as::<_, TotpData>(
            "SELECT bc.id, bc.mfa_method_id, bc.code, bc.used, bc.created_at, bc.last_used_at
             FROM backup_codes bc
             JOIN mfa_methods mm ON bc.mfa_method_id = mm.id
             WHERE mm.user_id = $1 AND mm.method_type = 'totp'
             LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let totp_data = match totp_data {
            Some(d) => d,
            None => return Err(TotpError::NotSetup),
        };

        // Verify the provided code
        if !Self::verify_code(&totp_data.code, code, None) {
            return Err(TotpError::InvalidCode);
        }

        // Activate TOTP for the user
        sqlx::query(
            "UPDATE mfa_methods SET verified = true, enabled = true
             WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .execute(pool)
        .await?;

        Ok(true)
    }

    /// Verifies a TOTP code for authentication
    pub async fn verify_authentication(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, TotpError> {
        // Get the MFA method
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "SELECT * FROM mfa_methods
             WHERE user_id = $1 AND method_type = 'totp' AND enabled = true",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let mfa_method = match mfa_method {
            Some(m) => m,
            None => return Err(TotpError::NotSetup),
        };

        // Check if the code is a backup code
        let backup_code = sqlx::query_as::<_, BackupCode>(
            "SELECT * FROM backup_codes
             WHERE mfa_method_id = $1 AND code = $2 AND used = false",
        )
        .bind(mfa_method.id)
        .bind(code)
        .fetch_optional(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        if let Some(backup_code) = backup_code {
            // Mark the backup code as used
            sqlx::query(
                "UPDATE backup_codes
                 SET used = true, last_used_at = CURRENT_TIMESTAMP
                 WHERE id = $1",
            )
            .bind(backup_code.id)
            .execute(pool)
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

            return Ok(true);
        }

        // Get the TOTP secret
        let totp_data = sqlx::query_as::<_, TotpData>(
            "SELECT bc.id, bc.mfa_method_id, bc.code, bc.used, bc.created_at, bc.last_used_at
             FROM backup_codes bc
             WHERE bc.mfa_method_id = $1
             LIMIT 1",
        )
        .bind(mfa_method.id)
        .fetch_one(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Verify TOTP code
        if Self::verify_code(&totp_data.code, code, None) {
            // Update last used timestamp
            sqlx::query(
                "UPDATE mfa_methods
                 SET updated_at = CURRENT_TIMESTAMP
                 WHERE id = $1",
            )
            .bind(mfa_method.id)
            .execute(pool)
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

            return Ok(true);
        }

        Ok(false)
    }

    /// Disables TOTP for a user
    pub async fn disable_totp(pool: &Pool<Postgres>, user_id: Uuid) -> Result<(), TotpError> {
        // Get the MFA method
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "SELECT * FROM mfa_methods
             WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let mfa_method = match mfa_method {
            Some(m) => m,
            None => return Err(TotpError::NotSetup),
        };

        // Start a transaction
        let mut tx = pool.begin().await.map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Delete backup codes
        sqlx::query("DELETE FROM backup_codes WHERE mfa_method_id = $1")
            .bind(mfa_method.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Delete MFA method
        sqlx::query("DELETE FROM mfa_methods WHERE id = $1")
            .bind(mfa_method.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Commit transaction
        tx.commit().await.map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Regenerates backup codes for a user
    pub async fn regenerate_backup_codes(
        pool: &Pool<Postgres>,
        user_id: Uuid,
    ) -> Result<Vec<String>, TotpError> {
        // Get the MFA method
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "SELECT * FROM mfa_methods
             WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let mfa_method = match mfa_method {
            Some(m) => m,
            None => return Err(TotpError::NotSetup),
        };

        // Start a transaction
        let mut tx = pool.begin().await.map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Delete old backup codes (except the TOTP secret which is the first one)
        sqlx::query(
            "DELETE FROM backup_codes
             WHERE mfa_method_id = $1
             AND id NOT IN (
                 SELECT id FROM backup_codes
                 WHERE mfa_method_id = $1
                 ORDER BY created_at ASC
                 LIMIT 1
             )",
        )
        .bind(mfa_method.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        // Generate new backup codes
        let backup_codes = Self::generate_backup_codes(10);

        // Store new backup codes
        for code in &backup_codes {
            sqlx::query(
                "INSERT INTO backup_codes (mfa_method_id, code, used)
                 VALUES ($1, $2, false)",
            )
            .bind(mfa_method.id)
            .bind(code)
            .execute(&mut *tx)
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;
        }

        // Commit transaction
        tx.commit().await.map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        Ok(backup_codes)
    }

    /// Generates a TOTP provisioning URI for use with authenticator apps
    pub fn generate_provisioning_uri(secret: &str, account_name: &str, issuer: &str) -> String {
        let mut uri = Url::parse("otpauth://totp/").unwrap();
        uri.set_path(&format!("{issuer}:{account_name}"));

        let mut query_pairs = uri.query_pairs_mut();
        query_pairs.append_pair("secret", secret);
        query_pairs.append_pair("issuer", issuer);
        query_pairs.append_pair("algorithm", "SHA1");
        query_pairs.append_pair("digits", &DEFAULT_DIGITS.to_string());
        query_pairs.append_pair("period", &DEFAULT_PERIOD.to_string());
        drop(query_pairs);

        uri.to_string()
    }

    /// Generates a QR code as a data URI for the TOTP provisioning URI
    pub fn generate_qr_code_url(uri: &str) -> Result<String, TotpError> {
        let code = QrCode::new(uri).map_err(|e| TotpError::QrCodeGenerationError(e.to_string()))?;

        let svg = code
            .render::<svg::Color>()
            .min_dimensions(200, 200)
            .max_dimensions(300, 300)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        let base64_svg = general_purpose::STANDARD.encode(svg.as_bytes());
        Ok(format!("data:image/svg+xml;base64,{}", base64_svg))
    }

    /// Generates backup codes for recovery
    fn generate_backup_codes(count: usize) -> Vec<String> {
        let mut rng = rand::rng();
        let mut codes = Vec::with_capacity(count);

        for _ in 0..count {
            let code: String = (0..8).map(|_| rng.gen_range(0..10).to_string()).collect();
            codes.push(code);
        }

        codes
    }

    /// Verifies a TOTP code against the secret
    fn verify_code(secret: &str, code: &str, time: Option<DateTime<Utc>>) -> bool {
        let time = time.unwrap_or_else(Utc::now);
        let timestamp = time.timestamp() as u64;

        // Check the code against multiple time windows to account for time drift
        for i in 0..=DEFAULT_TIME_WINDOWS {
            let window_timestamp = timestamp - (i * DEFAULT_PERIOD);
            let expected_code = Self::generate_code(secret, window_timestamp);

            if expected_code == code {
                return true;
            }
        }

        false
    }

    /// Generates a TOTP code for a given timestamp
    fn generate_code(secret: &str, timestamp: u64) -> String {
        // Decode the base32-encoded secret
        let decoded = base32::decode(
            Alphabet::Rfc4648 {
                padding: false,
            },
            secret,
        )
        .expect("Invalid base32 secret");

        // Calculate the time counter (number of time steps)
        let counter = timestamp / DEFAULT_PERIOD;

        // Convert counter to big-endian bytes
        let counter_bytes = counter.to_be_bytes();

        // Create HMAC-SHA1 hash
        let mut mac =
            Hmac::<Sha1>::new_from_slice(&decoded).expect("HMAC can take key of any size");
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();

        // Dynamic truncation
        let offset = (result[19] & 0xf) as usize;
        let binary = ((result[offset] & 0x7f) as u32) << 24
            | ((result[offset + 1] & 0xff) as u32) << 16
            | ((result[offset + 2] & 0xff) as u32) << 8
            | (result[offset + 3] & 0xff) as u32;

        // Truncate to the desired number of digits
        let code = binary % 10u32.pow(DEFAULT_DIGITS as u32);

        // Format with leading zeros if needed
        format!("{:0>width$}", code, width = DEFAULT_DIGITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_generate_secret() {
        let secret = TotpService::generate_secret().unwrap();
        assert_eq!(secret.len(), 52); // Base32 encoded output length

        // Make sure it's different each time
        let secret2 = TotpService::generate_secret().unwrap();
        assert_ne!(secret, secret2);
    }

    #[test]
    fn test_generate_and_verify_code() {
        let secret = "JBSWY3DPEHPK3PXP"; // Test secret
        let timestamp = 1602000000; // Fixed timestamp for reproducible test

        let code = TotpService::generate_code(secret, timestamp);
        assert_eq!(code.len(), DEFAULT_DIGITS);

        // Verify the code works with the same timestamp
        assert!(TotpService::verify_code(
            secret,
            &code,
            Some(Utc.timestamp_opt(timestamp as i64, 0).unwrap())
        ));

        // Should fail with a different timestamp outside window
        assert!(!TotpService::verify_code(
            secret,
            &code,
            Some(Utc.timestamp_opt((timestamp + 120) as i64, 0).unwrap())
        ));
    }

    #[test]
    fn test_generate_backup_codes() {
        let codes = TotpService::generate_backup_codes(10);
        assert_eq!(codes.len(), 10);

        // Each code should be 8 digits
        for code in &codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_digit(10)));
        }

        // Codes should be unique
        let mut unique_codes = codes.clone();
        unique_codes.sort();
        unique_codes.dedup();
        assert_eq!(unique_codes.len(), codes.len());
    }

    #[test]
    fn test_generate_provisioning_uri() {
        let secret = "JBSWY3DPEHPK3PXP";
        let account = "user@example.com";
        let issuer = "TestApp";

        let uri = TotpService::generate_provisioning_uri(secret, account, issuer);

        assert!(uri.contains("otpauth://totp/"));
        assert!(uri.contains(account));
        assert!(uri.contains(issuer));
        assert!(uri.contains(secret));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains(&format!("digits={}", DEFAULT_DIGITS)));
        assert!(uri.contains(&format!("period={}", DEFAULT_PERIOD)));
    }

    #[test]
    fn test_generate_qr_code() {
        let uri = "otpauth://totp/Test:user@example.com?secret=JBSWY3DPEHPK3PXP";
        let qr_code = TotpService::generate_qr_code_url(uri).unwrap();

        assert!(qr_code.starts_with("data:image/svg+xml;base64,"));
        assert!(qr_code.len() > 100); // SVG QR code should be reasonably sized
    }
}
