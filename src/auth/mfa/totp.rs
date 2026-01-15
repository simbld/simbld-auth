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
use sqlx::{FromRow, Pool, Postgres, Transaction};
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

    #[error("TOTP isn't n' up for the user")]
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
    /// Helper to get the TOTP MFA method for a user
    async fn get_mfa_method(pool: &Pool<Postgres>, user_id: Uuid) -> Result<MfaMethod, TotpError> {
        sqlx::query_as::<_, MfaMethod>(
            "SELECT * FROM mfa_methods WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or(TotpError::NotSetup)
    }

    /// Helper to store a batch of backup codes
    async fn store_backup_codes_batch(
        tx: &mut Transaction<'_, Postgres>,
        user_id: Uuid,
        mfa_method_id: Uuid,
        batch_id: Uuid,
        codes: &[String],
        start_index: i32,
    ) -> Result<(), TotpError> {
        for (i, code) in codes.iter().enumerate() {
            sqlx::query(
				"INSERT INTO backup_codes (user_id, mfa_method_id, code, code_hash, code_index, batch_id, used)
                 VALUES ($1, $2, $3, $4, $5, $6, false)",
			)
			  .bind(user_id)
			  .bind(mfa_method_id)
			  .bind(code)
			  .bind("") // code_hash placeholder
			  .bind(start_index + i as i32)
			  .bind(batch_id)
			  .execute(&mut **tx)
			  .await?;
        }
        Ok(())
    }

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
            "SELECT id FROM mfa_methods WHERE user_id = $1 AND method_type = 'totp'",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?;

        if existing.is_some() {
            return Err(TotpError::AlreadySetup);
        }

        // Use a provided secret or generate a new one
        let secret = match secret {
            Some(s) => s,
            None => Self::generate_secret()?,
        };

        // Start a transaction
        let mut tx = pool.begin().await?;

        let batch_id = Uuid::new_v4();

        // Insert MFA method
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "INSERT INTO mfa_methods (user_id, method_type, secret, enabled, verified, is_primary)
             VALUES ($1, 'totp', $2, false, false, false) RETURNING *",
        )
        .bind(user_id)
        .bind(&secret)
        .fetch_one(&mut *tx)
        .await?;

        // Store the TOTP secret as index 0
        Self::store_backup_codes_batch(
            &mut tx,
            user_id,
            mfa_method.id,
            batch_id,
            &[secret.clone()],
            0,
        )
        .await?;

        // Generate and store backup codes (indices 1-10)
        let backup_codes = Self::generate_backup_codes(10);
        Self::store_backup_codes_batch(&mut tx, user_id, mfa_method.id, batch_id, &backup_codes, 1)
            .await?;

        tx.commit().await?;

        Ok((secret, backup_codes))
    }

    /// Verifies a TOTP code and activates TOTP for the user if valid
    pub async fn verify_and_activate_totp(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, TotpError> {
        let mfa_method = Self::get_mfa_method(pool, user_id).await?;

        // Get the TOTP secret (index 0)
        let totp_data = sqlx::query_as::<_, TotpData>(
            "SELECT bc.id, bc.mfa_method_id, bc.code, bc.used, bc.created_at, bc.last_used_at
             FROM backup_codes bc
             WHERE bc.mfa_method_id = $1
             ORDER BY bc.created_at
             LIMIT 1",
        )
        .bind(mfa_method.id)
        .fetch_optional(pool)
        .await?
        .ok_or(TotpError::NotSetup)?;

        log::debug!("Activating TOTP for method ID: {}", mfa_method.id);

        if !Self::verify_code(&totp_data.code, code, None) {
            return Err(TotpError::InvalidCode);
        }

        sqlx::query(
            "UPDATE mfa_methods SET verified = true, enabled = true
             WHERE id = $1",
        )
        .bind(mfa_method.id)
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
        let mfa_method = sqlx::query_as::<_, MfaMethod>(
            "SELECT id FROM mfa_methods
             WHERE user_id = $1 AND method_type = 'totp' AND enabled = true",
        )
        .bind(user_id)
        .fetch_optional(pool)
        .await?
        .ok_or(TotpError::NotSetup)?;

        // Try as backup code first
        let backup_code = sqlx::query_as::<_, BackupCode>(
            "SELECT id FROM backup_codes
             WHERE mfa_method_id = $1 AND code = $2 AND used = false",
        )
        .bind(mfa_method.id)
        .bind(code)
        .fetch_optional(pool)
        .await?;

        if let Some(bc) = backup_code {
            sqlx::query(
				"UPDATE backup_codes SET used = true, last_used_at = CURRENT_TIMESTAMP WHERE id = $1",
			)
			  .bind(bc.id)
			  .execute(pool)
			  .await?;
            return Ok(true);
        }

        // Try as TOTP code
        let totp_data = sqlx::query_as::<_, TotpData>(
            "SELECT code FROM backup_codes WHERE mfa_method_id = $1 ORDER BY created_at LIMIT 1",
        )
        .bind(mfa_method.id)
        .fetch_one(pool)
        .await?;

        if Self::verify_code(&totp_data.code, code, None) {
            sqlx::query("UPDATE mfa_methods SET updated_at = CURRENT_TIMESTAMP WHERE id = $1")
                .bind(mfa_method.id)
                .execute(pool)
                .await?;
            return Ok(true);
        }

        Ok(false)
    }

    /// Disables TOTP for a user
    pub async fn disable_totp(pool: &Pool<Postgres>, user_id: Uuid) -> Result<(), TotpError> {
        let mfa_method = Self::get_mfa_method(pool, user_id).await?;
        let mut tx = pool.begin().await?;

        sqlx::query("DELETE FROM backup_codes WHERE mfa_method_id = $1")
            .bind(mfa_method.id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM mfa_methods WHERE id = $1")
            .bind(mfa_method.id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(())
    }

    /// Regenerates backup codes for a user
    pub async fn regenerate_backup_codes(
        pool: &Pool<Postgres>,
        user_id: Uuid,
    ) -> Result<Vec<String>, TotpError> {
        let mfa_method = Self::get_mfa_method(pool, user_id).await?;
        let mut tx = pool.begin().await?;
        let batch_id = Uuid::new_v4();

        // Delete all except the secret (index 0)
        sqlx::query(
			"DELETE FROM backup_codes
             WHERE mfa_method_id = $1
             AND id NOT IN (SELECT id FROM backup_codes WHERE mfa_method_id = $1 ORDER BY created_at LIMIT 1)",
		)
		  .bind(mfa_method.id)
		  .execute(&mut *tx)
		  .await?;

        let backup_codes = Self::generate_backup_codes(10);
        Self::store_backup_codes_batch(&mut tx, user_id, mfa_method.id, batch_id, &backup_codes, 1)
            .await?;

        tx.commit().await?;
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

        Ok(format!(
            "data:image/svg+xml;base64,{}",
            general_purpose::STANDARD.encode(svg.as_bytes())
        ))
    }

    /// Generates backup codes for recovery
    fn generate_backup_codes(count: usize) -> Vec<String> {
        let mut rng = rand::rng();
        (0..count).map(|_| (0..8).map(|_| rng.random_range(0..10).to_string()).collect()).collect()
    }

    /// Verifies a TOTP code against the secret
    fn verify_code(secret: &str, code: &str, time: Option<DateTime<Utc>>) -> bool {
        let timestamp = time.unwrap_or_else(Utc::now).timestamp() as u64;
        for i in 0..=DEFAULT_TIME_WINDOWS {
            if Self::generate_code(secret, timestamp - (i * DEFAULT_PERIOD)) == code {
                return true;
            }
        }
        false
    }

    /// Generates a TOTP code for a given timestamp
    fn generate_code(secret: &str, timestamp: u64) -> String {
        let decoded = base32::decode(
            Alphabet::Rfc4648 {
                padding: false,
            },
            secret,
        )
        .expect("Invalid base32 secret");
        let counter_bytes = (timestamp / DEFAULT_PERIOD).to_be_bytes();

        let mut mac = Hmac::<Sha1>::new_from_slice(&decoded).expect("HMAC error");
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();

        let offset = (result[19] & 0xf) as usize;
        let binary = ((result[offset] & 0x7f) as u32) << 24
            | ((result[offset + 1] & 0xff) as u32) << 16
            | ((result[offset + 2] & 0xff) as u32) << 8
            | (result[offset + 3] & 0xff) as u32;

        format!("{:0>width$}", binary % 10u32.pow(DEFAULT_DIGITS as u32), width = DEFAULT_DIGITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_generate_secret() {
        let secret = TotpService::generate_secret().unwrap();
        assert_eq!(secret.len(), 52);
        assert_ne!(secret, TotpService::generate_secret().unwrap());
    }

    #[test]
    fn test_generate_and_verify_code() {
        let secret = "JBSWY3DPEHPK3PXP";
        let timestamp = 1_602_000_000;
        let code = TotpService::generate_code(secret, timestamp);
        assert!(TotpService::verify_code(
            secret,
            &code,
            Some(Utc.timestamp_opt(timestamp as i64, 0).unwrap())
        ));
    }
}
