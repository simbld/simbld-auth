//! Time-based One-Time Password (TOTP) implementation for multi-factor authentication.
//!
//! Compliant with RFC 6238 (TOTP) and RFC 4226 (HOTP).
//! Compatible with Google Authenticator, Authy, Microsoft Authenticator, etc.

use base32::Alphabet;
use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Client;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use thiserror::Error;
use tokio_pg_mapper::PostgresMapper;
use tokio_pg_mapper_derive::PostgresMapper;
use uuid::Uuid;

/// TOTP secret length in bytes (recommended 20+ bytes for security)
const SECRET_LENGTH: usize = 32;

/// Default number of digits in TOTP code
const DEFAULT_DIGITS: usize = 6;

/// Default period (time step) in seconds
const DEFAULT_PERIOD: u64 = 30;

/// Default time window for code verification (before and after current time)
const DEFAULT_TIME_WINDOWS: u64 = 1;

/// MFA verification types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MfaType {
    Totp,
    WebAuthn,
    BackupCode,
    Sms,
}

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
}

/// TOTP setup record in the database
#[derive(Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user_mfa_totp")]
pub struct UserTotp {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret: String,
    pub backup_codes: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub enabled: bool,
}

/// TOTP service for managing time-based one-time passwords
pub struct TotpService;

impl TotpService {
    /// Generate a new TOTP secret
    pub fn generate_secret() -> Result<String, TotpError> {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; SECRET_LENGTH];
        rng.fill(&mut secret_bytes);

        // Encode in base32 for compatibility with authenticator apps
        let encoded = base32::encode(
            Alphabet::RFC4648 { padding: false },
            &secret_bytes,
        );

        Ok(encoded)
    }

    /// Setup TOTP for a user
    pub async fn setup_totp(
        client: &Client,
        user_id: Uuid,
        secret: Option<String>,
    ) -> Result<(String, Vec<String>), TotpError> {
        // Check if TOTP is already set up
        let existing_setup = client
            .query_opt(
                "SELECT id FROM user_mfa_totp WHERE user_id = $1 AND enabled = true",
                &[&user_id],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        if existing_setup.is_some() {
            return Err(TotpError::AlreadySetup);
        }

        // Generate a new secret if not provided
        let secret = secret.unwrap_or_else(|| Self::generate_secret().unwrap());

        // Generate backup codes
        let backup_codes = Self::generate_backup_codes(10);

        // Store in database
        let now = Utc::now();
        client
            .execute(
                "INSERT INTO user_mfa_totp (id, user_id, secret, backup_codes, created_at, enabled)
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &Uuid::new_v4(),
                    &user_id,
                    &secret,
                    &backup_codes,
                    &now,
                    &false, // Not enabled until verified with a valid code
                ],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        Ok((secret, backup_codes))
    }

    /// Verify and activate TOTP setup
    pub async fn verify_and_activate_totp(
        client: &Client,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, TotpError> {
        // Get the TOTP setup for this user
        let row = client
            .query_opt(
                "SELECT id, secret FROM user_mfa_totp WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let (id, secret) = match row {
            Some(row) => (row.get::<_, Uuid>("id"), row.get::<_, String>("secret")),
            None => return Err(TotpError::NotSetup),
        };

        // Verify the provided code
        if Self::verify_code(&secret, code, None) {
            // Activate TOTP
            let now = Utc::now();
            client
                .execute(
                    "UPDATE user_mfa_totp SET enabled = true, last_used_at = $1 WHERE id = $2",
                    &[&now, &id],
                )
                .await
                .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Verify a TOTP code for authentication
    pub async fn verify_authentication(
        client: &Client,
        user_id: Uuid,
        code: &str,
    ) -> Result<bool, TotpError> {
        // Get the TOTP setup for this user
        let row = client
            .query_opt(
                "SELECT id, secret, backup_codes FROM user_mfa_totp
                 WHERE user_id = $1 AND enabled = true",
                &[&user_id],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let (id, secret, backup_codes) = match row {
            Some(row) => (
                row.get::<_, Uuid>("id"),
                row.get::<_, String>("secret"),
                row.get::<_, Option<Vec<String>>>("backup_codes").unwrap_or_default(),
            ),
            None => return Err(TotpError::NotSetup),
        };

        // First check if it's a backup code
        if let Some(index) = backup_codes.iter().position(|bc| bc == code) {
            // Remove the used backup code
            let mut updated_codes = backup_codes.clone();
            updated_codes.remove(index);

            let now = Utc::now();
            client
                .execute(
                    "UPDATE user_mfa_totp SET backup_codes = $1, last_used_at = $2 WHERE id = $3",
                    &[&updated_codes, &now, &id],
                )
                .await
                .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

            return Ok(true);
        }

        // Otherwise verify as a TOTP code
        if Self::verify_code(&secret, code, None) {
            // Update last used time
            let now = Utc::now();
            client
                .execute(
                    "UPDATE user_mfa_totp SET last_used_at = $1 WHERE id = $2",
                    &[&now, &id],
                )
                .await
                .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Disable TOTP for a user
    pub async fn disable_totp(
        client: &Client,
        user_id: Uuid,
    ) -> Result<(), TotpError> {
        let result = client
            .execute(
                "DELETE FROM user_mfa_totp WHERE user_id = $1",
                &[&user_id],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        if result == 0 {
            return Err(TotpError::NotSetup);
        }

        Ok(())
    }

    /// Regenerate backup codes for a user
    pub async fn regenerate_backup_codes(
        client: &Client,
        user_id: Uuid,
    ) -> Result<Vec<String>, TotpError> {
        let row = client
            .query_opt(
                "SELECT id FROM user_mfa_totp WHERE user_id = $1 AND enabled = true",
                &[&user_id],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        let id = match row {
            Some(row) => row.get::<_, Uuid>("id"),
            None => return Err(TotpError::NotSetup),
        };

        // Generate new backup codes
        let backup_codes = Self::generate_backup_codes(10);

        // Update in database
        client
            .execute(
                "UPDATE user_mfa_totp SET backup_codes = $1 WHERE id = $2",
                &[&backup_codes, &id],
            )
            .await
            .map_err(|e| TotpError::DatabaseError(e.to_string()))?;

        Ok(backup_codes)
    }

    /// Generate URI for QR code (otpauth://...)
    pub fn generate_provisioning_uri(secret: &str, account_name: &str, issuer: &str) -> String {
        let encoded_account = urlencoding::encode(account_name);
        let encoded_issuer = urlencoding::encode(issuer);

        format!(
            "otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits={digits}&period={period}",
            issuer = encoded_issuer,
            account = encoded_account,
            secret = secret,
            digits = DEFAULT_DIGITS,
            period = DEFAULT_PERIOD,
        )
    }

    /// Convert the TOTP URI to a QR code data URL
    pub fn generate_qr_code_url(uri: &str) -> Result<String, TotpError> {
        // This would typically use a QR code generation library
        // For simplicity, we're returning a placeholder
        Ok(format!("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={}", urlencoding::encode(uri)))
    }

    /// Generate random backup codes
    fn generate_backup_codes(count: usize) -> Vec<String> {
        let mut codes = Vec::with_capacity(count);
        let mut rng = rand::thread_rng();

        for _ in 0..count {
            // Generate 8-character alphanumeric codes
            let code: String = (0..8)
                .map(|_| {
                    let idx = rng.gen_range(0..36);
                    if idx < 10 {
                        (b'0' + idx) as char
                    } else {
                        (b'A' + (idx - 10)) as char
                    }
                })
                .collect();

            codes.push(code);
        }

        codes
    }

    /// Verify a TOTP code with an optional time
    fn verify_code(secret: &str, code: &str, time: Option<DateTime<Utc>>) -> bool {
        let time = time.unwrap_or_else(Utc::now);
        let timestamp = time.timestamp() as u64;

        // Check current and adjacent time windows
        for window in -(DEFAULT_TIME_WINDOWS as i64)..=DEFAULT_TIME_WINDOWS as i64 {
            let adjusted_timestamp = timestamp + (window * DEFAULT_PERIOD) as u64;
            let expected_code = Self::generate_code(secret, adjusted_timestamp);

            if expected_code == code {
                return true;
            }
        }

        false
    }

    /// Generate a TOTP code for a given timestamp
    fn generate_code(secret: &str, timestamp: u64) -> String {
        // Decode the base32 secret
        let secret_bytes = match base32::decode(Alphabet::RFC4648 { padding: false }, secret) {
            Some(bytes) => bytes,
            None => return String::new(),
        };

        // Calculate the time counter
        let counter = timestamp / DEFAULT_PERIOD;

        // Convert counter to big-endian bytes
        let counter_bytes = counter.to_be_bytes();

        // Calculate HMAC-SHA1
        let mut mac = Hmac::<Sha1>::new_from_slice(&secret_bytes)
            .expect("HMAC can take key of any size");
        mac.update(&counter_bytes);
        let result = mac.finalize().into_bytes();

        // Dynamic truncation
        let offset = (result[19] & 0xf) as usize;
        let binary = ((result[offset] & 0x7f) as u32) << 24
            | (result[offset + 1] as u32) << 16
            | (result[offset + 2] as u32) << 8
            | (result[offset + 3] as u32);

        // Calculate modulus and format the code
        let code = binary % 10u32.pow(DEFAULT_DIGITS as u32);
        format!("{:0width$}", code, width = DEFAULT_DIGITS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_secret() {
        let secret = TotpService::generate_secret().unwrap();
        assert!(!secret.is_empty());
        // Base32 only uses uppercase letters and digits 2-7
        assert!(secret.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_and_verify_code() {
        let secret = "JBSWY3DPEHPK3PXP"; // Test secret
        let timestamp = 1616161616; // Fixed timestamp for testing

        // Generate code
        let code = TotpService::generate_code(secret, timestamp);
        assert_eq!(code.len(), DEFAULT_DIGITS);
        assert!(code.chars().all(|c| c.is_ascii_digit()));

        // Verify the same code with the same timestamp
        assert!(TotpService::verify_code(
            secret,
            &code,
            Some(DateTime::<Utc>::from_timestamp(timestamp as i64, 0).unwrap())
        ));

        // Verify the code fails with a different timestamp (outside the window)
        assert!(!TotpService::verify_code(
            secret,
            &code,
            Some(DateTime::<Utc>::from_timestamp(timestamp as i64 + 120, 0).unwrap())
        ));
    }

    #[test]
    fn test_generate_backup_codes() {
        let codes = TotpService::generate_backup_codes(10);
        assert_eq!(codes.len(), 10);

        // All codes should be 8 characters and alphanumeric
        for code in codes {
            assert_eq!(code.len(), 8);
            assert!(code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
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
        let issuer = "MyApp";

        let uri = TotpService::generate_provisioning_uri(secret, account, issuer);

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains(secret));
        assert!(uri.contains("MyApp"));
        assert!(uri.contains("user%40example.com")); // Encoded @ sign
    }
}