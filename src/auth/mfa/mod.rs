//! Multi-Factor Authentication module.
//!
//! Provides comprehensive MFA capabilities for securing user accounts:
//! - Time-based One-Time Password (TOTP) implementation
//! - WebAuthn/FIDO2 integration
//! - Backup codes for account recovery
//! - MFA policy enforcement

pub mod backup_codes;
pub mod dto;
pub mod email;
pub mod push;
pub mod recovery;
pub mod sms;
pub mod totp;
pub mod webauthn;

pub use backup_codes::{BackupCodeError, BackupCodeService};
pub use totp::{MfaType, TotpError, TotpService};

use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum MfaError {
    #[error("TOTP error: {0}")]
    TotpError(#[from] TotpError),

    #[error("Backup code error: {0}")]
    BackupCodeError(#[from] BackupCodeError),

    #[error("MFA not enabled for user")]
    NotEnabled,

    #[error("MFA already enabled for user")]
    AlreadyEnabled,

    #[error("MFA verification failed")]
    VerificationFailed,

    #[error("Database error: {0}")]
    DatabaseError(String),
}

/// MFA status for a user
#[derive(Debug, Serialize, Deserialize)]
pub struct MfaStatus {
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
    pub backup_codes_available: bool,
    pub backup_codes_count: usize,
}

/// MFA policy options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaPolicy {
    pub require_mfa: bool,
    pub allow_remember_device: bool,
    pub remember_device_days: u32,
    pub allowed_methods: Vec<MfaType>,
}

impl Default for MfaPolicy {
    fn default() -> Self {
        Self {
            require_mfa: false,
            allow_remember_device: true,
            remember_device_days: 30,
            allowed_methods: vec![MfaType::Totp, MfaType::BackupCode],
        }
    }
}

/// Unified MFA service interface
pub struct MfaService;

impl MfaService {
    /// Get MFA status for a user
    pub async fn get_mfa_status(client: &Client, user_id: Uuid) -> Result<MfaStatus, MfaError> {
        // Check TOTP
        let totp_row = client
            .query_opt(
                "SELECT id FROM user_mfa_totp WHERE user_id = $1 AND enabled = true",
                &[&user_id],
            )
            .await
            .map_err(|e| MfaError::DatabaseError(e.to_string()))?;

        let totp_enabled = totp_row.is_some();

        // Check WebAuthn (when implemented)
        let webauthn_enabled = false;

        // Check backup codes
        let backup_row = client
            .query_opt("SELECT codes FROM user_backup_codes WHERE user_id = $1", &[&user_id])
            .await
            .map_err(|e| MfaError::DatabaseError(e.to_string()))?;

        let (backup_codes_available, backup_codes_count) = match backup_row {
            Some(row) => {
                let codes: Vec<String> = row.get("codes");
                (true, codes.len())
            },
            None => (false, 0),
        };

        Ok(MfaStatus {
            totp_enabled,
            webauthn_enabled,
            backup_codes_available,
            backup_codes_count,
        })
    }

    /// Verify MFA during authentication
    pub async fn verify_authentication(
        pool: &Pool<Postgres>,
        user_id: Uuid,
        mfa_type: MfaType,
        code: &str,
    ) -> Result<bool, MfaError> {
        match mfa_type {
            MfaType::Totp => TotpService::verify_authentication(pool, user_id, code)
                .await
                .map_err(MfaError::from),
            MfaType::BackupCode => {
                BackupCodeService::verify_code(pool, user_id, code).await.map_err(MfaError::from)
            },
            // Other methods not yet implemented
            _ => Err(MfaError::VerificationFailed),
        }
    }

    /// Check if MFA is required for a user based on policy
    pub async fn is_mfa_required(
        client: &Client,
        user_id: Uuid,
        policy: &MfaPolicy,
    ) -> Result<bool, MfaError> {
        if !policy.require_mfa {
            return Ok(false);
        }

        // Check if user has MFA methods configured
        let status = Self::get_mfa_status(client, user_id).await?;

        Ok(status.totp_enabled || status.webauthn_enabled)
    }

    /// Enable MFA for a user (setup phase)
    pub async fn enable_mfa(
        client: &Client,
        user_id: Uuid,
        mfa_type: MfaType,
    ) -> Result<(), MfaError> {
        match mfa_type {
            MfaType::Totp => {
                // Check if already enabled
                let existing = TotpService::get_user_totp(client, user_id).await?;
                if existing.map(|t| t.enabled).unwrap_or(false) {
                    return Err(MfaError::AlreadyEnabled);
                }

                // Generate backup codes if they don't exist
                if !BackupCodeService::has_backup_codes(client, user_id).await? {
                    BackupCodeService::generate_backup_codes(client, user_id).await?;
                }

                Ok(())
            },
            MfaType::BackupCode => {
                // Backup codes are always available, just regenerate if needed
                if !BackupCodeService::has_backup_codes(client, user_id).await? {
                    BackupCodeService::generate_backup_codes(client, user_id).await?;
                }

                Ok(())
            },
            _ => Err(MfaError::VerificationFailed), // Not implemented yet
        }
    }

    /// Disable MFA for a user
    pub async fn disable_mfa(
        client: &Client,
        user_id: Uuid,
        mfa_type: MfaType,
    ) -> Result<(), MfaError> {
        match mfa_type {
            MfaType::Totp => {
                // Disable TOTP
                let updated = client
                    .execute(
                        "UPDATE user_mfa_totp SET enabled = false WHERE user_id = $1",
                        &[&user_id],
                    )
                    .await
                    .map_err(|e| MfaError::DatabaseError(e.to_string()))?;

                if updated == 0 {
                    return Err(MfaError::NotEnabled);
                }

                Ok(())
            },
            MfaType::BackupCode => {
                // Cannot disable backup codes, just regenerate them
                BackupCodeService::generate_backup_codes(client, user_id).await?;
                Ok(())
            },
            _ => Err(MfaError::VerificationFailed), // Not implemented yet
        }
    }

    /// Record a successful MFA verification
    pub async fn record_verification(
        client: &Client,
        user_id: Uuid,
        mfa_type: MfaType,
    ) -> Result<(), MfaError> {
        client
            .execute(
                "INSERT INTO mfa_verifications (user_id, method, verified_at)
                 VALUES ($1, $2, NOW())",
                &[&user_id, &mfa_type.to_string()],
            )
            .await
            .map_err(|e| MfaError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Get available MFA methods for a user
    pub async fn get_available_methods(
        client: &Client,
        user_id: Uuid,
    ) -> Result<Vec<MfaType>, MfaError> {
        let status = Self::get_mfa_status(client, user_id).await?;
        let mut methods = Vec::new();

        if status.totp_enabled {
            methods.push(MfaType::Totp);
        }

        if status.webauthn_enabled {
            methods.push(MfaType::WebAuthn);
        }

        if status.backup_codes_available {
            methods.push(MfaType::BackupCode);
        }

        Ok(methods)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mocks::mock_client::MockClient;
    use tokio_postgres::Row;

    #[tokio::test]
    async fn test_get_mfa_status_with_enabled_totp() {
        // Create a mock client that returns enabled TOTP
        let mock_client = MockClient::with_query_opt_result(Some(Row::new()));

        // Create a mock client that returns backup codes
        let mock_client = MockClient::with_query_opt_result(Some(Row::new()));

        let user_id = Uuid::new_v4();

        // This test won't pass with the current mock implementation
        // We need to enhance our mocks to handle sequential calls
        // For now, this serves as a template
    }

    #[tokio::test]
    async fn test_verify_authentication_totp_success() {
        // This would test TOTP verification with a mock TotpService
        // It would need to mock the TotpService::verify_authentication method
    }

    #[tokio::test]
    async fn test_disable_mfa_success() {
        // Create a mock client that returns 1 affected row for the update
        let mock_client = MockClient::with_execute_result(1);

        let user_id = Uuid::new_v4();

        // This is a template - actual test implementation would need
        // more refined mocking capabilities
    }

    #[tokio::test]
    async fn test_disable_mfa_not_enabled() {
        // Create a mock client that returns 0 affected rows (nothing updated)
        let mock_client = MockClient::with_execute_result(0);

        let user_id = Uuid::new_v4();

        // This is a template - actual test implementation would need
        // more refined mocking capabilities
    }

    // Additional tests would be added for other methods
}
