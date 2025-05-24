//! Data Transfer Objects for Multi-Factor Authentication
//!
//! Contains request and response structures for MFA-related APIs

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::MfaType;

/// MFA setup initialization request
#[derive(Debug, Deserialize)]
pub struct MfaSetupInitRequest {
    pub mfa_type: MfaType,
    pub device_name: Option<String>,
}

/// TOTP setup response
#[derive(Debug, Serialize)]
pub struct TotpSetupResponse {
    pub secret: String,
    pub qr_code: String,
    pub setup_token: String,
}

/// WebAuthn registration options response
#[derive(Debug, Serialize)]
pub struct WebAuthnRegistrationResponse {
    pub registration_options: String,
    pub setup_token: String,
}

/// MFA setup verification request
#[derive(Debug, Deserialize)]
pub struct MfaSetupVerifyRequest {
    pub setup_token: String,
    pub code: String,
}

/// WebAuthn verification request
#[derive(Debug, Deserialize)]
pub struct WebAuthnVerifyRequest {
    pub setup_token: String,
    pub registration_data: String,
}

/// Backup codes response
#[derive(Debug, Serialize)]
pub struct BackupCodesResponse {
    pub codes: Vec<String>,
}

/// MFA methods status response
#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    pub totp_enabled: bool,
    pub webauthn_enabled: bool,
    pub webauthn_credentials: Vec<WebAuthnCredentialInfo>,
    pub backup_codes_available: bool,
    pub backup_codes_count: Option<usize>,
}

/// WebAuthn credential info
#[derive(Debug, Serialize)]
pub struct WebAuthnCredentialInfo {
    pub id: Uuid,
    pub name: Option<String>,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// MFA disable request
#[derive(Debug, Deserialize)]
pub struct MfaDisableRequest {
    pub mfa_type: MfaType,
    pub credential_id: Option<Uuid>,
    pub verification_code: Option<String>,
}