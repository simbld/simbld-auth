//! # `WebAuthn` (FIDO2/U2F) Multi-Factor Authentication
//!
//! This module provides `WebAuthn` capabilities for authenticating with security keys,
//! biometrics, and platform authenticators like Windows Hello, Touch ID, etc.

use crate::auth::mfa::MfaMethod;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::types::{ApiError, AppConfig};

/// Provider for WebAuthn-based MFA
#[derive(Clone)]
pub struct WebAuthnProvider {
    ///`WebAuthn` implementation
    webauthn: Webauthn,
}

///`WebAuthn` credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Unique identifier
    pub id: Uuid,
    /// User ID
    pub user_id: Uuid,
    /// Credential ID
    pub credential_id: CredentialID,
    /// Credential public key
    pub passkey: Passkey,
    /// Credential counter
    pub counter: u32,
    /// User-friendly name
    pub name: String,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// Settings for `WebAuthn`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSettings {
    pub user_id: Uuid,
    pub enabled: bool,
    pub credential_count: usize,
}

/// Registration challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip)]
    pub state: Option<PasskeyRegistration>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationChallenge {
    pub id: Uuid,
    pub user_id: Uuid,
    #[serde(skip)]
    pub state: Option<PasskeyAuthentication>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl WebAuthnProvider {
    /// Create a new `WebAuthn` provider
    ///
    /// # Errors
    ///
    /// Returns `WebauthnError` if the configuration is invalid.
    pub fn new(config: &AppConfig) -> Result<Self, WebauthnError> {
        let rp_id = config.webauthn.rp_id.clone().unwrap_or_else(|| "localhost".to_string());
        let rp_name = config.webauthn.rp_name.clone().unwrap_or_else(|| "Simbld Auth".to_string());
        let rp_origin = config
            .webauthn
            .rp_origin
            .clone()
            .unwrap_or_else(|| "http://localhost:8080".to_string());
        let rp_origin_url = Url::parse(&rp_origin).map_err(|_| WebauthnError::Configuration)?;

        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin_url)?.rp_name(&rp_name).build()?;

        Ok(Self {
            webauthn,
        })
    }

    /// Start registration for a new credential
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if registration fails to initiate.
    pub async fn start_registration(
        &self,
        user_id: Uuid,
        username: &str,
        display_name: &str,
    ) -> Result<(Uuid, CreationChallengeResponse), ApiError> {
        let exclude_credentials = self.get_existing_credential_descriptors(user_id).await?;

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_id, username, display_name, Some(exclude_credentials))
            .map_err(|e| ApiError::Internal {
                message: format!("WebAuthn error: {e}"),
            })?;

        let challenge_id = Uuid::new_v4();
        let now = Utc::now();
        let challenge = WebAuthnRegistrationChallenge {
            id: challenge_id,
            user_id,
            state: Some(reg_state),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        };

        self.store_registration_challenge(&challenge).await?;
        Ok((challenge_id, ccr))
    }

    /// Complete registration
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the response is invalid or a challenge expired.
    pub async fn complete_registration(
        &self,
        challenge_id: Uuid,
        response: &RegisterPublicKeyCredential,
        name: &str,
    ) -> Result<WebAuthnCredential, ApiError> {
        let challenge = self.get_registration_challenge(challenge_id).await?;
        if challenge.expires_at < Utc::now() {
            return Err(ApiError::BadRequest("Challenge expired".into()));
        }

        let state = challenge.state.as_ref().ok_or_else(|| ApiError::Internal {
            message: "State missing".into(),
        })?;
        let result = self
            .webauthn
            .finish_passkey_registration(response, state)
            .map_err(|e| ApiError::BadRequest(format!("Invalid response: {e}")))?;

        let credential = WebAuthnCredential {
            id: Uuid::new_v4(),
            user_id: challenge.user_id,
            credential_id: result.cred_id().clone(),
            passkey: result,
            counter: 0,
            name: name.to_string(),
            created_at: Utc::now(),
            last_used: None,
        };

        self.store_credential(&credential).await?;
        self.delete_registration_challenge(challenge_id).await?;
        self.update_credential_count(challenge.user_id).await?;

        Ok(credential)
    }

    /// Start authentication
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the user has no credentials.
    pub async fn start_authentication(
        &self,
        user_id: Uuid,
    ) -> Result<(Uuid, RequestChallengeResponse), ApiError> {
        let passkeys = self.get_user_passkeys(user_id).await?;
        if passkeys.is_empty() {
            return Err(ApiError::BadRequest("No credentials found".into()));
        }

        let (rcr, auth_state) =
            self.webauthn.start_passkey_authentication(&passkeys).map_err(|e| {
                ApiError::Internal {
                    message: format!("Auth start failed: {e}"),
                }
            })?;

        let challenge_id = Uuid::new_v4();
        let now = Utc::now();
        let challenge = WebAuthnAuthenticationChallenge {
            id: challenge_id,
            user_id,
            state: Some(auth_state),
            created_at: now,
            expires_at: now + chrono::Duration::minutes(5),
        };

        self.store_authentication_challenge(&challenge).await?;
        Ok((challenge_id, rcr))
    }

    /// Complete authentication
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if verification fails.
    pub async fn complete_authentication(
        &self,
        challenge_id: Uuid,
        response: &PublicKeyCredential,
    ) -> Result<bool, ApiError> {
        let challenge = self.get_authentication_challenge(challenge_id).await?;
        if challenge.expires_at < Utc::now() {
            return Err(ApiError::BadRequest("Challenge expired".into()));
        }

        let state = challenge.state.as_ref().ok_or_else(|| ApiError::Internal {
            message: "State missing".into(),
        })?;
        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, state)
            .map_err(|e| ApiError::BadRequest(format!("Auth failed: {e}")))?;

        let cred_id =
            BASE64.decode(&response.id).map_err(|_| ApiError::BadRequest("Invalid ID".into()))?;
        if let Some(credential) = self.get_credential_by_id(&cred_id).await? {
            self.update_credential_counter(&credential, auth_result.counter()).await?;
        }

        self.delete_authentication_challenge(challenge_id).await?;
        Ok(true)
    }

    async fn get_existing_credential_descriptors(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<CredentialID>, ApiError> {
        let credentials = self.get_user_credentials(user_id).await?;
        Ok(credentials.into_iter().map(|c| c.credential_id).collect())
    }

    #[allow(clippy::unused_async)]
    async fn get_user_passkeys(&self, _user_id: Uuid) -> Result<Vec<Passkey>, ApiError> {
        Ok(Vec::new())
    }

    #[allow(clippy::unused_async)]
    async fn store_registration_challenge(
        &self,
        _c: &WebAuthnRegistrationChallenge,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn get_registration_challenge(
        &self,
        _id: Uuid,
    ) -> Result<WebAuthnRegistrationChallenge, ApiError> {
        Err(ApiError::BadRequest("Challenge not found".into()))
    }

    #[allow(clippy::unused_async)]
    async fn delete_registration_challenge(&self, _id: Uuid) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn store_authentication_challenge(
        &self,
        _c: &WebAuthnAuthenticationChallenge,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn get_authentication_challenge(
        &self,
        _id: Uuid,
    ) -> Result<WebAuthnAuthenticationChallenge, ApiError> {
        Err(ApiError::BadRequest("Challenge not found".into()))
    }

    #[allow(clippy::unused_async)]
    async fn delete_authentication_challenge(&self, _id: Uuid) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn store_credential(&self, _c: &WebAuthnCredential) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn get_credential_by_id(
        &self,
        _id: &[u8],
    ) -> Result<Option<WebAuthnCredential>, ApiError> {
        Ok(None)
    }

    #[allow(clippy::unused_async)]
    async fn update_credential_counter(
        &self,
        _c: &WebAuthnCredential,
        _cnt: u32,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn update_credential_count(&self, _user_id: Uuid) -> Result<(), ApiError> {
        Ok(())
    }

    /// Get settings
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if retrieval fails.
    #[allow(clippy::unused_async)]
    pub async fn get_settings(&self, _user_id: Uuid) -> Result<Option<WebAuthnSettings>, ApiError> {
        Ok(None)
    }

    /// Get user credentials
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if retrieval fails.
    #[allow(clippy::unused_async)]
    pub async fn get_user_credentials(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<WebAuthnCredential>, ApiError> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl MfaMethod for WebAuthnProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        let (challenge_id, _) = self.start_authentication(user_id).await?;
        Ok(challenge_id.to_string())
    }

    async fn complete_verification(
        &self,
        _user_id: Uuid,
        v_id: &str,
        code: &str,
    ) -> Result<bool, ApiError> {
        let challenge_id =
            Uuid::parse_str(v_id).map_err(|_| ApiError::BadRequest("Invalid ID".into()))?;
        let response: PublicKeyCredential = serde_json::from_str(code)
            .map_err(|e| ApiError::BadRequest(format!("Invalid JSON: {e}")))?;
        self.complete_authentication(challenge_id, &response).await
    }

    fn get_method_name(&self) -> &'static str {
        "webauthn"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webauthn_settings() {
        let user_id = Uuid::new_v4();
        let settings = WebAuthnSettings {
            user_id,
            enabled: true,
            credential_count: 2,
        };
        assert_eq!(settings.user_id, user_id);
    }

    #[test]
    fn test_provider_creation() {
        let config = AppConfig::default();
        let provider = WebAuthnProvider::new(&config);
        assert!(provider.is_ok());
    }
}
