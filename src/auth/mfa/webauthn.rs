//! # WebAuthn (FIDO2/U2F) Multi-Factor Authentication
//!
//! This module provides WebAuthn capabilities for authenticating with security keys,
//! biometrics, and platform authenticators like Windows Hello, Touch ID, etc.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use webauthn_rs::{
    prelude::*,
    error::WebauthnError,
};

use crate::auth::mfa::MfaMethod;
use crate::config::AppConfig;
use crate::errors::ApiError;

/// Provider for WebAuthn-based MFA
#[derive(Clone)]
pub struct WebAuthnProvider {
    /// WebAuthn implementation
    webauthn: Webauthn,
}

/// WebAuthn credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnCredential {
    /// Unique identifier
    pub id: Uuid,

    /// User ID
    pub user_id: Uuid,

    /// Credential ID
    pub credential_id: CredentialID,

    /// Credential public key
    pub public_key: PublicKeyCredential,

    /// Credential counter (for anti-replay)
    pub counter: u32,

    /// User-friendly credential name
    pub name: String,

    /// When the credential was registered
    pub created_at: DateTime<Utc>,

    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// Settings for WebAuthn
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnSettings {
    /// User ID
    pub user_id: Uuid,

    /// Whether WebAuthn is enabled
    pub enabled: bool,

    /// Registered credentials count
    pub credential_count: usize,
}

/// Registration challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnRegistrationChallenge {
    /// Unique identifier
    pub id: Uuid,

    /// User ID
    pub user_id: Uuid,

    /// Registration state
    #[serde(skip_serializing, skip_deserializing)]
    pub state: PasskeyRegistration,

    /// When the challenge was created
    pub created_at: DateTime<Utc>,

    /// Challenge expiry time
    pub expires_at: DateTime<Utc>,
}

/// Authentication challenge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAuthenticationChallenge {
    /// Unique identifier
    pub id: Uuid,

    /// User ID
    pub user_id: Uuid,

    /// Authentication state
    #[serde(skip_serializing, skip_deserializing)]
    pub state: PasskeyAuthentication,

    /// When the challenge was created
    pub created_at: DateTime<Utc>,

    /// Challenge expiry time
    pub expires_at: DateTime<Utc>,
}

impl WebAuthnProvider {
    /// Create a new WebAuthn provider
    pub fn new(config: &AppConfig) -> Result<Self, WebauthnError> {
        // Create a WebAuthn implementation with the proper configuration
        let rp_id = config.webauthn.rp_id.clone().unwrap_or_else(|| "example.com".to_string());
        let rp_name = config.webauthn.rp_name.clone().unwrap_or_else(|| "Example Application".to_string());
        let rp_origin = config.webauthn.rp_origin.clone().unwrap_or_else(|| "https://example.com".to_string());

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name(&rp_name);

        let webauthn = builder.build()?;

        Ok(Self { webauthn })
    }

    /// Start registration for a new credential
    pub async fn start_registration(&self, user_id: Uuid, username: &str, display_name: &str) -> Result<(Uuid, PublicKeyCredentialCreationOptions), ApiError> {
        // Generate registration options
        let user_id_bytes = user_id.as_bytes().to_vec();
        let exclude_credentials = self.get_existing_credential_descriptors(user_id).await?;

        // Start registration
        let (state, options) = self.webauthn.start_passkey_registration(
            user_id_bytes,
            username,
            display_name,
            exclude_credentials,
        ).map_err(|e| ApiError::new(500, format!("Failed to start WebAuthn registration: {}", e)))?;

        // Create challenge record
        let challenge_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);

        let challenge = WebAuthnRegistrationChallenge {
            id: challenge_id,
            user_id,
            state,
            created_at: now,
            expires_at,
        };

        // Store challenge (in a real app, this would go to a database)
        self.store_registration_challenge(&challenge).await?;

        Ok((challenge_id, options))
    }

    /// Complete registration of a new credential
    pub async fn complete_registration(
        &self,
        challenge_id: Uuid,
        response: &PublicKeyCredentialCreation,
        name: &str,
    ) -> Result<WebAuthnCredential, ApiError> {
        // Get the challenge
        let challenge = self.get_registration_challenge(challenge_id).await?;

        // Check if the challenge has expired
        let now = Utc::now();
        if challenge.expires_at < now {
            return Err(ApiError::new(400, "Registration challenge has expired".to_string()));
        }

        // Complete registration
        let result = self.webauthn.finish_passkey_registration(response, &challenge.state)
            .map_err(|e| ApiError::new(400, format!("Invalid registration response: {}", e)))?;

        // Create credential record
        let credential = WebAuthnCredential {
            id: Uuid::new_v4(),
            user_id: challenge.user_id,
            credential_id: result.cred_id().clone(),
            public_key: result,
            counter: 0,
            name: name.to_string(),
            created_at: now,
            last_used: None,
        };

        // Store credential (in a real app, this would go to a database)
        self.store_credential(&credential).await?;

        // Delete challenge
        self.delete_registration_challenge(challenge_id).await?;

        // Update settings
        self.update_credential_count(challenge.user_id).await?;

        Ok(credential)
    }

    /// Start authentication with a credential
    pub async fn start_authentication(&self, user_id: Uuid) -> Result<(Uuid, PublicKeyCredentialRequestOptions), ApiError> {
        // Get user's credentials
        let allow_credentials = self.get_existing_credential_descriptors(user_id).await?;

        if allow_credentials.is_empty() {
            return Err(ApiError::new(400, "No WebAuthn credentials registered for this user".to_string()));
        }

        // Start authentication
        let (state, options) = self.webauthn.start_passkey_authentication(allow_credentials)
            .map_err(|e| ApiError::new(500, format!("Failed to start WebAuthn authentication: {}", e)))?;

        // Create challenge record
        let challenge_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::minutes(5);

        let challenge = WebAuthnAuthenticationChallenge {
            id: challenge_id,
            user_id,
            state,
            created_at: now,
            expires_at,
        };

        // Store challenge (in a real app, this would go to a database)
        self.store_authentication_challenge(&challenge).await?;

        Ok((challenge_id, options))
    }

    /// Complete authentication with a credential
    pub async fn complete_authentication(
        &self,
        challenge_id: Uuid,
        response: &PublicKeyCredentialRequest,
    ) -> Result<bool, ApiError> {
        // Get the challenge
        let challenge = self.get_authentication_challenge(challenge_id).await?;

        // Check if the challenge has expired
        let now = Utc::now();
        if challenge.expires_at < now {
            return Err(ApiError::new(400, "Authentication challenge has expired".to_string()));
        }

        // Get the credential
        let cred_id = base64::decode(&response.id)
            .map_err(|_| ApiError::new(400, "Invalid credential ID".to_string()))?;

        let credential = self.get_credential_by_id(&cred_id).await?
            .ok_or_else(|| ApiError::new(400, "Unknown credential".to_string()))?;

        // Complete authentication
        let auth_result = self.webauthn.finish_passkey_authentication(
            response,
            &challenge.state,
            credential.counter,
        ).map_err(|e| ApiError::new(400, format!("Invalid authentication response: {}", e)))?;

        // Update credential counter
        self.update_credential_counter(&credential, auth_result.counter).await?;

        // Delete challenge
        self.delete_authentication_challenge(challenge_id).await?;

        Ok(true)
    }

    /// Get existing credential descriptors for a user
    async fn get_existing_credential_descriptors(&self, user_id: Uuid) -> Result<Vec<CredentialDescriptor>, ApiError> {
        // In a real app, you would fetch credentials from your database
        // For this example, we return an empty list
        Ok(Vec::new())
    }

    /// Store a registration challenge (placeholder for actual DB implementation)
    async fn store_registration_challenge(&self, challenge: &WebAuthnRegistrationChallenge) -> Result<(), ApiError> {
        // In a real application, you would store the challenge in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Get a registration challenge (placeholder for actual DB implementation)
    async fn get_registration_challenge(&self, id: Uuid) -> Result<WebAuthnRegistrationChallenge, ApiError> {
        // In a real application, you would retrieve the challenge from your database
        // For this example, we return an error since we don't have a real database
        Err(ApiError::new(404, "Challenge not found".to_string()))
    }

    /// Delete a registration challenge (placeholder for actual DB implementation)
    async fn delete_registration_challenge(&self, id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would delete the challenge from your database
        // For this example, we just pretend it's deleted
        Ok(())
    }

    /// Store an authentication challenge (placeholder for actual DB implementation)
    async fn store_authentication_challenge(&self, challenge: &WebAuthnAuthenticationChallenge) -> Result<(), ApiError> {
        // In a real application, you would store the challenge in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Get an authentication challenge (placeholder for actual DB implementation)
    async fn get_authentication_challenge(&self, id: Uuid) -> Result<WebAuthnAuthenticationChallenge, ApiError> {
        // In a real application, you would retrieve the challenge from your database
        // For this example, we return an error since we don't have a real database
        Err(ApiError::new(404, "Challenge not found".to_string()))
    }

    /// Delete an authentication challenge (placeholder for actual DB implementation)
    async fn delete_authentication_challenge(&self, id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would delete the challenge from your database
        // For this example, we just pretend it's deleted
        Ok(())
    }

    /// Store a credential (placeholder for actual DB implementation)
    async fn store_credential(&self, credential: &WebAuthnCredential) -> Result<(), ApiError> {
        // In a real application, you would store the credential in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Get a credential by its ID (placeholder for actual DB implementation)
    async fn get_credential_by_id(&self, credential_id: &[u8]) -> Result<Option<WebAuthnCredential>, ApiError> {
        // In a real application, you would retrieve the credential from your database
        // For this example, we return None since we don't have a real database
        Ok(None)
    }

    /// Update a credential's counter (placeholder for actual DB implementation)
    async fn update_credential_counter(&self, credential: &WebAuthnCredential, new_counter: u32) -> Result<(), ApiError> {
        // In a real application, you would update the credential in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Update a user's credential count (placeholder for actual DB implementation)
    async fn update_credential_count(&self, user_id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would update the user's settings in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Get WebAuthn settings for a user
    pub async fn get_settings(&self, user_id: Uuid) -> Result<Option<WebAuthnSettings>, ApiError> {
        // In a real application, you would retrieve these settings from your database
        // For this example, we return None since we don't have a real database
        Ok(None)
    }

    /// Get all credentials for a user
    pub async fn get_user_credentials(&self, user_id: Uuid) -> Result<Vec<WebAuthnCredential>, ApiError> {
        // In a real application, you would retrieve credentials from your database
        // For this example, we return an empty list since we don't have a real database
        Ok(Vec::new())
    }

    /// Delete a credential
    pub async fn delete_credential(&self, credential_id: Uuid, user_id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would delete the credential from your database
        // For this example, we just pretend it's deleted

        // Update credential count
        self.update_credential_count(user_id).await?;

        Ok(())
    }
}

/// Implement MFA method trait for WebAuthn
#[async_trait]
impl MfaMethod for WebAuthnProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        // Start WebAuthn authentication
        let (challenge_id, _options) = self.start_authentication(user_id).await?;

        // Return challenge ID as a string
        Ok(challenge_id.to_string())
    }

    async fn complete_verification(&self, _user_id: Uuid, verification_id: &str, code: &str) -> Result<bool, ApiError> {
        // Convert verification ID from string to UUID
        let challenge_id = Uuid::parse_str(verification_id)
            .map_err(|_| ApiError::new(400, "Invalid verification ID".to_string()))?;

        // Parse response from JSON
        let response: PublicKeyCredentialRequest = serde_json::from_str(code)
            .map_err(|e| ApiError::new(400, format!("Invalid WebAuthn response: {}", e)))?;

        // Complete authentication
        self.complete_authentication(challenge_id, &response).await
    }

    fn get_method_name(&self) -> &'static str {
        "webauthn"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use webauthn_rs::prelude::*;

    // Test WebAuthn settings
    #[test]
    fn test_webauthn_settings() {
        let user_id = Uuid::new_v4();
        let settings = WebAuthnSettings {
            user_id,
            enabled: true,
            credential_count: 2,
        };

        assert_eq!(settings.user_id, user_id);
        assert!(settings.enabled);
        assert_eq!(settings.credential_count, 2);
    }

    // Test WebAuthn credential creation
    #[test]
    fn test_webauthn_credential_creation() {
        let user_id = Uuid::new_v4();
        let credential_id = CredentialID::from(vec![1, 2, 3, 4]);
        let public_key = PublicKeyCredential::from_es256_key(
            vec![5, 6, 7, 8],
            ES256Key::from_pkcs8(&vec![9, 10, 11, 12]).unwrap()
        ).unwrap();

        let credential = WebAuthnCredential {
            id: Uuid::new_v4(),
            user_id,
            credential_id,
            public_key,
            counter: 0,
            name: "My Security Key".to_string(),
            created_at: Utc::now(),
            last_used: None,
        };

        assert_eq!(credential.user_id, user_id);
        assert_eq!(credential.counter, 0);
        assert_eq!(credential.name, "My Security Key");
        assert!(credential.last_used.is_none());
    }

    // Test WebAuthn registration challenge
    #[test]
    fn test_webauthn_registration_challenge() {
        let user_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let now = Utc::now();
        let expires = now + Duration::minutes(5);

        // Create RPID for test
        let rp_id = "example.com".to_string();
        let rp_name = "Example Service".to_string();
        let rp_origin = Url::parse("https://example.com").unwrap();

        // Create a challenge
        let challenge = Challenge::new(vec![1, 2, 3, 4]);

        // Create a user entity
        let user_entity = webauthn_rs::prelude::UserVerificationPolicy::Required;

        // Create a registration state (simplified for test)
        let registration_state = PasskeyRegistration::new(
            user_entity,
            challenge,
        );

        let challenge = WebAuthnRegistrationChallenge {
            id: challenge_id,
            user_id,
            state: registration_state,
            created_at: now,
            expires_at: expires,
        };

        assert_eq!(challenge.id, challenge_id);
        assert_eq!(challenge.user_id, user_id);
        assert_eq!(challenge.created_at, now);
        assert_eq!(challenge.expires_at, expires);
    }

    // Test WebAuthn authentication challenge
    #[test]
    fn test_webauthn_authentication_challenge() {
        let user_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let now = Utc::now();
        let expires = now + Duration::minutes(5);

        // Create a challenge
        let challenge = Challenge::new(vec![1, 2, 3, 4]);

        // Create allowed credentials
        let allowed_credentials = vec![
            CredentialDescriptor {
                cred_id: CredentialID::from(vec![5, 6, 7, 8]),
                transports: None,
            }
        ];

        // Create an authentication state (simplified for test)
        let authentication_state = PasskeyAuthentication::new(
            challenge,
            allowed_credentials,
        );

        let challenge = WebAuthnAuthenticationChallenge {
            id: challenge_id,
            user_id,
            state: authentication_state,
            created_at: now,
            expires_at: expires,
        };

        assert_eq!(challenge.id, challenge_id);
        assert_eq!(challenge.user_id, user_id);
        assert_eq!(challenge.created_at, now);
        assert_eq!(challenge.expires_at, expires);
    }

    // Test WebAuthn provider creation
    #[test]
    fn test_webauthn_provider_creation() {
        // Create a webauthn config for testing
        let rp_id = "example.com".to_string();
        let rp_origin = url::Url::parse("https://example.com").unwrap();

        let builder = WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("Failed to create WebauthnBuilder");

        let webauthn = builder.build()
            .expect("Failed to build Webauthn");

        let provider = WebAuthnProvider {
            webauthn,
        };

        // Since Webauthn doesn't implement PartialEq, we can only test that creation works
        assert!(true);
    }

    // Test valid credential expiration
    #[test]
    fn test_challenge_expiration() {
        let user_id = Uuid::new_v4();
        let challenge_id = Uuid::new_v4();
        let now = Utc::now();

        // Create an expired challenge
        let expired_time = now - Duration::minutes(10);

        // Create a challenge
        let challenge = Challenge::new(vec![1, 2, 3, 4]);

        // Create a user entity
        let user_entity = webauthn_rs::prelude::UserVerificationPolicy::Required;

        // Create a registration state
        let registration_state = PasskeyRegistration::new(
            user_entity,
            challenge,
        );

        let expired_challenge = WebAuthnRegistrationChallenge {
            id: challenge_id,
            user_id,
            state: registration_state,
            created_at: expired_time,
            expires_at: expired_time + Duration::minutes(5),
        };

        // Check that the challenge is expired
        assert!(Utc::now() > expired_challenge.expires_at);
    }

    // Test method name implementation
    #[tokio::test]
    async fn test_method_name() {
        // Create a webauthn config for testing
        let rp_id = "example.com".to_string();
        let rp_origin = url::Url::parse("https://example.com").unwrap();

        let builder = WebauthnBuilder::new(rp_id, &rp_origin)
            .expect("Failed to create WebauthnBuilder");

        let webauthn = builder.build()
            .expect("Failed to build Webauthn");

        let provider = WebAuthnProvider {
            webauthn,
        };

        // Test the method name
        assert_eq!(provider.get_method_name(), "webauthn");
    }
}