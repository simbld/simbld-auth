//! # Push Notification-based Multi-Factor Authentication
//!
//! This module provides push notification verification for multifactor authentication.
//! It sends push notifications to a mobile app and verifies the response.

use crate::auth::mfa::MfaMethod;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::{ApiError, AppConfig};

/// Provider for push-notification-based MFA
pub struct PushMfaProvider {
    /// Push notification service client
    push_client: Box<dyn PushClient>,

    /// Notification expiration time in seconds
    expiration_seconds: u64,
}

/// Push notification verification information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushVerification {
    /// Unique identifier for this verification attempt
    pub id: Uuid,

    /// User ID
    pub user_id: Uuid,

    /// When the verification was created
    pub created_at: DateTime<Utc>,

    /// When the verification expires
    pub expires_at: DateTime<Utc>,

    /// Verification status
    pub status: PushVerificationStatus,

    /// Device ID that received the notification
    pub device_id: String,
}

/// Push verification status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PushVerificationStatus {
    /// Verification is pending user response
    Pending,

    /// User approved the verification
    Approved,

    /// User rejected the verification
    Rejected,

    /// Verification expired with no response
    Expired,
}

/// Push notification device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushDevice {
    /// Unique identifier
    pub id: Uuid,

    /// User ID
    pub user_id: Uuid,

    /// Device name
    pub name: String,

    /// Device token for push notifications
    pub token: String,

    /// Device type
    pub device_type: DeviceType,

    /// When the device was registered
    pub created_at: DateTime<Utc>,

    /// Last used timestamp
    pub last_used: Option<DateTime<Utc>>,
}

/// Device type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeviceType {
    /// iOS device
    IOs,

    /// Android-powered device
    Android,

    /// Web browser
    Web,

    /// Another device type
    Other,
}

/// Settings for push notification MFA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMfaSettings {
    /// User ID
    pub user_id: Uuid,

    /// Whether push notification MFA is enabled
    pub enabled: bool,

    /// Registered devices count
    pub device_count: usize,
}

/// Push client trait for sending notifications
#[async_trait]
pub trait PushClient: Send + Sync {
    /// Send a push notification
    async fn send_notification(
        &self,
        device: &PushDevice,
        message: &PushMessage,
    ) -> Result<(), ApiError>;
}

/// Push notification message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMessage {
    /// Message title
    pub title: String,

    /// Message body
    pub body: String,

    /// Data payload
    pub data: serde_json::Value,
}

impl PushMfaProvider {
    /// Create a new push notification MFA provider
    #[must_use]
    pub fn new(config: &AppConfig, push_client: Box<dyn PushClient>) -> Self {
        Self {
            push_client,
            expiration_seconds: config.mfa.push_expiration_seconds,
        }
    }

    /// Create a new verification and send a push notification
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if no devices are registered or notification sending fails.
    pub async fn create_verification(&self, user_id: Uuid) -> Result<Uuid, ApiError> {
        let devices = self.get_user_devices(user_id).await?;

        if devices.is_empty() {
            return Err(ApiError::BadRequest("No devices registered for push notification".into()));
        }

        let verification_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.expiration_seconds.cast_signed());

        let device = &devices[0];

        let verification = PushVerification {
            id: verification_id,
            user_id,
            created_at: now,
            expires_at,
            status: PushVerificationStatus::Pending,
            device_id: device.id.to_string(),
        };

        self.store_verification(&verification).await?;

        let data = serde_json::json!({
            "verification_id": verification_id.to_string(),
            "expires_at": expires_at.to_rfc3339(),
            "type": "mfa_verification"
        });

        let message = PushMessage {
            title: "Verify your login".to_string(),
            body: "Tap to verify it's you logging in".to_string(),
            data,
        };

        self.push_client.send_notification(device, &message).await?;

        Ok(verification_id)
    }

    /// Check verification status
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if verification retrieval fails.
    pub async fn check_verification(
        &self,
        verification_id: Uuid,
    ) -> Result<PushVerificationStatus, ApiError> {
        let verification = self.get_verification(verification_id).await?;

        let now = Utc::now();
        if verification.expires_at < now && verification.status == PushVerificationStatus::Pending {
            self.update_verification_status(verification_id, PushVerificationStatus::Expired)
                .await?;
            return Ok(PushVerificationStatus::Expired);
        }

        Ok(verification.status)
    }

    /// Update verification status (called by the mobile app)
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if verification is expired or already completed.
    pub async fn update_verification_status(
        &self,
        verification_id: Uuid,
        status: PushVerificationStatus,
    ) -> Result<(), ApiError> {
        let verification = self.get_verification(verification_id).await?;

        if verification.status != PushVerificationStatus::Pending {
            return Err(ApiError::BadRequest("Verification is already completed".into()));
        }

        let now = Utc::now();
        if verification.expires_at < now {
            self.update_verification(verification_id, PushVerificationStatus::Expired).await?;
            return Err(ApiError::BadRequest("Verification has expired".into()));
        }

        self.update_verification(verification_id, status).await?;

        if status == PushVerificationStatus::Approved {
            self.update_device_last_used(&verification.device_id).await?;
        }

        Ok(())
    }

    /// Register a new device
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if storage fails.
    pub async fn register_device(
        &self,
        user_id: Uuid,
        name: &str,
        token: &str,
        device_type: DeviceType,
    ) -> Result<Uuid, ApiError> {
        if let Some(existing_device) = self.get_device_by_token(token).await? {
            if existing_device.user_id == user_id {
                self.update_device(&existing_device.id, name, token, device_type).await?;
                return Ok(existing_device.id);
            }
            return Err(ApiError::BadRequest("Token registered to another user".into()));
        }

        let device_id = Uuid::new_v4();
        let now = Utc::now();

        let device = PushDevice {
            id: device_id,
            user_id,
            name: name.to_string(),
            token: token.to_string(),
            device_type,
            created_at: now,
            last_used: None,
        };

        self.store_device(&device).await?;
        self.update_device_count(user_id).await?;

        Ok(device_id)
    }

    /// Get all devices for a user
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if retrieval fails.
    #[allow(clippy::unused_async)]
    pub async fn get_user_devices(&self, _u_id: Uuid) -> Result<Vec<PushDevice>, ApiError> {
        Ok(Vec::new())
    }

    /// Get push MFA settings
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if retrieval fails.
    #[allow(clippy::unused_async)]
    pub async fn get_settings(&self, _u_id: Uuid) -> Result<Option<PushMfaSettings>, ApiError> {
        Ok(None)
    }

    #[allow(clippy::unused_async)]
    async fn get_device_by_token(&self, _t: &str) -> Result<Option<PushDevice>, ApiError> {
        Ok(None)
    }

    #[allow(clippy::unused_async)]
    async fn store_device(&self, _d: &PushDevice) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn update_device(
        &self,
        _id: &Uuid,
        _n: &str,
        _t: &str,
        _dt: DeviceType,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn update_device_last_used(&self, _d_id: &str) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn update_device_count(&self, _u_id: Uuid) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn store_verification(&self, _v: &PushVerification) -> Result<(), ApiError> {
        Ok(())
    }

    #[allow(clippy::unused_async)]
    async fn get_verification(&self, _id: Uuid) -> Result<PushVerification, ApiError> {
        Err(ApiError::BadRequest("Verification not found".into()))
    }

    #[allow(clippy::unused_async)]
    async fn update_verification(
        &self,
        _id: Uuid,
        _s: PushVerificationStatus,
    ) -> Result<(), ApiError> {
        Ok(())
    }

    /// Delete a device
    ///
    /// # Errors
    ///
    /// Returns [`ApiError`] if deletion fails.
    pub async fn delete_device(&self, _d_id: Uuid, user_id: Uuid) -> Result<(), ApiError> {
        self.update_device_count(user_id).await?;
        Ok(())
    }
}

#[async_trait]
impl MfaMethod for PushMfaProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        let verification_id = self.create_verification(user_id).await?;
        Ok(verification_id.to_string())
    }

    async fn complete_verification(
        &self,
        _u_id: Uuid,
        v_id: &str,
        _c: &str,
    ) -> Result<bool, ApiError> {
        let v_uuid = Uuid::parse_str(v_id)
            .map_err(|_| ApiError::BadRequest("Invalid verification ID".into()))?;

        let status = self.check_verification(v_uuid).await?;

        match status {
            PushVerificationStatus::Approved => Ok(true),
            PushVerificationStatus::Rejected => Ok(false),
            PushVerificationStatus::Expired => {
                Err(ApiError::BadRequest("Verification expired".into()))
            },
            PushVerificationStatus::Pending => {
                Err(ApiError::BadRequest("Verification pending".into()))
            },
        }
    }

    fn get_method_name(&self) -> &'static str {
        "push"
    }
}

/// Basic implementation of a push client for Firebase Cloud Messaging (FCM)
pub struct FcmPushClient {
    api_key: String,
    http_client: reqwest::Client,
}

impl FcmPushClient {
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PushClient for FcmPushClient {
    async fn send_notification(
        &self,
        device: &PushDevice,
        msg: &PushMessage,
    ) -> Result<(), ApiError> {
        let payload = serde_json::json!({
            "to": device.token,
            "notification": { "title": msg.title, "body": msg.body },
            "data": msg.data
        });

        let res = self
            .http_client
            .post("https://fcm.googleapis.com/fcm/send")
            .header("Authorization", format!("key={}", self.api_key))
            .header("Content-Type", "app/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| ApiError::Internal {
                message: format!("FCM error: {e}"),
            })?;

        if !res.status().is_success() {
            return Err(ApiError::Internal {
                message: "FCM rejected notification".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct MockPushClient {
        sent_notifications: Arc<Mutex<Vec<(PushDevice, PushMessage)>>>,
        should_fail: bool,
    }

    impl MockPushClient {
        fn new() -> Self {
            Self {
                sent_notifications: Arc::new(Mutex::new(Vec::new())),
                should_fail: false,
            }
        }
        #[allow(dead_code)]
        fn with_error() -> Self {
            let mut client = Self::new();
            client.should_fail = true;
            client
        }
        #[allow(dead_code)]
        fn get_sent_notifications(&self) -> Vec<(PushDevice, PushMessage)> {
            self.sent_notifications.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl PushClient for MockPushClient {
        async fn send_notification(&self, d: &PushDevice, m: &PushMessage) -> Result<(), ApiError> {
            if self.should_fail {
                return Err(ApiError::Internal {
                    message: "Mock failure".into(),
                });
            }
            self.sent_notifications.lock().unwrap().push((d.clone(), m.clone()));
            Ok(())
        }
    }

    #[test]
    fn test_provider_creation() {
        let push_client = Box::new(MockPushClient::new());
        let provider = PushMfaProvider {
            push_client,
            expiration_seconds: 300,
        };
        assert_eq!(provider.expiration_seconds, 300);
    }

    #[test]
    fn test_method_name() {
        let push_client = Box::new(MockPushClient::new());
        let provider = PushMfaProvider {
            push_client,
            expiration_seconds: 300,
        };
        assert_eq!(provider.get_method_name(), "push");
    }

    #[test]
    fn test_push_verification_status() {
        assert_eq!(PushVerificationStatus::Pending, PushVerificationStatus::Pending);
        assert_ne!(PushVerificationStatus::Approved, PushVerificationStatus::Rejected);

        let user_id = Uuid::new_v4();
        let verification = PushVerification {
            id: Uuid::new_v4(),
            user_id,
            created_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::seconds(300),
            status: PushVerificationStatus::Pending,
            device_id: "device123".to_string(),
        };
        assert_eq!(verification.status, PushVerificationStatus::Pending);
    }

    #[test]
    fn test_push_device_creation() {
        let user_id = Uuid::new_v4();
        let device = PushDevice {
            id: Uuid::new_v4(),
            user_id,
            name: "Test Phone".to_string(),
            token: "fcm-token-123".to_string(),
            device_type: DeviceType::Android,
            created_at: Utc::now(),
            last_used: None,
        };
        assert_eq!(device.name, "Test Phone");
        assert_eq!(device.device_type, DeviceType::Android);
    }

    #[test]
    fn test_fcm_client_creation() {
        let client = FcmPushClient {
            api_key: "test-api-key".to_string(),
            http_client: reqwest::Client::new(),
        };
        assert_eq!(client.api_key, "test-api-key");
    }
}
