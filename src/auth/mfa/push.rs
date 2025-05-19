//! # Push Notification-based Multi-Factor Authentication
//!
//! This module provides push notification verification for multi-factor authentication.
//! It sends push notifications to a mobile app and verifies the response.

use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::auth::mfa::MfaMethod;
use crate::config::AppConfig;
use crate::errors::ApiError;

/// Provider for push notification-based MFA
#[derive(Debug, Clone)]
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
    iOS,

    /// Android device
    Android,

    /// Web browser
    Web,

    /// Other device type
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
    async fn send_notification(&self, device: &PushDevice, message: &PushMessage) -> Result<(), ApiError>;
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
    pub fn new(config: &AppConfig, push_client: Box<dyn PushClient>) -> Self {
        Self {
            push_client,
            expiration_seconds: config.mfa.push_expiration_seconds.unwrap_or(60), // 1 minute default
        }
    }

    /// Create a new verification and send push notification
    pub async fn create_verification(&self, user_id: Uuid) -> Result<Uuid, ApiError> {
        // Get user's devices
        let devices = self.get_user_devices(user_id).await?;

        if devices.is_empty() {
            return Err(ApiError::new(400, "No devices registered for push notification".to_string()));
        }

        // Create verification record
        let verification_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(self.expiration_seconds as i64);

        // For this example, we'll use the first device
        let device = &devices[0];

        let verification = PushVerification {
            id: verification_id,
            user_id,
            created_at: now,
            expires_at,
            status: PushVerificationStatus::Pending,
            device_id: device.id.to_string(),
        };

        // Store verification (in a real app, this would go to a database)
        self.store_verification(&verification).await?;

        // Create notification
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

        // Send notification
        self.push_client.send_notification(device, &message).await?;

        Ok(verification_id)
    }

    /// Check verification status
    pub async fn check_verification(&self, verification_id: Uuid) -> Result<PushVerificationStatus, ApiError> {
        // Get verification
        let verification = self.get_verification(verification_id).await?;

        // Check if expired
        let now = Utc::now();
        if verification.expires_at < now && verification.status == PushVerificationStatus::Pending {
            // Update verification status
            self.update_verification_status(verification_id, PushVerificationStatus::Expired).await?;
            return Ok(PushVerificationStatus::Expired);
        }

        Ok(verification.status)
    }

    /// Update verification status (called by the mobile app)
    pub async fn update_verification_status(&self, verification_id: Uuid, status: PushVerificationStatus) -> Result<(), ApiError> {
        // Get verification
        let verification = self.get_verification(verification_id).await?;

        // Check if already completed or expired
        if verification.status != PushVerificationStatus::Pending {
            return Err(ApiError::new(400, "Verification is already completed or expired".to_string()));
        }

        // Check if expired
        let now = Utc::now();
        if verification.expires_at < now {
            // Update verification status to expired
            self.update_verification(verification_id, PushVerificationStatus::Expired).await?;
            return Err(ApiError::new(400, "Verification has expired".to_string()));
        }

        // Update verification status
        self.update_verification(verification_id, status).await?;

        // Update device last_used if approved
        if status == PushVerificationStatus::Approved {
            self.update_device_last_used(&verification.device_id).await?;
        }

        Ok(())
    }

    /// Register a new device
    pub async fn register_device(&self, user_id: Uuid, name: &str, token: &str, device_type: DeviceType) -> Result<Uuid, ApiError> {
        // Check if device with this token already exists
        if let Some(existing_device) = self.get_device_by_token(token).await? {
            // If the device already belongs to this user, just update it
            if existing_device.user_id == user_id {
                self.update_device(&existing_device.id, name, token, device_type).await?;
                return Ok(existing_device.id);
            } else {
                // Device token belongs to another user, this shouldn't happen
                return Err(ApiError::new(400, "Device token already registered to another user".to_string()));
            }
        }

        // Create new device
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

        // Store device (in a real app, this would go to a database)
        self.store_device(&device).await?;

        // Update device count
        self.update_device_count(user_id).await?;

        Ok(device_id)
    }

    /// Get all devices for a user
    pub async fn get_user_devices(&self, user_id: Uuid) -> Result<Vec<PushDevice>, ApiError> {
        // In a real application, you would retrieve these devices from your database
        // For this example, we return an empty list since we don't have a real database
        Ok(Vec::new())
    }

    /// Get push MFA settings for a user
    pub async fn get_settings(&self, user_id: Uuid) -> Result<Option<PushMfaSettings>, ApiError> {
        // In a real application, you would retrieve these settings from your database
        // For this example, we return None since we don't have a real database
        Ok(None)
    }

    /// Get a device by its token
    async fn get_device_by_token(&self, token: &str) -> Result<Option<PushDevice>, ApiError> {
        // In a real application, you would retrieve this device from your database
        // For this example, we return None since we don't have a real database
        Ok(None)
    }

    /// Store a device (placeholder for actual DB implementation)
    async fn store_device(&self, device: &PushDevice) -> Result<(), ApiError> {
        // In a real application, you would store the device in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Update a device (placeholder for actual DB implementation)
    async fn update_device(&self, device_id: &Uuid, name: &str, token: &str, device_type: DeviceType) -> Result<(), ApiError> {
        // In a real application, you would update the device in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Update a device's last_used timestamp (placeholder for actual DB implementation)
    async fn update_device_last_used(&self, device_id: &str) -> Result<(), ApiError> {
        // In a real application, you would update the device in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Update a user's device count (placeholder for actual DB implementation)
    async fn update_device_count(&self, user_id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would update the user's settings in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Store a verification (placeholder for actual DB implementation)
    async fn store_verification(&self, verification: &PushVerification) -> Result<(), ApiError> {
        // In a real application, you would store the verification in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Get a verification (placeholder for actual DB implementation)
    async fn get_verification(&self, verification_id: Uuid) -> Result<PushVerification, ApiError> {
        // In a real application, you would retrieve the verification from your database
        // For this example, we return an error since we don't have a real database
        Err(ApiError::new(404, "Verification not found".to_string()))
    }

    /// Update a verification (placeholder for actual DB implementation)
    async fn update_verification(&self, verification_id: Uuid, status: PushVerificationStatus) -> Result<(), ApiError> {
        // In a real application, you would update the verification in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Delete a device
    pub async fn delete_device(&self, device_id: Uuid, user_id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would delete the device from your database
        // For this example, we just pretend it's deleted

        // Update device count
        self.update_device_count(user_id).await?;

        Ok(())
    }
}

/// Implement MFA method trait for push notifications
#[async_trait]
impl MfaMethod for PushMfaProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        // Create verification and send push notification
        let verification_id = self.create_verification(user_id).await?;

        // Return verification ID as a string
        Ok(verification_id.to_string())
    }

    async fn complete_verification(&self, _user_id: Uuid, verification_id: &str, _code: &str) -> Result<bool, ApiError> {
        // Parse verification ID from string
        let verification_id = Uuid::parse_str(verification_id)
            .map_err(|_| ApiError::new(400, "Invalid verification ID".to_string()))?;

        // Check verification status
        let status = self.check_verification(verification_id).await?;

        match status {
            PushVerificationStatus::Approved => Ok(true),
            PushVerificationStatus::Rejected => Ok(false),
            PushVerificationStatus::Expired => Err(ApiError::new(400, "Verification has expired".to_string())),
            PushVerificationStatus::Pending => Err(ApiError::new(400, "Verification is still pending".to_string())),
        }
    }

    fn get_method_name(&self) -> &'static str {
        "push"
    }
}

/// Basic implementation of push client for Firebase Cloud Messaging (FCM)
pub struct FcmPushClient {
    /// FCM API key
    api_key: String,

    /// HTTP client
    http_client: reqwest::Client,
}

impl FcmPushClient {
    /// Create a new FCM push client
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl PushClient for FcmPushClient {
    async fn send_notification(&self, device: &PushDevice, message: &PushMessage) -> Result<(), ApiError> {
        // Build FCM payload
        let payload = match device.device_type {
            DeviceType::iOS => {
                serde_json::json!({
                    "to": device.token,
                    "notification": {
                        "title": message.title,
                        "body": message.body,
                        "sound": "default"
                    },
                    "data": message.data,
                    "priority": "high",
                    "content_available": true
                })
            },
            DeviceType::Android => {
                serde_json::json!({
                    "to": device.token,
                    "notification": {
                        "title": message.title,
                        "body": message.body
                    },
                    "data": message.data,
                    "priority": "high"
                })
            },
            _ => {
                // Web or other device types use generic format
                serde_json::json!({
                    "to": device.token,
                    "notification": {
                        "title": message.title,
                        "body": message.body
                    },
                    "data": message.data
                })
            }
        };

        // Send to FCM
        let res = self.http_client
            .post("https://fcm.googleapis.com/fcm/send")
            .header("Authorization", format!("key={}", self.api_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| ApiError::new(500, format!("Failed to send push notification: {}", e)))?;

        // Check response
        if !res.status().is_success() {
            let error_message = res.text().await
                .unwrap_or_else(|_| "Unknown error".to_string());

            return Err(ApiError::new(500, format!("FCM rejected push notification: {}", error_message)));
        }

        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::{Arc, Mutex};
        use chrono::Utc;

        // Mock implementation for push notification client
        #[derive(Clone)]
        struct MockPushClient {
            sent_notifications: Arc<Mutex<Vec<(PushDevice, PushMessage)>>>,
            should_fail: bool,
        }

        impl MockPushClient {
            fn new() -> Self {
                MockPushClient {
                    sent_notifications: Arc::new(Mutex::new(Vec::new())),
                    should_fail: false,
                }
            }

            fn with_error() -> Self {
                let mut client = Self::new();
                client.should_fail = true;
                client
            }

            fn get_sent_notifications(&self) -> Vec<(PushDevice, PushMessage)> {
                self.sent_notifications.lock().unwrap().clone()
            }
        }

        #[async_trait]
        impl PushClient for MockPushClient {
            async fn send_notification(&self, device: &PushDevice, message: &PushMessage) -> Result<(), ApiError> {
                if self.should_fail {
                    return Err(ApiError::ExternalServiceError("Simulated push notification failure".to_string()));
                }

                self.sent_notifications.lock().unwrap().push((
                    device.clone(),
                    message.clone(),
                ));

                Ok(())
            }
        }

        // Test for provider creation
        #[test]
        fn test_provider_creation() {
            let push_client = Box::new(MockPushClient::new());
            let provider = PushMfaProvider {
                push_client,
                expiration_seconds: 300,
            };

            assert_eq!(provider.expiration_seconds, 300);
        }

        // Test for method name
        #[test]
        fn test_method_name() {
            let push_client = Box::new(MockPushClient::new());
            let provider = PushMfaProvider {
                push_client,
                expiration_seconds: 300,
            };

            assert_eq!(provider.get_method_name(), "push");
        }

        // Test for verification status
        #[test]
        fn test_push_verification_status() {
            // Check that statuses can be compared correctly
            assert_eq!(PushVerificationStatus::Pending, PushVerificationStatus::Pending);
            assert_ne!(PushVerificationStatus::Approved, PushVerificationStatus::Rejected);

            // Create a verification
            let user_id = Uuid::new_v4();
            let verification = PushVerification {
                id: Uuid::new_v4(),
                user_id,
                created_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::seconds(300),
                status: PushVerificationStatus::Pending,
                device_id: "device123".to_string(),
            };

            // Verify that initial status is Pending
            assert_eq!(verification.status, PushVerificationStatus::Pending);
        }

        // Test for push device creation
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
            assert_eq!(device.last_used, None);
        }

        // Test for FcmPushClient creation
        #[test]
        fn test_fcm_client_creation() {
            let client = FcmPushClient {
                api_key: "test-api-key".to_string(),
                http_client: reqwest::Client::new(),
            };

            assert_eq!(client.api_key, "test-api-key");
        }
    }
}