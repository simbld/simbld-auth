//! # SMS-based Multi-Factor Authentication
//!
//! This module provides SMS-based verification for multi-factor authentication.
//! It generates random codes, sends them via SMS, and verifies them.

use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::types::{ApiError, AppConfig};

/// Provider for SMS-based MFA
#[derive(Debug, Clone)]
pub struct SmsMfaProvider {
    /// SMS service client
    sms_client: Box<dyn SmsClient>,

    /// Code expiration time in seconds
    expiration_seconds: u64,

    /// Number of digits in the verification code
    code_length: usize,
}

/// SMS verification code information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsCode {
    /// Unique identifier for this verification attempt
    pub id: Uuid,

    /// The verification code (typically 6 digits)
    pub code: String,

    /// Phone number the code was sent to
    pub phone_number: String,

    /// When the code was created
    pub created_at: SystemTime,

    /// When the code expires
    pub expires_at: SystemTime,

    /// Whether the code has been used
    pub used: bool,
}

/// Settings for SMS MFA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsMfaSettings {
    /// User ID
    pub user_id: Uuid,

    /// User's phone number
    pub phone_number: String,

    /// Whether SMS MFA is enabled
    pub enabled: bool,
}

impl SmsMfaProvider {
    /// Create a new SMS MFA provider
    pub fn new(config: &AppConfig, sms_client: Box<dyn SmsClient>) -> Self {
        Self {
            sms_client,
            expiration_seconds: config.mfa.sms_code_expiration_seconds.unwrap_or(300), // 5 minutes default
            code_length: config.mfa.sms_code_length.unwrap_or(6),
        }
    }

    /// Generate a random verification code
    fn generate_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let mut code = String::new();

        for _ in 0..self.code_length {
            code.push(char::from_digit(rng.gen_range(0..10) as u32, 10).unwrap());
        }

        code
    }

    /// Create a new verification code and send it via SMS
    pub async fn create_verification(&self, phone_number: &str) -> Result<Uuid, ApiError> {
        // Generate verification code
        let code = self.generate_code();
        let id = Uuid::new_v4();
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.expiration_seconds);

        // Create code record (would typically be stored in a database)
        let sms_code = SmsCode {
            id,
            code: code.clone(),
            phone_number: phone_number.to_string(),
            created_at: now,
            expires_at,
            used: false,
        };

        // Store code in database (this would be an actual DB call in a real app)
        self.store_code(&sms_code).await?;

        // Send SMS
        let message = format!(
            "Your verification code is: {}. It expires in {} minutes.",
            code,
            self.expiration_seconds / 60
        );

        self.sms_client
            .send_sms(phone_number, &message)
            .await
            .map_err(|e| ApiError::new(500, format!("Failed to send SMS: {}", e)))?;

        Ok(id)
    }

    /// Verify a code
    pub async fn verify_code(&self, verification_id: Uuid, code: &str) -> Result<bool, ApiError> {
        // Retrieve code from database (this would be a DB call in a real app)
        let sms_code = self.get_code(verification_id).await?;

        // Check if code is expired
        let now = SystemTime::now();
        if sms_code.expires_at < now {
            return Ok(false);
        }

        // Check if code has already been used
        if sms_code.used {
            return Ok(false);
        }

        // Check if code matches
        if sms_code.code != code {
            return Ok(false);
        }

        // Mark code as used
        self.mark_code_used(verification_id).await?;

        Ok(true)
    }

    /// Store code in database (placeholder for actual DB implementation)
    async fn store_code(&self, code: &SmsCode) -> Result<(), ApiError> {
        // In a real application, you would store the code in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Get code from database (placeholder for actual DB implementation)
    async fn get_code(&self, id: Uuid) -> Result<SmsCode, ApiError> {
        // In a real application, you would retrieve the code from your database
        // For this example, we return an error since we don't have a real database
        Err(ApiError::new(404, "Code not found".to_string()))
    }

    /// Mark code as used (placeholder for actual DB implementation)
    async fn mark_code_used(&self, id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would update the code in your database
        // For this example, we just pretend it's updated
        Ok(())
    }

    /// Create SMS MFA settings for a user
    pub async fn create_settings(
        &self,
        user_id: Uuid,
        phone_number: &str,
    ) -> Result<SmsMfaSettings, ApiError> {
        // In a real application, you would store these settings in your database
        // For this example, we just return the settings
        Ok(SmsMfaSettings {
            user_id,
            phone_number: phone_number.to_string(),
            enabled: true,
        })
    }

    /// Get SMS MFA settings for a user
    pub async fn get_settings(&self, user_id: Uuid) -> Result<Option<SmsMfaSettings>, ApiError> {
        // In a real application, you would retrieve these settings from your database
        // For this example, we return None since we don't have a real database
        Ok(None)
    }

    /// Update SMS MFA settings for a user
    pub async fn update_settings(&self, settings: &SmsMfaSettings) -> Result<(), ApiError> {
        // In a real application, you would update these settings in your database
        // For this example, we just pretend they're updated
        Ok(())
    }

    /// Delete SMS MFA settings for a user
    pub async fn delete_settings(&self, user_id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would delete these settings from your database
        // For this example, we just pretend they're deleted
        Ok(())
    }
}

/// Implement MFA method trait for SMS
#[async_trait]
impl MfaMethod for SmsMfaProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        // Get user's phone number from settings
        let settings = self.get_settings(user_id).await?.ok_or_else(|| {
            ApiError::new(404, "SMS MFA not configured for this user".to_string())
        })?;

        // Create verification
        let verification_id = self.create_verification(&settings.phone_number).await?;

        // Return verification ID as a string
        Ok(verification_id.to_string())
    }

    async fn complete_verification(
        &self,
        user_id: Uuid,
        verification_id: &str,
        code: &str,
    ) -> Result<bool, ApiError> {
        // Convert verification ID from string to UUID
        let verification_uuid = Uuid::parse_str(verification_id)
            .map_err(|_| ApiError::new(400, "Invalid verification ID".to_string()))?;

        // Verify code
        self.verify_code(verification_uuid, code).await
    }

    fn get_method_name(&self) -> &'static str {
        "sms"
    }
}

/// Trait for SMS service providers
#[async_trait]
pub trait SmsClient: Send + Sync {
    /// Send an SMS message
    async fn send_sms(&self, phone_number: &str, message: &str) -> Result<(), String>;
}

/// Twilio SMS client implementation
pub struct TwilioSmsClient {
    account_sid: String,
    auth_token: String,
    from_number: String,
    client: reqwest::Client,
}

impl TwilioSmsClient {
    /// Create a new Twilio SMS client
    pub fn new(account_sid: String, auth_token: String, from_number: String) -> Self {
        Self {
            account_sid,
            auth_token,
            from_number,
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SmsClient for TwilioSmsClient {
    async fn send_sms(&self, phone_number: &str, message: &str) -> Result<(), String> {
        let url = format!(
            "https://api.twilio.com/2010-04-01/Accounts/{}/Messages.json",
            self.account_sid
        );

        let params = [("To", phone_number), ("From", &self.from_number), ("Body", message)];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Failed to send request to Twilio: {}", e))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Twilio error: {}", error_text));
        }

        Ok(())
    }
}

/// AWS SNS SMS client implementation
pub struct AwsSnsSmsClient {
    region: String,
    credentials: aws_sdk_sns::config::Credentials,
    client: Option<aws_sdk_sns::Client>,
}

impl AwsSnsSmsClient {
    /// Create a new AWS SNS SMS client
    pub fn new(region: String, access_key: String, secret_key: String) -> Self {
        let credentials = aws_sdk_sns::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "rust-auth-lib",
        );

        Self {
            region,
            credentials,
            client: None,
        }
    }

    /// Initialize the AWS SNS client
    async fn init_client(&mut self) -> Result<(), String> {
        if self.client.is_none() {
            let config = aws_config::ConfigLoader::default()
                .region(aws_sdk_sns::config::Region::new(self.region.clone()))
                .credentials_provider(self.credentials.clone())
                .load()
                .await;

            self.client = Some(aws_sdk_sns::Client::new(&config));
        }

        Ok(())
    }
}

#[async_trait]
impl SmsClient for AwsSnsSmsClient {
    async fn send_sms(&self, phone_number: &str, message: &str) -> Result<(), String> {
        // We need to clone self to mutate it within this async method
        let mut this = self.clone();
        this.init_client().await?;

        let client = this.client.as_ref().unwrap();

        let resp = client
            .publish()
            .phone_number(phone_number)
            .message(message)
            .send()
            .await
            .map_err(|e| format!("Failed to send SMS via AWS SNS: {}", e))?;

        log::debug!("SMS sent with message ID: {:?}", resp.message_id());

        Ok(())
    }
}

// Implement Clone for AwsSnsSmsClient
impl Clone for AwsSnsSmsClient {
    fn clone(&self) -> Self {
        Self {
            region: self.region.clone(),
            credentials: self.credentials.clone(),
            client: None, // We'll reinitialize this when needed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime};

    // Mock SMS client for testing
    #[derive(Clone)]
    struct MockSmsClient {
        sent_messages: Arc<Mutex<Vec<(String, String)>>>,
        should_fail: bool,
    }

    impl MockSmsClient {
        fn new() -> Self {
            MockSmsClient {
                sent_messages: Arc::new(Mutex::new(Vec::new())),
                should_fail: false,
            }
        }

        fn with_error() -> Self {
            let mut client = Self::new();
            client.should_fail = true;
            client
        }

        fn get_sent_messages(&self) -> Vec<(String, String)> {
            self.sent_messages.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl SmsClient for MockSmsClient {
        async fn send_sms(&self, phone_number: &str, message: &str) -> Result<(), String> {
            if self.should_fail {
                return Err("Simulated SMS sending failure".to_string());
            }

            self.sent_messages
                .lock()
                .unwrap()
                .push((phone_number.to_string(), message.to_string()));

            Ok(())
        }
    }

    // Test provider creation
    #[test]
    fn test_provider_creation() {
        let sms_client = Box::new(MockSmsClient::new());
        let provider = SmsMfaProvider {
            sms_client,
            expiration_seconds: 300,
            code_length: 6,
        };

        assert_eq!(provider.expiration_seconds, 300);
        assert_eq!(provider.code_length, 6);
    }

    // Test code generation
    #[test]
    fn test_code_generation() {
        let sms_client = Box::new(MockSmsClient::new());
        let provider = SmsMfaProvider {
            sms_client,
            expiration_seconds: 300,
            code_length: 6,
        };

        let code = provider.generate_code();

        // Check code length
        assert_eq!(code.len(), 6);

        // Check that the code contains only digits
        for c in code.chars() {
            assert!(c.is_digit(10), "Character '{}' is not a digit", c);
        }
    }

    // Test method name
    #[test]
    fn test_method_name() {
        let sms_client = Box::new(MockSmsClient::new());
        let provider = SmsMfaProvider {
            sms_client,
            expiration_seconds: 300,
            code_length: 6,
        };

        assert_eq!(provider.get_method_name(), "sms");
    }

    // Test SMS code creation
    #[test]
    fn test_sms_code_creation() {
        let id = Uuid::new_v4();
        let now = SystemTime::now();
        let expires = now + Duration::from_secs(300);

        let code = SmsCode {
            id,
            code: "123456".to_string(),
            phone_number: "+1234567890".to_string(),
            created_at: now,
            expires_at: expires,
            used: false,
        };

        assert_eq!(code.id, id);
        assert_eq!(code.code, "123456");
        assert_eq!(code.phone_number, "+1234567890");
        assert_eq!(code.created_at, now);
        assert_eq!(code.expires_at, expires);
        assert!(!code.used);
    }

    // Test SMS settings
    #[test]
    fn test_sms_settings() {
        let user_id = Uuid::new_v4();
        let settings = SmsMfaSettings {
            user_id,
            phone_number: "+1234567890".to_string(),
            enabled: true,
        };

        assert_eq!(settings.user_id, user_id);
        assert_eq!(settings.phone_number, "+1234567890");
        assert!(settings.enabled);
    }

    // Test sending SMS via mock client
    #[tokio::test]
    async fn test_send_sms() {
        let client = MockSmsClient::new();
        let phone = "+1234567890";
        let message = "Your verification code is: 123456";

        let result = client.send_sms(phone, message).await;
        assert!(result.is_ok());

        let messages = client.get_sent_messages();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].0, phone);
        assert_eq!(messages[0].1, message);
    }

    // Test SMS client failure
    #[tokio::test]
    async fn test_sms_client_failure() {
        let client = MockSmsClient::with_error();
        let phone = "+1234567890";
        let message = "Your verification code is: 123456";

        let result = client.send_sms(phone, message).await;
        assert!(result.is_err());

        let messages = client.get_sent_messages();
        assert_eq!(messages.len(), 0);
    }

    // Test Twilio client creation
    #[test]
    fn test_twilio_client_creation() {
        let client = TwilioSmsClient {
            account_sid: "test_sid".to_string(),
            auth_token: "test_token".to_string(),
            from_number: "+1987654321".to_string(),
            client: reqwest::Client::new(),
        };

        assert_eq!(client.account_sid, "test_sid");
        assert_eq!(client.auth_token, "test_token");
        assert_eq!(client.from_number, "+1987654321");
    }

    // Test AWS SNS client creation
    #[test]
    fn test_aws_sns_client_creation() {
        let client = AwsSnsSmsClient {
            region: "us-east-1".to_string(),
            credentials: aws_sdk_sns::config::Credentials::new(
                "test_access_key",
                "test_secret_key",
                None,
                None,
                "test",
            ),
            client: None,
        };

        assert_eq!(client.region, "us-east-1");
    }
}
