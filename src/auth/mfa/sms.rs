//! # SMS-based Multi-Factor Authentication
//!
//! This module provides SMS-based verification for multi-factor authentication.
//! It generates random codes, sends them via SMS, and verifies them.

use crate::auth::mfa::MfaMethod;
use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::types::{ApiError, AppConfig};

/// Provider for SMS-based MFA
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

    /// Phone number that received the code
    pub phone_number: String,

    /// Code creation timestamp
    pub created_at: SystemTime,

    /// Code expiration timestamp
    pub expires_at: SystemTime,

    /// True if someone has already used the code
    pub used: bool,
}

/// Settings for SMS MFA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmsMfaSettings {
    /// User ID
    pub user_id: Uuid,

    /// User's phone number
    pub phone_number: String,

    /// Flag indicating SMS MFA status
    pub enabled: bool,
}

impl SmsMfaProvider {
    /// Creates a new SMS MFA provider
    #[must_use]
    pub fn new(config: &AppConfig, sms_client: Box<dyn SmsClient>) -> Self {
        Self {
            sms_client,
            expiration_seconds: config.mfa.sms_code_expiration_seconds,
            code_length: config.mfa.sms_code_length,
        }
    }

    /// Generates a random verification code
    fn generate_code(&self) -> String {
        let mut rng = rand::rng();
        let mut code = String::new();

        for _ in 0..self.code_length {
            let digit = rng.random_range(0_u32..10);
            code.push(char::from_digit(digit, 10).unwrap());
        }

        code
    }

    /// Creates a new verification code and sends it via SMS
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the SMS fails to send or the database operation fails.
    pub async fn create_verification(&self, phone_number: &str) -> Result<Uuid, ApiError> {
        // Generate verification code
        let code = self.generate_code();
        let id = Uuid::new_v4();
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.expiration_seconds);

        // Create a code record (would typically be stored in a database)
        let sms_code = SmsCode {
            id,
            code: code.clone(),
            phone_number: phone_number.to_string(),
            created_at: now,
            expires_at,
            used: false,
        };

        // Store code in a database (this would be an actual DB call in a real app)
        Self::store_code(&sms_code);

        // Send SMS
        let expiration_minutes = self.expiration_seconds / 60;
        let message = format!(
            "The verification code is: {code}. It expires in {expiration_minutes} minutes."
        );

        self.sms_client
            .send_sms(phone_number, &message)
            .await
            .map_err(|e| ApiError::new(500, format!("Failed to send SMS: {e}")))?;

        Ok(id)
    }

    /// Verifies a code
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if retrieval of the code from the database fails.
    pub fn verify_code(&self, verification_id: Uuid, code: &str) -> Result<bool, ApiError> {
        // Retrieve code from the database—this would be a DB call in a real app
        let sms_code = Self::get_code(verification_id)?;

        // Check if code expired, was already used, or doesn't match
        let now = SystemTime::now();
        if sms_code.expires_at < now || sms_code.used || sms_code.code != code {
            return Ok(false);
        }

        // Mark code as used
        Self::mark_code_used(verification_id);

        Ok(true)
    }

    /// Stores code in the database
    ///
    /// Placeholder for actual DB implementation.
    fn store_code(code: &SmsCode) {
        // In a real app, this would store the code in the database.
        // For this example, it just logs
        let code_id = code.id;
        let phone = &code.phone_number;
        log::debug!("Storing SMS code {code_id} for {phone}");
    }

    /// Gets code from the database
    ///
    /// Placeholder for actual DB implementation.
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if finding the code or database operation fails.
    fn get_code(id: Uuid) -> Result<SmsCode, ApiError> {
        // In a real app, this would retrieve the code from the database.
        // For this example, it returns an error since there is no real database
        log::debug!("Attempting to retrieve SMS code {id}");
        Err(ApiError::new(404, "Code not found".to_string()))
    }

    /// Marks code as used
    ///
    /// Placeholder for actual DB implementation.
    fn mark_code_used(id: Uuid) {
        // In a real app, this would update the code in the database.
        // For this example, it just logs
        log::debug!("Marking SMS code {id} as used");
    }

    /// Creates SMS MFA settings for a user
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the database operation fails.
    pub fn create_settings(
        &self,
        user_id: Uuid,
        phone_number: &str,
    ) -> Result<SmsMfaSettings, ApiError> {
        // In a real app, this would store these settings in the database.
        // For this example, it just returns the settings
        Ok(SmsMfaSettings {
            user_id,
            phone_number: phone_number.to_string(),
            enabled: true,
        })
    }

    /// Gets SMS MFA settings for a user
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the database operation fails.
    pub fn get_settings(&self, user_id: Uuid) -> Result<Option<SmsMfaSettings>, ApiError> {
        // In a real app, this would retrieve these settings from the database.
        // For this example, it returns None since there is no real database
        log::debug!("Retrieving SMS MFA settings for user {user_id}");
        Ok(None)
    }

    /// Updates SMS MFA settings for a user
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the database operation fails.
    pub fn update_settings(&self, settings: &SmsMfaSettings) -> Result<(), ApiError> {
        // In a real app, this would update these settings in the database.
        // For this example, it pretends they're updated
        let user_id = settings.user_id;
        log::debug!("Updating SMS MFA settings for user {user_id}");
        Ok(())
    }

    /// Deletes SMS MFA settings for a user
    ///
    /// # Errors
    ///
    /// Returns `ApiError` if the database operation fails.
    pub fn delete_settings(&self, user_id: Uuid) -> Result<(), ApiError> {
        // In a real app, this would delete these settings from the database.
        // For this example, it just logs and returns
        log::debug!("Deleting SMS MFA settings for user {user_id}");
        Ok(())
    }
}

/// Implement MFA method trait for SMS
#[async_trait]
impl MfaMethod for SmsMfaProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        // Get the user's phone number from settings
        let settings = self.get_settings(user_id)?.ok_or_else(|| {
            ApiError::new(404, "SMS MFA isn't configured for this user".to_string())
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
        log::debug!("Completing SMS verification for user {user_id}");
        // Convert verification ID from string to Uuid
        let verification_uuid = Uuid::parse_str(verification_id)
            .map_err(|e| ApiError::new(400, format!("Invalid verification ID: {e}")))?;

        // Verify code
        self.verify_code(verification_uuid, code)
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
    #[must_use]
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
        let account_sid = &self.account_sid;
        let url = format!("https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json");

        let params = [("To", phone_number), ("From", &self.from_number), ("Body", message)];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Failed to send a request to Twilio: {e}"))?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(format!("Twilio error: {error_text}"));
        }

        Ok(())
    }
}

/// Amazon Web Services Simple Notification Service SMS client implementation
/// TODO: re-enable when AWS SDK is configured
#[allow(dead_code)]
pub struct AwsSnsSmsClient {
    region: String,
    // credentials: aws_sdk_sns::config::Credentials,
    // client: Option<aws_sdk_sns::Client>,
}

impl AwsSnsSmsClient {
    /// Creates a new Amazon Web Services Simple Notification Service SMS client
    ///
    /// TODO: re-enable when AWS SDK is configured
    #[must_use]
    #[allow(unused_variables, clippy::needless_pass_by_value)]
    pub fn new(region: String, access_key: String, secret_key: String) -> Self {
        // let credentials = aws_sdk_sns::config::Credentials::new(
        //     access_key,
        //     secret_key,
        //     None,
        //     None,
        //     "rust-auth-lib",
        // );

        Self {
            region,
            // credentials,
            // client: None,
        }
    }

    /// Initializes the Amazon Web Services Simple Notification Service client
    ///
    /// TODO: re-enable when AWS SDK is configured
    #[allow(dead_code)]
    fn init_client() {
        // if self.client.is_none() {
        //     let config = aws_config::ConfigLoader::default()
        //         .region(aws_sdk_sns::config::Region::new(self.region.clone()))
        //         .credentials_provider(self.credentials.clone())
        //         .load()
        //         .await;
        //     self.client = Some(aws_sdk_sns::Client::new(&config));
        // }
    }
}

#[async_trait]
impl SmsClient for AwsSnsSmsClient {
    /// TODO: re-enable when AWS SDK is configured
    #[allow(unused_variables)]
    async fn send_sms(&self, phone_number: &str, message: &str) -> Result<(), String> {
        // TODO: implementation temporarily disabled
        Err("Amazon Web Services Simple Notification Service is not configured".to_string())

        // let mut this = self.clone();
        // this.init_client().await?;
        // let client = this.client.as_ref().unwrap();
        // let resp = client
        //     .publish()
        //     .phone_number(phone_number)
        //     .message(message)
        //     .send()
        //     .await
        //     .map_err(|e| format!("Failed to send SMS via AWS SNS: {e}"))?;
        // let msg_id = resp.message_id();
        // log::debug!("SMS sent with message ID: {msg_id:?}");
        // Ok(())
    }
}

/// Implements `Clone` for `AwsSnsSmsClient`
impl Clone for AwsSnsSmsClient {
    fn clone(&self) -> Self {
        Self {
            region: self.region.clone(),
            // credentials: self.credentials.clone(),
            // client: None,
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

    // Test sending SMS via the mock client
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
    // TODO: Re-enable when AWS SDK is re-enabled
    // #[test]
    // fn test_aws_sns_client_creation() {
    //     let client = AwsSnsSmsClient {
    //         region: "us-east-1".to_string(),
    //         credentials: aws_sdk_sns::config::Credentials::new(
    //             "test_access_key",
    //             "test_secret_key",
    //             None,
    //             None,
    //             "test",
    //         ),
    //         client: None,
    //     };
    //
    //     assert_eq!(client.region, "us-east-1");
    // }
}
