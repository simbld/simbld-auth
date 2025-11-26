//! # Email-based Multi-Factor Authentication
//!
//! This module provides email-based verification for multi-factor authentication.
//! It generates random codes, sends them via email, and verifies them.

use crate::auth::mfa::MfaMethod;
use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use crate::types::{ApiError, AppConfig};

/// Provider for email-based MFA
pub struct EmailMfaProvider {
    /// Email service client
    email_client: Box<dyn EmailClient>,

    /// Code expiration time in seconds
    expiration_seconds: u64,

    /// Number of digits in the verification code
    code_length: usize,

    /// Email subject
    email_subject: String,

    /// Sender email address
    sender_email: String,
}

/// Email verification code information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCode {
    /// Unique identifier for this verification attempt
    pub id: Uuid,

    /// The verification code (typically 6 digits)
    pub code: String,

    /// Email address the code was sent to
    pub email: String,

    /// When the code was created
    pub created_at: SystemTime,

    /// When the code expires
    pub expires_at: SystemTime,

    /// Whether the code has been used
    pub used: bool,
}

/// Settings for Email MFA
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailMfaSettings {
    /// User ID
    pub user_id: Uuid,

    /// User's email address
    pub email: String,

    /// Whether Email MFA is enabled
    pub enabled: bool,
}

impl EmailMfaProvider {
    /// Create a new Email MFA provider
    pub fn new(config: &AppConfig, email_client: Box<dyn EmailClient>) -> Self {
        Self {
            email_client,
            expiration_seconds: config.mfa.email_code_expiration_seconds, // Already has default in MfaConfig
            code_length: config.mfa.email_code_length,
            email_subject: config.mfa.email_subject.clone(),
            sender_email: config.mfa.sender_email.clone(),
        }
    }

    /// Generate a random verification code
    fn generate_code(&self) -> String {
        let mut rng = rand::rng();
        let mut code = String::new();

        for _ in 0..self.code_length {
            code.push(char::from_digit(rng.random_range(0..10) as u32, 10).unwrap());
        }

        code
    }

    /// Create a new verification code and send it via email
    pub async fn create_verification(&self, email: &str) -> Result<Uuid, ApiError> {
        // Generate verification code
        let code = self.generate_code();
        let id = Uuid::new_v4();
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.expiration_seconds);

        // Create code record (would typically be stored in a database)
        let email_code = EmailCode {
            id,
            code: code.clone(),
            email: email.to_string(),
            created_at: now,
            expires_at,
            used: false,
        };

        // Store code in database (this would be an actual DB call in a real app)
        self.store_code(&email_code).await?;

        // Prepare email body
        let minutes = self.expiration_seconds / 60;
        let body = format!(
            "Your verification code is: {}\n\nThis code will expire in {} minutes.",
            code, minutes
        );

        // Send email
        self.email_client
            .send_email(&self.sender_email, email, &self.email_subject, &body)
            .await
            .map_err(|e| ApiError::new(500, format!("Failed to send email: {}", e)))?;

        Ok(id)
    }

    /// Verify a code
    pub async fn verify_code(&self, verification_id: Uuid, code: &str) -> Result<bool, ApiError> {
        // Retrieve code from database (this would be a DB call in a real app)
        let email_code = self.get_code(verification_id).await?;

        // Check if code is expired
        let now = SystemTime::now();
        if email_code.expires_at < now {
            return Ok(false);
        }

        // Check if code has already been used
        if email_code.used {
            return Ok(false);
        }

        // Check if code matches
        if email_code.code != code {
            return Ok(false);
        }

        // Mark code as used
        self.mark_code_used(verification_id).await?;

        Ok(true)
    }

    /// Store code in database (placeholder for actual DB implementation)
    async fn store_code(&self, code: &EmailCode) -> Result<(), ApiError> {
        // In a real application, you would store the code in your database
        // For this example, we just pretend it's stored
        Ok(())
    }

    /// Get code from database (placeholder for actual DB implementation)
    async fn get_code(&self, id: Uuid) -> Result<EmailCode, ApiError> {
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

    /// Create Email MFA settings for a user
    pub async fn create_settings(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<EmailMfaSettings, ApiError> {
        // In a real application, you would store these settings in your database
        // For this example, we just return the settings
        Ok(EmailMfaSettings {
            user_id,
            email: email.to_string(),
            enabled: true,
        })
    }

    /// Get Email MFA settings for a user
    pub async fn get_settings(&self, user_id: Uuid) -> Result<Option<EmailMfaSettings>, ApiError> {
        // In a real application, you would retrieve these settings from your database
        // For this example, we return None since we don't have a real database
        Ok(None)
    }

    /// Update Email MFA settings for a user
    pub async fn update_settings(&self, settings: &EmailMfaSettings) -> Result<(), ApiError> {
        // In a real application, you would update these settings in your database
        // For this example, we just pretend they're updated
        Ok(())
    }

    /// Delete Email MFA settings for a user
    pub async fn delete_settings(&self, user_id: Uuid) -> Result<(), ApiError> {
        // In a real application, you would delete these settings from your database
        // For this example, we just pretend they're deleted
        Ok(())
    }
}

/// Implement MFA method trait for Email
#[async_trait]
impl MfaMethod for EmailMfaProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        // Get user's email from settings
        let settings = self.get_settings(user_id).await?.ok_or_else(|| {
            ApiError::new(404, "Email MFA not configured for this user".to_string())
        })?;

        // Create verification
        let verification_id = self.create_verification(&settings.email).await?;

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
        "email"
    }
}

/// Trait for email service providers
#[async_trait]
pub trait EmailClient: Send + Sync {
    /// Send an email message
    async fn send_email(
        &self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String>;
}

/// SMTP email client implementation
pub struct SmtpEmailClient {
    host: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    use_tls: bool,
}

impl SmtpEmailClient {
    /// Create a new SMTP email client
    pub fn new(
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        use_tls: bool,
    ) -> Self {
        Self {
            host,
            port,
            username,
            password,
            use_tls,
        }
    }
}

#[async_trait]
impl EmailClient for SmtpEmailClient {
    async fn send_email(
        &self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String> {
        // In a real implementation, you would use a library like lettre to send emails
        // For this example, we just log the message
        log::info!("Sending email from {} to {} with subject '{}': {}", from, to, subject, body);

        Ok(())
    }
}

/// AWS SES email client implementation
/// TODO: Re-enable when AWS SDK is configured
#[allow(dead_code)]
pub struct AwsSesEmailClient {
    region: String,
    // credentials: aws_sdk_sesv2::config::Credentials,
    // client: Option<aws_sdk_sesv2::Client>,
}

impl AwsSesEmailClient {
    /// Create a new AWS SES email client
    /// TODO: Re-enable when AWS SDK is configured
    #[allow(unused_variables)]
    pub fn new(region: String, access_key: String, secret_key: String) -> Self {
        // let credentials = aws_sdk_sesv2::config::Credentials::new(
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

    /// Initialize the AWS SES client
    /// TODO: Re-enable when AWS SDK is configured
    #[allow(dead_code)]
    async fn init_client(&mut self) -> Result<(), String> {
        // if self.client.is_none() {
        //     let config = aws_config::ConfigLoader::default()
        //         .region(aws_sdk_sesv2::config::Region::new(self.region.clone()))
        //         .credentials_provider(self.credentials.clone())
        //         .load()
        //         .await;
        //     self.client = Some(aws_sdk_sesv2::Client::new(&config));
        // }
        Ok(())
    }
}

#[async_trait]
impl EmailClient for AwsSesEmailClient {
    /// TODO: Re-enable when AWS SDK is configured
    #[allow(unused_variables)]
    async fn send_email(
        &self,
        from: &str,
        to: &str,
        subject: &str,
        body: &str,
    ) -> Result<(), String> {
        // TODO: AWS SES implementation temporarily disabled
        Err("AWS SES not configured".to_string())

        // let mut this = self.clone();
        // this.init_client().await?;
        // let client = this.client.as_ref().unwrap();
        // let destination = aws_sdk_sesv2::model::Destination::builder().to_addresses(to).build();
        // let subject_content = aws_sdk_sesv2::model::Content::builder().data(subject).charset("UTF-8").build();
        // let body_content = aws_sdk_sesv2::model::Content::builder().data(body).charset("UTF-8").build();
        // let message_body = aws_sdk_sesv2::model::Body::builder().text(body_content).build();
        // let message = aws_sdk_sesv2::model::Message::builder()
        //     .subject(subject_content)
        //     .body(message_body)
        //     .build();
        // let resp = client
        //     .send_email()
        //     .from_email_address(from)
        //     .destination(destination)
        //     .content(aws_sdk_sesv2::model::EmailContent::builder().simple(message).build())
        //     .send()
        //     .await
        //     .map_err(|e| format!("Failed to send email via AWS SES: {}", e))?;
        // log::debug!("Email sent with message ID: {:?}", resp.message_id());
        // Ok(())
    }
}

// Implement Clone for AwsSesEmailClient
impl Clone for AwsSesEmailClient {
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

    // Mock implementation of EmailClient for testing
    #[derive(Clone)]
    struct MockEmailClient {
        sent_emails: Arc<Mutex<Vec<(String, String, String, String)>>>,
    }

    impl MockEmailClient {
        fn new() -> Self {
            MockEmailClient {
                sent_emails: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn get_sent_emails(&self) -> Vec<(String, String, String, String)> {
            self.sent_emails.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl EmailClient for MockEmailClient {
        async fn send_email(
            &self,
            from: &str,
            to: &str,
            subject: &str,
            body: &str,
        ) -> Result<(), String> {
            self.sent_emails.lock().unwrap().push((
                from.to_string(),
                to.to_string(),
                subject.to_string(),
                body.to_string(),
            ));

            Ok(())
        }
    }

    #[test]
    fn test_generate_code_length() {
        // Arrange
        let provider = EmailMfaProvider {
            email_client: Box::new(MockEmailClient::new()),
            expiration_seconds: 300,
            code_length: 6,
            email_subject: "Test".to_string(),
            sender_email: "test@example.com".to_string(),
        };

        // Act
        let code = provider.generate_code();

        // Assert
        assert_eq!(code.len(), 6, "Le code généré devrait avoir 6 caractères");
    }
}
