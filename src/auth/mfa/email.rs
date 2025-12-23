// rust
//! Email-based Multi-Factor Authentication
//!
//! Implémentation avec stockage Postgres via `sqlx`. Les codes sont stockés
//! sous forme hachée (sha256) pour éviter de conserver le code en clair.

use crate::auth::mfa::MfaMethod;
use crate::types::{ApiError, AppConfig};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use rand::distr::{Distribution, Uniform};
use rand::rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Provider for email-based MFA
pub struct EmailMfaProvider {
    /// Database pool
    pool: PgPool,

    /// Email service client
    email_client: Box<dyn EmailClient + Send + Sync>,

    /// Code expiration time in seconds
    expiration_seconds: u64,

    /// Number of digits in the verification code
    code_length: usize,

    /// Email subject
    email_subject: String,

    /// Sender email address
    sender_email: String,
}

/// Email verification code information (stocke le hash du code)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailCode {
    /// Unique identifier for this verification attempt
    pub id: Uuid,

    /// The verification code hash (sha256 hex)
    pub code_hash: String,

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
    /// Create a new Email MFA provider (note: now prend `pool`)
    #[must_use]
    pub fn new(
        config: &AppConfig,
        pool: PgPool,
        email_client: Box<dyn EmailClient + Send + Sync>,
    ) -> Self {
        Self {
            pool,
            email_client,
            expiration_seconds: config.mfa.email_code_expiration_seconds,
            code_length: config.mfa.email_code_length,
            email_subject: config.mfa.email_subject.clone(),
            sender_email: config.mfa.sender_email.clone(),
        }
    }

    /// Generate a random verification code
    fn generate_code(&self) -> String {
        let mut rng = rng();
        let dist = Uniform::new(0, 10).expect("uniform range");
        (0..self.code_length).map(|_| dist.sample(&mut rng).to_string()).collect()
    }

    fn hash_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Create a new verification code and send it via email
    pub async fn create_verification(&self, email: &str) -> Result<Uuid, ApiError> {
        // Generate verification code (plaintext for email only)
        let code = self.generate_code();
        let id = Uuid::new_v4();
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(self.expiration_seconds);

        // Hash the code before storing
        let code_hash = Self::hash_code(&code);

        // Store code in a database
        let created_at_chrono: DateTime<Utc> = DateTime::<Utc>::from(now);
        let expires_at_chrono: DateTime<Utc> = DateTime::<Utc>::from(expires_at);
        sqlx::query!(
            r#"
            INSERT INTO email_mfa_codes (id, code_hash, email, created_at, expires_at, used)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            id,
            code_hash,
            email,
            created_at_chrono,
            expires_at_chrono,
            false
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB insert failed: {e}")))?;

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
            .map_err(|e| ApiError::new(500, format!("Failed to send email: {e}")))?;

        Ok(id)
    }

    /// Verify a code
    pub async fn verify_code(
        &self,
        verification_id: Uuid,
        provided_code: &str,
    ) -> Result<bool, ApiError> {
        // Retrieve code record from a database
        let row = sqlx::query!(
            r#"
            SELECT id, code_hash, email, created_at, expires_at, used
            FROM email_mfa_codes
            WHERE id = $1
            "#,
            verification_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB query failed: {e}")))?;

        let rec = match row {
            Some(r) => r,
            None => return Ok(false),
        };

        // Convert chrono times to SystemTime using non déprécié
        let expires_at: SystemTime =
            DateTime::<Utc>::from_naive_utc_and_offset(rec.expires_at.naive_utc(), Utc).into();

        // Check expiry
        let now = SystemTime::now();
        if expires_at < now {
            return Ok(false);
        }

        // Check if already used
        if rec.used {
            return Ok(false);
        }

        // Compare hashes
        let provided_hash = Self::hash_code(provided_code);
        if provided_hash != rec.code_hash {
            return Ok(false);
        }

        // Mark used
        sqlx::query!(
            r#"
            UPDATE email_mfa_codes
            SET used = true, used_at = $2
            WHERE id = $1
            "#,
            verification_id,
            DateTime::<Utc>::from(now)
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB update failed: {e}")))?;

        Ok(true)
    }

    /// Store code in database (compatibility wrapper)
    async fn store_code(&self, code: &EmailCode) -> Result<(), ApiError> {
        let created_at_chrono: DateTime<Utc> = DateTime::<Utc>::from(code.created_at);
        let expires_at_chrono: DateTime<Utc> = DateTime::<Utc>::from(code.expires_at);
        sqlx::query!(
            r#"
            INSERT INTO email_mfa_codes (id, code_hash, email, created_at, expires_at, used)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            code.id,
            code.code_hash,
            code.email,
            created_at_chrono,
            expires_at_chrono,
            code.used
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB insert failed: {e}")))?;
        Ok(())
    }

    /// Get code from database (renvoie EmailCode avec code_hash)
    async fn get_code(&self, id: Uuid) -> Result<EmailCode, ApiError> {
        let row = sqlx::query!(
            r#"
            SELECT id, code_hash, email, created_at, expires_at, used
            FROM email_mfa_codes
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB query failed: {e}")))?;

        let r = row.ok_or_else(|| ApiError::new(404, "Code not found".to_string()))?;

        let created_at: SystemTime =
            DateTime::<Utc>::from_naive_utc_and_offset(r.created_at.naive_utc(), Utc).into();
        let expires_at: SystemTime =
            DateTime::<Utc>::from_naive_utc_and_offset(r.expires_at.naive_utc(), Utc).into();

        Ok(EmailCode {
            id: r.id,
            code_hash: r.code_hash,
            email: r.email,
            created_at,
            expires_at,
            used: r.used,
        })
    }

    /// Mark code as used
    async fn mark_code_used(&self, id: Uuid) -> Result<(), ApiError> {
        let now = SystemTime::now();
        sqlx::query!(
            r#"
            UPDATE email_mfa_codes
            SET used = true, used_at = $2
            WHERE id = $1
            "#,
            id,
            DateTime::<Utc>::from(now)
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB update failed: {e}")))?;
        Ok(())
    }

    /// Create Email MFA settings for a user (upsert)
    pub async fn create_settings(
        &self,
        user_id: Uuid,
        email: &str,
    ) -> Result<EmailMfaSettings, ApiError> {
        sqlx::query!(
            r#"
            INSERT INTO email_mfa_settings (user_id, email, enabled)
            VALUES ($1, $2, true)
            ON CONFLICT (user_id) DO UPDATE SET email = EXCLUDED.email, enabled = true
            "#,
            user_id,
            email
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB upsert failed: {e}")))?;

        Ok(EmailMfaSettings {
            user_id,
            email: email.to_string(),
            enabled: true,
        })
    }

    /// Get Email MFA settings for a user
    pub async fn get_settings(&self, user_id: Uuid) -> Result<Option<EmailMfaSettings>, ApiError> {
        let row = sqlx::query!(
            r#"
            SELECT user_id, email, enabled
            FROM email_mfa_settings
            WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB query failed: {e}")))?;

        if let Some(r) = row {
            Ok(Some(EmailMfaSettings {
                user_id: r.user_id,
                email: r.email,
                enabled: r.enabled,
            }))
        } else {
            Ok(None)
        }
    }

    /// Update Email MFA settings for a user
    pub async fn update_settings(&self, settings: &EmailMfaSettings) -> Result<(), ApiError> {
        sqlx::query!(
            r#"
            UPDATE email_mfa_settings
            SET email = $2, enabled = $3
            WHERE user_id = $1
            "#,
            settings.user_id,
            settings.email,
            settings.enabled
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB update failed: {e}")))?;
        Ok(())
    }

    /// Delete Email MFA settings for a user
    pub async fn delete_settings(&self, user_id: Uuid) -> Result<(), ApiError> {
        sqlx::query!(
            r#"
            DELETE FROM email_mfa_settings WHERE user_id = $1
            "#,
            user_id
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::new(500, format!("DB delete failed: {e}")))?;
        Ok(())
    }
}

/// Implement MFA method trait for Email
#[async_trait]
impl MfaMethod for EmailMfaProvider {
    async fn initiate_verification(&self, user_id: Uuid) -> Result<String, ApiError> {
        let settings = self.get_settings(user_id).await?.ok_or_else(|| {
            ApiError::new(404, "Email MFA not configured for this user".to_string())
        })?;

        let verification_id = self.create_verification(&settings.email).await?;
        Ok(verification_id.to_string())
    }

    async fn complete_verification(
        &self,
        _user_id: Uuid,
        verification_id: &str,
        code: &str,
    ) -> Result<bool, ApiError> {
        let verification_uuid = Uuid::parse_str(verification_id)
            .map_err(|_| ApiError::new(400, "Invalid verification ID".to_string()))?;
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
        log::info!("Sending email from {} to {} with subject '{}': {}", from, to, subject, body);
        Ok(())
    }
}

/// AWS SES email client (désactivé si non configuré)
#[allow(dead_code)]
pub struct AwsSesEmailClient {
    region: String,
}

impl AwsSesEmailClient {
    #[allow(unused_variables)]
    pub fn new(region: String, _access_key: String, _secret_key: String) -> Self {
        Self {
            region,
        }
    }
}

#[async_trait]
impl EmailClient for AwsSesEmailClient {
    #[allow(unused_variables)]
    async fn send_email(
        &self,
        _from: &str,
        _to: &str,
        _subject: &str,
        _body: &str,
    ) -> Result<(), String> {
        Err("AWS SES not configured".to_string())
    }
}

impl Clone for AwsSesEmailClient {
    fn clone(&self) -> Self {
        Self {
            region: self.region.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::{Arc, Mutex};
    use tokio::runtime::Runtime;

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
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let pool = PgPoolOptions::new()
                .max_connections(1)
                .connect_lazy("postgres://localhost/testdb")
                .unwrap();

            let provider = EmailMfaProvider {
                pool,
                email_client: Box::new(MockEmailClient::new()),
                expiration_seconds: 300,
                code_length: 6,
                email_subject: "Test".to_string(),
                sender_email: "test@example.com".to_string(),
            };

            let code = provider.generate_code();
            assert_eq!(code.len(), 6, "Le code généré devrait avoir 6 caractères");
        });
    }
}
