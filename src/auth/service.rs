//! # Authentication Service
//!
//! This module provides the core authentication service implementation for the application.
//! The AuthService handles user registration, authentication, token management, 
//! MFA operations, and password management.

use deadpool_postgres::Pool;
use uuid::Uuid;
use argon2::{self, Config};
use chrono::{Duration, Utc};
use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;
use totp_rs::{TOTP, Secret, Algorithm};
use jwt::{encode, decode, Header, Validation};
use serde::{Serialize, Deserialize};

use crate::auth::models::{User, RefreshToken, MfaSetup};
use crate::auth::handlers::{RegisterRequest, TokenResponse};
use crate::auth::jwt::{Claims, JWT_SECRET};
use crate::auth::sessions::{Session, SessionManager};
use crate::errors::ApiError;

/// Authentication result containing user ID and MFA status
pub struct AuthResult {
    /// User's UUID
    pub user_id: Uuid,

    /// Flag indicating if MFA verification is required
    pub mfa_required: bool,
}

/// Token pair containing access and refresh tokens
pub struct TokenPair {
    /// JWT access token
    pub access_token: String,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,
}

/// MFA setup information
pub struct MfaSetupInfo {
    /// TOTP secret key
    pub secret: String,

    /// URI for QR code generation
    pub provisioning_uri: String,
}

/// The main authentication service for the application
pub struct AuthService {
    /// Session manager instance
    session_manager: SessionManager,

    /// TOTP issuer name for MFA
    mfa_issuer: String,
}

impl AuthService {
    /// Create a new instance of the AuthService
    ///
    /// # Arguments
    ///
    /// * `mfa_issuer` - The issuer name to use for MFA TOTP URIs
    ///
    /// # Returns
    ///
    /// A new AuthService instance
    pub fn new(mfa_issuer: String) -> Self {
        Self {
            session_manager: SessionManager::new(),
            mfa_issuer,
        }
    }

    /// Register a new user
    ///
    /// # Arguments
    ///
    /// * `req` - The registration request containing user data
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// The newly created user on success
    pub async fn register_user(
        &self,
        req: &RegisterRequest,
        pool: &Pool,
    ) -> Result<User, ApiError> {
        // Check if user with email already exists
        let conn = pool.get().await?;
        let stmt = conn.prepare("SELECT id FROM users WHERE email = $1").await?;
        let rows = conn.query(&stmt, &[&req.email]).await?;

        if !rows.is_empty() {
            return Err(ApiError::new(
                409,
                "User with this email already exists".to_string(),
            ));
        }

        // Hash the password
        let password_hash = self.hash_password(&req.password)?;

        // Create the user
        let stmt = conn.prepare(
            "INSERT INTO users (username, email, password_hash) 
             VALUES ($1, $2, $3) 
             RETURNING id, username, email, created_at, updated_at"
        ).await?;

        let row = conn.query_one(
            &stmt,
            &[&req.username, &req.email, &password_hash]
        ).await?;

        let user = User {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        Ok(user)
    }

    /// Authenticate a user with email and password
    ///
    /// # Arguments
    ///
    /// * `email` - User's email
    /// * `password` - User's password
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// AuthResult containing user ID and MFA status
    pub async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        pool: &Pool,
    ) -> Result<AuthResult, ApiError> {
        // Get user from database
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "SELECT id, password_hash, mfa_enabled 
             FROM users 
             WHERE email = $1"
        ).await?;

        let row = conn.query_opt(&stmt, &[&email]).await?
            .ok_or_else(|| ApiError::new(401, "Invalid email or password".to_string()))?;

        let user_id: Uuid = row.get("id");
        let password_hash: String = row.get("password_hash");
        let mfa_enabled: bool = row.get("mfa_enabled");

        // Verify password
        if !self.verify_password(password, &password_hash)? {
            // Use a constant-time comparison function to prevent timing attacks
            return Err(ApiError::new(401, "Invalid email or password".to_string()));
        }

        // Return result based on MFA status
        Ok(AuthResult {
            user_id,
            mfa_required: mfa_enabled,
        })
    }

    /// Verify a user's password directly
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `password` - Password to verify
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// Ok if password is verified, Error otherwise
    pub async fn verify_password(
        &self,
        user_id: Uuid,
        password: &str,
        pool: &Pool,
    ) -> Result<(), ApiError> {
        // Get password hash from database
        let conn = pool.get().await?;
        let stmt = conn.prepare("SELECT password_hash FROM users WHERE id = $1").await?;

        let row = conn.query_opt(&stmt, &[&user_id]).await?
            .ok_or_else(|| ApiError::new(404, "User not found".to_string()))?;

        let password_hash: String = row.get("password_hash");

        // Verify password
        if !self.verify_password(password, &password_hash)? {
            return Err(ApiError::new(401, "Invalid password".to_string()));
        }

        Ok(())
    }

    /// Generate authentication tokens for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `pool` - Database connection pool
    /// * `ip_address` - Client IP address
    /// * `user_agent` - Client user agent
    ///
    /// # Returns
    ///
    /// TokenPair containing access and refresh tokens
    pub async fn generate_tokens(
        &self,
        user_id: Uuid,
        pool: &Pool,
        ip_address: String,
        user_agent: String,
    ) -> Result<TokenPair, ApiError> {
        // Create a new session
        let session = self.session_manager.create_session(
            user_id,
            ip_address,
            user_agent,
            pool
        ).await?;

        // Generate JWT for access token
        let now = Utc::now();
        let expiry = now + Duration::hours(1);

        let claims = Claims {
            sub: user_id,
            exp: expiry.timestamp() as usize,
            iat: now.timestamp() as usize,
            session_id: session.id,
        };

        let header = Header::default();
        let access_token = encode(&header, &claims, &JWT_SECRET.as_ref())?;

        // Generate refresh token
        let refresh_token = self.generate_refresh_token(user_id, session.id, pool).await?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }

    /// Generate a refresh token
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `session_id` - Session ID
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// Refresh token string
    async fn generate_refresh_token(
        &self,
        user_id: Uuid,
        session_id: Uuid,
        pool: &Pool,
    ) -> Result<String, ApiError> {
        // Generate random token
        let token: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        // Store token in database
        let conn = pool.get().await?;
        let expiry = Utc::now() + Duration::days(7);

        let stmt = conn.prepare(
            "INSERT INTO refresh_tokens (token, user_id, session_id, expires_at) 
             VALUES ($1, $2, $3, $4)"
        ).await?;

        conn.execute(&stmt, &[&token, &user_id, &session_id, &expiry]).await?;

        Ok(token)
    }

    /// Refresh an access token using a refresh token
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - Refresh token string
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// TokenPair containing new access and refresh tokens
    pub async fn refresh_token(
        &self,
        refresh_token: &str,
        pool: &Pool,
    ) -> Result<TokenPair, ApiError> {
        // Verify refresh token
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "SELECT user_id, session_id 
             FROM refresh_tokens 
             WHERE token = $1 AND expires_at > $2 AND is_revoked = FALSE"
        ).await?;

        let now = Utc::now();
        let row = conn.query_opt(&stmt, &[&refresh_token, &now]).await?
            .ok_or_else(|| ApiError::new(401, "Invalid or expired refresh token".to_string()))?;

        let user_id: Uuid = row.get("user_id");
        let session_id: Uuid = row.get("session_id");

        // Verify session is still active
        let session = self.session_manager.get_session(session_id, pool).await?;
        if session.is_expired() || session.is_revoked {
            return Err(ApiError::new(401, "Session expired or revoked".to_string()));
        }

        // Revoke the old refresh token
        self.invalidate_token(refresh_token, pool).await?;

        // Get session details
        let ip_address = session.ip_address;
        let user_agent = session.user_agent;

        // Generate new tokens
        let now = Utc::now();
        let expiry = now + Duration::hours(1);

        let claims = Claims {
            sub: user_id,
            exp: expiry.timestamp() as usize,
            iat: now.timestamp() as usize,
            session_id,
        };

        let header = Header::default();
        let access_token = encode(&header, &claims, &JWT_SECRET.as_ref())?;

        // Generate new refresh token
        let new_refresh_token = self.generate_refresh_token(user_id, session_id, pool).await?;

        Ok(TokenPair {
            access_token,
            refresh_token: new_refresh_token,
        })
    }

    /// Invalidate a refresh token
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - Refresh token to invalidate
    /// * `pool` - Database connection pool
    pub async fn invalidate_token(
        &self,
        refresh_token: &str,
        pool: &Pool,
    ) -> Result<(), ApiError> {
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "UPDATE refresh_tokens 
             SET is_revoked = TRUE 
             WHERE token = $1"
        ).await?;

        conn.execute(&stmt, &[&refresh_token]).await?;

        Ok(())
    }

    /// Verify an MFA code
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `code` - MFA code to verify
    /// * `pool` - Database connection pool
    pub async fn verify_mfa_code(
        &self,
        user_id: Uuid,
        code: &str,
        pool: &Pool,
    ) -> Result<(), ApiError> {
        // Get MFA secret from database
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "SELECT mfa_secret 
             FROM users 
             WHERE id = $1 AND mfa_enabled = TRUE"
        ).await?;

        let row = conn.query_opt(&stmt, &[&user_id]).await?
            .ok_or_else(|| ApiError::new(400, "MFA not enabled for this user".to_string()))?;

        let secret: String = row.get("mfa_secret");

        // Verify code
        let totp = self.create_totp(&secret)?;
        if !totp.check_current(code)? {
            return Err(ApiError::new(401, "Invalid MFA code".to_string()));
        }

        Ok(())
    }

    /// Generate MFA setup information
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// MFA setup information including secret and provisioning URI
    pub async fn generate_mfa_setup(
        &self,
        user_id: Uuid,
        pool: &Pool,
    ) -> Result<MfaSetupInfo, ApiError> {
        // Generate a new secret
        let secret = Secret::generate_secret().b32_encoded();

        // Get user email
        let conn = pool.get().await?;
        let stmt = conn.prepare("SELECT email FROM users WHERE id = $1").await?;

        let row = conn.query_opt(&stmt, &[&user_id]).await?
            .ok_or_else(|| ApiError::new(404, "User not found".to_string()))?;

        let email: String = row.get("email");

        // Create TOTP with the secret
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret.clone()).to_bytes()?,
            Some(self.mfa_issuer.clone()),
            email.clone(),
        )?;

        // Generate provisioning URI for QR code
        let provisioning_uri = totp.get_provisioning_uri();

        // Store the secret temporarily
        let stmt = conn.prepare(
            "UPDATE users 
             SET mfa_secret = $1, mfa_enabled = FALSE 
             WHERE id = $2"
        ).await?;

        conn.execute(&stmt, &[&secret, &user_id]).await?;

        Ok(MfaSetupInfo {
            secret,
            provisioning_uri,
        })
    }

    /// Verify and activate MFA
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `code` - MFA code to verify
    /// * `pool` - Database connection pool
    pub async fn verify_and_activate_mfa(
        &self,
        user_id: Uuid,
        code: &str,
        pool: &Pool,
    ) -> Result<(), ApiError> {
        // Get MFA secret from database
        let conn = pool.get().await?;
        let stmt = conn.prepare("SELECT mfa_secret FROM users WHERE id = $1").await?;

        let row = conn.query_opt(&stmt, &[&user_id]).await?
            .ok_or_else(|| ApiError::new(404, "User not found".to_string()))?;

        let secret: String = row.get("mfa_secret");

        // Verify code
        let totp = self.create_totp(&secret)?;
        if !totp.check_current(code)? {
            return Err(ApiError::new(401, "Invalid MFA code".to_string()));
        }

        // Activate MFA
        let stmt = conn.prepare(
            "UPDATE users 
             SET mfa_enabled = TRUE 
             WHERE id = $1"
        ).await?;

        conn.execute(&stmt, &[&user_id]).await?;

        Ok(())
    }

    /// Disable MFA for a user
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `pool` - Database connection pool
    pub async fn disable_mfa(
        &self,
        user_id: Uuid,
        pool: &Pool,
    ) -> Result<(), ApiError> {
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "UPDATE users 
             SET mfa_enabled = FALSE, mfa_secret = NULL 
             WHERE id = $1"
        ).await?;

        conn.execute(&stmt, &[&user_id]).await?;

        Ok(())
    }

    /// Change a user's password
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `current_password` - Current password
    /// * `new_password` - New password
    /// * `pool` - Database connection pool
    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: &str,
        new_password: &str,
        pool: &Pool,
    ) -> Result<(), ApiError> {
        // Verify current password
        self.verify_password(user_id, current_password, pool).await?;

        // Hash the new password
        let new_password_hash = self.hash_password(new_password)?;

        // Update password in database
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "UPDATE users 
             SET password_hash = $1, updated_at = $2 
             WHERE id = $3"
        ).await?;

        let now = Utc::now();
        conn.execute(&stmt, &[&new_password_hash, &now, &user_id]).await?;

        // Revoke all sessions and refresh tokens
        self.session_manager.revoke_all_sessions(user_id, pool).await?;

        let stmt = conn.prepare(
            "UPDATE refresh_tokens 
             SET is_revoked = TRUE 
             WHERE user_id = $1"
        ).await?;

        conn.execute(&stmt, &[&user_id]).await?;

        Ok(())
    }

    /// Get user by ID
    ///
    /// # Arguments
    ///
    /// * `user_id` - User's ID
    /// * `pool` - Database connection pool
    ///
    /// # Returns
    ///
    /// User object if found
    pub async fn get_user_by_id(
        &self,
        user_id: Uuid,
        pool: &Pool,
    ) -> Result<User, ApiError> {
        let conn = pool.get().await?;
        let stmt = conn.prepare(
            "SELECT id, username, email, created_at, updated_at 
             FROM users 
             WHERE id = $1"
        ).await?;

        let row = conn.query_opt(&stmt, &[&user_id]).await?
            .ok_or_else(|| ApiError::new(404, "User not found".to_string()))?;

        let user = User {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        Ok(user)
    }

    /// Hash a password using Argon2
    ///
    /// # Arguments
    ///
    /// * `password` - Password to hash
    ///
    /// # Returns
    ///
    /// Hashed password
    fn hash_password(&self, password: &str) -> Result<String, ApiError> {
        let salt: [u8; 32] = thread_rng().gen();
        let config = Config::default();

        let hash = argon2::hash_encoded(
            password.as_bytes(),
            &salt,
            &config,
        )?;

        Ok(hash)
    }

    /// Verify a password against its hash
    ///
    /// # Arguments
    ///
    /// * `password` - Password to verify
    /// * `hash` - Hash to verify against
    ///
    /// # Returns
    ///
    /// true if password is valid, false otherwise
    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, ApiError> {
        Ok(argon2::verify_encoded(hash, password.as_bytes())?)
    }

    /// Create a TOTP instance from a secret
    ///
    /// # Arguments
    ///
    /// * `secret` - TOTP secret
    ///
    /// # Returns
    ///
    /// TOTP instance
    fn create_totp(&self, secret: &str) -> Result<TOTP, ApiError> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret.to_string()).to_bytes()?,
            None,
            String::new(),
        )?;

        Ok(totp)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::errors::ApiError;
        use deadpool_postgres::{Client, Pool};
        use mockall::{mock, predicate::*};
        use std::str::FromStr;
        use tokio_postgres::Row;
        use uuid::Uuid;

        // Mocks pour les dépendances
        mock! {
        pub SessionManager {}
        impl SessionManager {
            pub async fn create_session(
                &self,
                user_id: Uuid,
                ip_address: String,
                user_agent: String,
                pool: &Pool
            ) -> Result<Session, ApiError>;

            pub async fn get_session_by_id(
                &self,
                session_id: Uuid,
                pool: &Pool
            ) -> Result<Session, ApiError>;

            pub async fn invalidate_session(
                &self,
                session_id: Uuid,
                pool: &Pool
            ) -> Result<(), ApiError>;
        }
    }

        mock! {
        pub PostgresPool {}
        impl Clone for PostgresPool {
            fn clone(&self) -> Self;
        }
        impl PostgresPool {
            pub async fn get(&self) -> Result<Client, deadpool_postgres::PoolError>;
        }
    }

        mock! {
        pub PostgresClient {}
        impl PostgresClient {
            pub async fn query_one<T: tokio_postgres::types::ToSql + Sync>(
                &self,
                statement: &str,
                params: &[T]
            ) -> Result<Row, tokio_postgres::Error>;

            pub async fn query<T: tokio_postgres::types::ToSql + Sync>(
                &self,
                statement: &str,
                params: &[T]
            ) -> Result<Vec<Row>, tokio_postgres::Error>;

            pub async fn execute<T: tokio_postgres::types::ToSql + Sync>(
                &self,
                statement: &str,
                params: &[T]
            ) -> Result<u64, tokio_postgres::Error>;
        }
    }

        // Fonction d'aide pour créer un AuthService de test
        fn create_test_auth_service() -> AuthService {
            AuthService::new("test-issuer".to_string())
        }

        // Fonction d'aide pour créer un UUID valide
        fn test_uuid() -> Uuid {
            Uuid::from_str("00000000-0000-0000-0000-000000000001").unwrap()
        }

        #[tokio::test]
        async fn test_register_user_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            // Configuration du mock pour simuler l'absence d'utilisateur existant
            mock_client.expect_query()
                .with(eq("SELECT * FROM users WHERE email = $1"), any())
                .times(1)
                .returning(|_, _| Ok(vec![]));

            // Configuration du mock pour simuler l'insertion d'un nouvel utilisateur
            mock_client.expect_query_one()
                .with(eq("INSERT INTO users (email, password_hash, display_name, profile_image) VALUES ($1, $2, $3, $4) RETURNING *"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("id", test_uuid())
                        .add_column("email", "test@example.com")
                        .add_column("password_hash", "hashed_password")
                        .add_column("display_name", "Test User")
                        .add_column("profile_image", "https://example.com/profile.jpg")
                        .add_column("is_active", true)
                        .add_column("mfa_enabled", false)
                        .add_column("mfa_secret", Option::<String>::None)
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let register_request = RegisterRequest {
                email: "test@example.com".to_string(),
                password: "securepassword".to_string(),
                display_name: Some("Test User".to_string()),
                profile_image: Some("https://example.com/profile.jpg".to_string()),
            };

            let result = auth_service.register_user(&register_request, &mock_pool).await;

            assert!(result.is_ok());

            let user = result.unwrap();
            assert_eq!(user.email, "test@example.com");
            assert_eq!(user.display_name, Some("Test User".to_string()));
            assert_eq!(user.profile_image, Some("https://example.com/profile.jpg".to_string()));
            assert_eq!(user.is_active, true);
            assert_eq!(user.mfa_enabled, false);
        }

        #[tokio::test]
        async fn test_register_user_duplicate_email() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            // Configuration du mock pour simuler un utilisateur existant
            mock_client.expect_query()
                .with(eq("SELECT * FROM users WHERE email = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("id", test_uuid())
                        .add_column("email", "test@example.com")
                        .build();
                    Ok(vec![row])
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let register_request = RegisterRequest {
                email: "test@example.com".to_string(),
                password: "securepassword".to_string(),
                display_name: None,
                profile_image: None,
            };

            let result = auth_service.register_user(&register_request, &mock_pool).await;

            assert!(result.is_err());
            match result {
                Err(ApiError::Conflict(msg)) => {
                    assert!(msg.contains("email already exists"));
                },
                _ => panic!("Expected Conflict error"),
            }
        }

        #[tokio::test]
        async fn test_authenticate_user_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            // Configure mock pour simuler un utilisateur existant avec mot de passe correct
            mock_client.expect_query_one()
                .with(eq("SELECT * FROM users WHERE email = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("id", test_uuid())
                        .add_column("email", "test@example.com")
                        .add_column("password_hash", "$2b$12$S9vahIaQY.lpMOv/s9bFFeaGKRz1r9N6pW5AsbLiJRGGET1vKqhAS") // 'password' hashed
                        .add_column("is_active", true)
                        .add_column("mfa_enabled", false)
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.authenticate_user("test@example.com", "password", &mock_pool).await;

            assert!(result.is_ok());
            let auth_result = result.unwrap();
            assert_eq!(auth_result.user_id, test_uuid());
            assert_eq!(auth_result.mfa_required, false);
        }

        #[tokio::test]
        async fn test_authenticate_user_invalid_password() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            // Configure mock pour simuler un utilisateur existant avec mot de passe incorrect
            mock_client.expect_query_one()
                .with(eq("SELECT * FROM users WHERE email = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("id", test_uuid())
                        .add_column("email", "test@example.com")
                        .add_column("password_hash", "$2b$12$S9vahIaQY.lpMOv/s9bFFeaGKRz1r9N6pW5AsbLiJRGGET1vKqhAS") // 'password' hashed
                        .add_column("is_active", true)
                        .add_column("mfa_enabled", false)
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.authenticate_user("test@example.com", "wrong_password", &mock_pool).await;

            assert!(result.is_err());
            match result {
                Err(ApiError::Unauthorized(msg)) => {
                    assert!(msg.contains("Invalid credentials"));
                },
                _ => panic!("Expected Unauthorized error"),
            }
        }

        #[tokio::test]
        async fn test_authenticate_user_inactive_account() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            // Configure mock pour simuler un utilisateur inactif
            mock_client.expect_query_one()
                .with(eq("SELECT * FROM users WHERE email = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("id", test_uuid())
                        .add_column("email", "test@example.com")
                        .add_column("password_hash", "$2b$12$S9vahIaQY.lpMOv/s9bFFeaGKRz1r9N6pW5AsbLiJRGGET1vKqhAS")
                        .add_column("is_active", false)
                        .add_column("mfa_enabled", false)
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.authenticate_user("test@example.com", "password", &mock_pool).await;

            assert!(result.is_err());
            match result {
                Err(ApiError::Unauthorized(msg)) => {
                    assert!(msg.contains("Account is inactive"));
                },
                _ => panic!("Expected Unauthorized error"),
            }
        }

        #[tokio::test]
        async fn test_authenticate_user_mfa_required() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            // Configure mock pour simuler un utilisateur avec MFA activé
            mock_client.expect_query_one()
                .with(eq("SELECT * FROM users WHERE email = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("id", test_uuid())
                        .add_column("email", "test@example.com")
                        .add_column("password_hash", "$2b$12$S9vahIaQY.lpMOv/s9bFFeaGKRz1r9N6pW5AsbLiJRGGET1vKqhAS")
                        .add_column("is_active", true)
                        .add_column("mfa_enabled", true)
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.authenticate_user("test@example.com", "password", &mock_pool).await;

            assert!(result.is_ok());
            let auth_result = result.unwrap();
            assert_eq!(auth_result.user_id, test_uuid());
            assert_eq!(auth_result.mfa_required, true);
        }

        #[tokio::test]
        async fn test_generate_tokens_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();
            let mut mock_session_manager = MockSessionManager::new();

            let user_id = test_uuid();
            let session_id = Uuid::from_str("00000000-0000-0000-0000-000000000002").unwrap();

            // Configure mock pour récupérer les rôles de l'utilisateur
            mock_client.expect_query()
                .with(eq("SELECT r.role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row1 = MockRow::new()
                        .add_column("role_name", "USER")
                        .build();
                    let row2 = MockRow::new()
                        .add_column("role_name", "ADMIN")
                        .build();
                    Ok(vec![row1, row2])
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            // Configure mock pour la création d'une session
            let session = Session {
                id: session_id,
                user_id,
                ip_address: "127.0.0.1".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(7),
                is_revoked: false,
                last_activity: chrono::Utc::now(),
                created_at: chrono::Utc::now(),
            };

            mock_session_manager.expect_create_session()
                .with(eq(user_id), eq("127.0.0.1".to_string()), eq("Mozilla/5.0".to_string()), any())
                .times(1)
                .returning(move |_, _, _, _| Ok(session.clone()));

            let auth_service = AuthService {
                session_manager: mock_session_manager,
                mfa_issuer: "test-issuer".to_string(),
            };

            let result = auth_service.generate_tokens(
                user_id,
                &mock_pool,
                "127.0.0.1".to_string(),
                "Mozilla/5.0".to_string()
            ).await;

            assert!(result.is_ok());

            let token_pair = result.unwrap();
            assert!(!token_pair.access_token.is_empty());
            assert!(!token_pair.refresh_token.is_empty());
        }

        #[tokio::test]
        async fn test_refresh_token_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();
            let mut mock_session_manager = MockSessionManager::new();

            let user_id = test_uuid();
            let session_id = Uuid::from_str("00000000-0000-0000-0000-000000000002").unwrap();

            // Configure mock pour récupérer les rôles de l'utilisateur
            mock_client.expect_query()
                .with(eq("SELECT r.role_name FROM user_roles ur JOIN roles r ON ur.role_id = r.id WHERE ur.user_id = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("role_name", "USER")
                        .build();
                    Ok(vec![row])
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            // Configure mock pour récupérer la session
            let session = Session {
                id: session_id,
                user_id,
                ip_address: "127.0.0.1".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(7),
                is_revoked: false,
                last_activity: chrono::Utc::now(),
                created_at: chrono::Utc::now(),
            };

            mock_session_manager.expect_get_session_by_id()
                .with(eq(session_id), any())
                .times(1)
                .returning(move |_, _| Ok(session.clone()));

            let auth_service = AuthService {
                session_manager: mock_session_manager,
                mfa_issuer: "test-issuer".to_string(),
            };

            // Créer un refresh token valide
            let refresh_token = "valid_refresh_token"; // Simuler un token JWT valide décodé par le service

            let result = auth_service.refresh_token(refresh_token, &mock_pool).await;

            assert!(result.is_ok());

            let token_pair = result.unwrap();
            assert!(!token_pair.access_token.is_empty());
            assert!(!token_pair.refresh_token.is_empty());
        }

        #[tokio::test]
        async fn test_refresh_token_revoked_session() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_session_manager = MockSessionManager::new();

            let user_id = test_uuid();
            let session_id = Uuid::from_str("00000000-0000-0000-0000-000000000002").unwrap();

            // Configure mock pour récupérer une session révoquée
            let session = Session {
                id: session_id,
                user_id,
                ip_address: "127.0.0.1".to_string(),
                user_agent: "Mozilla/5.0".to_string(),
                expires_at: chrono::Utc::now() + chrono::Duration::days(7),
                is_revoked: true, // Session révoquée
                last_activity: chrono::Utc::now(),
                created_at: chrono::Utc::now(),
            };

            mock_session_manager.expect_get_session_by_id()
                .with(eq(session_id), any())
                .times(1)
                .returning(move |_, _| Ok(session.clone()));

            let auth_service = AuthService {
                session_manager: mock_session_manager,
                mfa_issuer: "test-issuer".to_string(),
            };

            // Créer un refresh token valide
            let refresh_token = "valid_refresh_token"; // Simuler un token JWT valide décodé par le service

            let result = auth_service.refresh_token(refresh_token, &mock_pool).await;

            assert!(result.is_err());
            match result {
                Err(ApiError::Unauthorized(msg)) => {
                    assert!(msg.contains("Session has been revoked"));
                },
                _ => panic!("Expected Unauthorized error"),
            }
        }

        #[tokio::test]
        async fn test_invalidate_token_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_session_manager = MockSessionManager::new();

            let session_id = Uuid::from_str("00000000-0000-0000-0000-000000000002").unwrap();

            mock_session_manager.expect_invalidate_session()
                .with(eq(session_id), any())
                .times(1)
                .returning(|_, _| Ok(()));

            let auth_service = AuthService {
                session_manager: mock_session_manager,
                mfa_issuer: "test-issuer".to_string(),
            };

            // Créer un refresh token valide
            let refresh_token = "valid_refresh_token"; // Simuler un token JWT valide décodé par le service

            let result = auth_service.invalidate_token(refresh_token, &mock_pool).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_verify_mfa_code_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer le secret MFA de l'utilisateur
            mock_client.expect_query_one()
                .with(eq("SELECT mfa_secret FROM users WHERE id = $1 AND mfa_enabled = true"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("mfa_secret", "JBSWY3DPEHPK3PXP") // Secret TOTP valide
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            // Code MFA valide pour le secret donné (simulé)
            let code = "123456";

            let result = auth_service.verify_mfa_code(user_id, code, &mock_pool).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_verify_mfa_code_invalid() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer le secret MFA de l'utilisateur
            mock_client.expect_query_one()
                .with(eq("SELECT mfa_secret FROM users WHERE id = $1 AND mfa_enabled = true"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("mfa_secret", "JBSWY3DPEHPK3PXP") // Secret TOTP valide
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            // Code MFA invalide pour le secret donné
            let code = "999999";

            let result = auth_service.verify_mfa_code(user_id, code, &mock_pool).await;

            assert!(result.is_err());
            match result {
                Err(ApiError::Unauthorized(msg)) => {
                    assert!(msg.contains("Invalid MFA code"));
                },
                _ => panic!("Expected Unauthorized error"),
            }
        }

        #[tokio::test]
        async fn test_generate_mfa_setup_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer l'utilisateur
            mock_client.expect_query_one()
                .with(eq("SELECT email FROM users WHERE id = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("email", "test@example.com")
                        .build();
                    Ok(row)
                });

            // Configure mock pour mettre à jour le secret MFA de l'utilisateur
            mock_client.expect_execute()
                .with(eq("UPDATE users SET mfa_secret = $1 WHERE id = $2"), any())
                .times(1)
                .returning(|_, _| Ok(1));

            mock_pool.expect_get()
                .times(2)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.generate_mfa_setup(user_id, &mock_pool).await;

            assert!(result.is_ok());

            let setup_info = result.unwrap();
            assert!(!setup_info.secret.is_empty());
            assert!(setup_info.provisioning_uri.contains("test@example.com"));
        }

        #[tokio::test]
        async fn test_verify_and_activate_mfa_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer le secret MFA de l'utilisateur
            mock_client.expect_query_one()
                .with(eq("SELECT mfa_secret FROM users WHERE id = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("mfa_secret", "JBSWY3DPEHPK3PXP") // Secret TOTP valide
                        .build();
                    Ok(row)
                });

            // Configure mock pour activer MFA pour l'utilisateur
            mock_client.expect_execute()
                .with(eq("UPDATE users SET mfa_enabled = true WHERE id = $1"), any())
                .times(1)
                .returning(|_, _| Ok(1));

            mock_pool.expect_get()
                .times(2)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            // Code MFA valide pour le secret donné (simulé)
            let code = "123456";

            let result = auth_service.verify_and_activate_mfa(user_id, code, &mock_pool).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_verify_and_activate_mfa_invalid_code() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer le secret MFA de l'utilisateur
            mock_client.expect_query_one()
                .with(eq("SELECT mfa_secret FROM users WHERE id = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("mfa_secret", "JBSWY3DPEHPK3PXP") // Secret TOTP valide
                        .build();
                    Ok(row)
                });

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            // Code MFA invalide pour le secret donné
            let code = "999999";

            let result = auth_service.verify_and_activate_mfa(user_id, code, &mock_pool).await;

            assert!(result.is_err());
            match result {
                Err(ApiError::Unauthorized(msg)) => {
                    assert!(msg.contains("Invalid MFA code"));
                },
                _ => panic!("Expected Unauthorized error"),
            }
        }

        #[tokio::test]
        async fn test_disable_mfa_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour désactiver MFA pour l'utilisateur
            mock_client.expect_execute()
                .with(eq("UPDATE users SET mfa_enabled = false, mfa_secret = NULL WHERE id = $1"), any())
                .times(1)
                .returning(|_, _| Ok(1));

            mock_pool.expect_get()
                .times(1)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.disable_mfa(user_id, &mock_pool).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_change_password_success() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer le hash de mot de passe actuel
            mock_client.expect_query_one()
                .with(eq("SELECT password_hash FROM users WHERE id = $1"), any())
                .times(1)
                .returning(|_, _| {
                    let row = MockRow::new()
                        .add_column("password_hash", "$2b$12$S9vahIaQY.lpMOv/s9bFFeaGKRz1r9N6pW5AsbLiJRGGET1vKqhAS") // 'current_password' hashed
                        .build();
                    Ok(row)
                });

            // Configure mock pour mettre à jour le mot de passe
            mock_client.expect_execute()
                .with(eq("UPDATE users SET password_hash = $1 WHERE id = $2"), any())
                .times(1)
                .returning(|_, _| Ok(1));

            mock_pool.expect_get()
                .times(2)
                .returning(move || Ok(mock_client.clone()));

            let auth_service = create_test_auth_service();

            let result = auth_service.change_password(
                user_id,
                "current_password",
                "new_secure_password",
                &mock_pool
            ).await;

            assert!(result.is_ok());
        }

        #[tokio::test]
        async fn test_change_password_invalid_current() {
            let mut mock_pool = MockPostgresPool::new();
            let mut mock_client = MockPostgresClient::new();

            let user_id = test_uuid();

            // Configure mock pour récupérer le hash de mot
}