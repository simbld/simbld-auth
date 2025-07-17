//! Database connection and user management operations
//!
//! This module provides secure database operations with proper password hashing
//! and verification using Argon2id encryption.

use crate::auth::password::security::{PasswordService, SecurePassword};
use crate::types::ApiError;
use crate::utils::response_handler::ResponseHandler;
use actix_web::{HttpRequest, HttpResponse};
use simbld_http::responses::ResponsesTypes;
use simbld_http::{ResponsesClientCodes, ResponsesServerCodes};
use sqlx::{PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

/// Database connection pool wrapper
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database connection with health check
    pub async fn new(database_url: &str) -> Result<Self, ApiError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to connect: {e}")))?;

        // Test connection
        let _test = sqlx::query("SELECT 1")
            .fetch_one(&pool)
            .await
            .map_err(|e| ApiError::Database(format!("Connection test failed: {e}")))?;

        println!("✅ Database connection established successfully.");

        Ok(Database {
            pool,
        })
    }

    /// Check if a user exists by email
    pub async fn user_exists(&self, email: &str) -> Result<bool, ApiError> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM users WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to check user existence: {e}")))?;

        let count: i64 = result
            .try_get("count")
            .map_err(|e| ApiError::Database(format!("Failed to get count: {e}")))?;

        Ok(count > 0)
    }

    /// Create a new user with secure password hashing
    pub async fn create_user(
        &self,
        email: &str,
        password: &SecurePassword,
        username: &str,
        firstname: &str,
        lastname: &str,
    ) -> Result<Uuid, ApiError> {
        // 🔒 Hash password securely
        let password_hash = PasswordService::hash_secure_password(password)
            .map_err(|e| ApiError::Database(format!("Failed to hash password: {e}")))?;

        let result = sqlx::query(
            "INSERT INTO users (email, password, username, firstname, lastname)
             VALUES ($1, $2, $3, $4, $5) 
             RETURNING id",
        )
        .bind(email)
        .bind(password_hash) // 🔒 Store hashed password
        .bind(username)
        .bind(firstname)
        .bind(lastname)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to create user: {e}")))?;

        let id: Uuid = result
            .try_get("id")
            .map_err(|e| ApiError::Database(format!("Failed to get user ID: {e}")))?;

        Ok(id)
    }

    /// Verify user login with secure password verification
    pub async fn verify_user_login(&self, email: &str, password: &str) -> Result<bool, ApiError> {
        // 🔒 Get a user's hashed password from a database
        let result = sqlx::query("SELECT password FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to fetch user: {e}")))?;

        if let Some(row) = result {
            let stored_hash: String = row
                .try_get("password")
                .map_err(|e| ApiError::Database(format!("Failed to get password hash: {e}")))?;

            // 🔒 Verify password against stored hash
            PasswordService::verify_password(password, &stored_hash)
                .map_err(|e| ApiError::Database(format!("Password verification failed: {e}")))
        } else {
            // User not found
            Ok(false)
        }
    }

    /// Get user by email for authentication
    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, ApiError> {
        let result = sqlx::query(
            "SELECT id, email, username, firstname, lastname, password, email_verified,
                    mfa_enabled, account_locked, failed_login_attempts, last_login, status 
             FROM users WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to fetch user: {e}")))?;

        if let Some(row) = result {
            Ok(Some(UserRecord {
                id: row
                    .try_get("id")
                    .map_err(|e| ApiError::Database(format!("Failed to get id: {e}")))?,
                email: row
                    .try_get("email")
                    .map_err(|e| ApiError::Database(format!("Failed to get email: {e}")))?,
                username: row
                    .try_get("username")
                    .map_err(|e| ApiError::Database(format!("Failed to get username: {e}")))?,
                firstname: row
                    .try_get("firstname")
                    .map_err(|e| ApiError::Database(format!("Failed to get the firstname: {e}")))?,
                lastname: row
                    .try_get("lastname")
                    .map_err(|e| ApiError::Database(format!("Failed to get lastname: {e}")))?,
                password_hash: row
                    .try_get("password")
                    .map_err(|e| ApiError::Database(format!("Failed to get password: {e}")))?,
                email_verified: row.try_get("email_verified").map_err(|e| {
                    ApiError::Database(format!("Failed to get email_verified: {e}"))
                })?,
                mfa_enabled: row
                    .try_get("mfa_enabled")
                    .map_err(|e| ApiError::Database(format!("Failed to get mfa_enabled: {e}")))?,
                account_locked: row.try_get("account_locked").map_err(|e| {
                    ApiError::Database(format!("Failed to get account_locked: {e}"))
                })?,
                failed_login_attempts: row.try_get("failed_login_attempts").map_err(|e| {
                    ApiError::Database(format!("Failed to get failed_login_attempts: {e}"))
                })?,
                last_login: row
                    .try_get("last_login")
                    .map_err(|e| ApiError::Database(format!("Failed to get last_login: {e}")))?,
                status: row
                    .try_get("status")
                    .map_err(|e| ApiError::Database(format!("Failed to get status: {e}")))?,
            }))
        } else {
            Ok(None)
        }
    }
}

/// 🔧 Helper methods for creating standardized error responses
pub fn create_database_error_response(
    req: &HttpRequest,
    error_message: &str,
    duration: Duration,
) -> HttpResponse {
    ResponseHandler::create_hybrid_response(
        req,
        ResponsesTypes::ServerError(ResponsesServerCodes::InternalServerError),
        Some("Database Error"),
        Some(error_message),
        duration,
    )
}

pub fn create_user_not_found_response(
    req: &HttpRequest,
    email: &str,
    duration: Duration,
) -> HttpResponse {
    ResponseHandler::create_hybrid_response(
        req,
        ResponsesTypes::ClientError(ResponsesClientCodes::NotFound),
        Some("User Not Found"),
        Some(&format!("No user found with email: {}", email)),
        duration,
    )
}

pub fn create_auth_failed_response(req: &HttpRequest, duration: Duration) -> HttpResponse {
    ResponseHandler::create_hybrid_response(
        req,
        ResponsesTypes::ClientError(ResponsesClientCodes::Unauthorized),
        Some("Authentication Failed"),
        Some("Invalid email or password"),
        duration,
    )
}

/// User record from Database
#[derive(Debug)]
pub struct UserRecord {
    pub id: Uuid,
    pub email: String,
    pub username: String,
    pub firstname: String,
    pub lastname: String,
    pub password_hash: String,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub account_locked: bool,
    pub failed_login_attempts: i32,
    pub last_login: Option<chrono::DateTime<chrono::Utc>>,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_connection() {
        // Test database connection
        let db_url = std::env::var("TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://localhost/test_simbld_auth".to_string());

        let db = Database::new(&db_url).await;
        assert!(db.is_ok(), "Database connection should succeed");
    }
}
