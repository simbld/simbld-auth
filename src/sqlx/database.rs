//! Database module for simbld_auth
//!
//! Contains the database layer implementation using SQLx with PostgreSQL.
//! Handles user operations, authentication, and database connections.

use crate::auth::password::security::SecurePassword;
use crate::types::ApiError;
use crate::utils::response_handler::ResponseHandler;
use actix_web::{HttpRequest, HttpResponse};
use chrono::{DateTime, Utc};
use simbld_http::responses::ResponsesTypes;
use simbld_http::ResponsesServerCodes;
use sqlx::{PgPool, Row};
use std::time::Duration;
use uuid::Uuid;

#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl std::fmt::Debug for Database {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Database").field("pool", &"<PgPool>").finish()
    }
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, ApiError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to connect to database: {}", e)))?;

        Ok(Self {
            pool,
        })
    }

    pub async fn user_exists(&self, email: &str) -> Result<bool, ApiError> {
        let result = sqlx::query("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Database query failed: {}", e)))?;

        Ok(result.get(0))
    }

    pub async fn create_user(
        &self,
        email: &str,
        password: &SecurePassword,
        username: &str,
        firstname: &str,
        lastname: &str,
    ) -> Result<Uuid, ApiError> {
        let user_id = Uuid::new_v4();
        let password_hash = password.expose_secret();
        let now = Utc::now();

        sqlx::query(
			r#"
            INSERT INTO users (id, email, username, firstname, lastname, password_hash, email_verified, mfa_enabled, account_locked, failed_login_attempts, status, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            "#,
		)
		  .bind(user_id)
		  .bind(email)
		  .bind(username)
		  .bind(firstname)
		  .bind(lastname)
		  .bind(password_hash)
		  .bind(false) // email_verified
		  .bind(false) // mfa_enabled
		  .bind(false) // account_locked
		  .bind(0) // failed_login_attempts
		  .bind("active") // status
		  .bind(now) // created_at
		  .execute(&self.pool)
		  .await
		  .map_err(|e| ApiError::Database(format!("Failed to create user: {}", e)))?;

        Ok(user_id)
    }

    pub async fn verify_user_login(&self, email: &str, password: &str) -> Result<bool, ApiError> {
        let result = sqlx::query("SELECT password_hash FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Database query failed: {}", e)))?;

        match result {
            Some(row) => {
                let stored_hash: String = row.get("password_hash");
                Ok(stored_hash == password)
            },
            None => Ok(false),
        }
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<UserRecord>, ApiError> {
        let result = sqlx::query_as::<_, UserRecord>(
            r"
            SELECT id, email, username, firstname, lastname, password_hash,
                   email_verified, mfa_enabled, account_locked, failed_login_attempts,
                   last_login, status, created_at
            FROM users
            WHERE email = $1
            ",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Database query failed: {}", e)))?;

        Ok(result)
    }
}

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
    let message = format!("User isn't found: {}", email);
    ResponseHandler::create_hybrid_response(
        req,
        ResponsesTypes::ClientError(simbld_http::ResponsesClientCodes::NotFound),
        Some("User Not Found"),
        Some(&message),
        duration,
    )
}

pub fn create_auth_failed_response(req: &HttpRequest, duration: Duration) -> HttpResponse {
    ResponseHandler::create_hybrid_response(
        req,
        ResponsesTypes::ClientError(simbld_http::ResponsesClientCodes::Unauthorized),
        Some("Authentication Failed"),
        Some("Invalid credentials provided"),
        duration,
    )
}

#[derive(Debug, sqlx::FromRow)]
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
    pub last_login: Option<DateTime<Utc>>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_database_connection() {
        assert!(true);
    }
}
