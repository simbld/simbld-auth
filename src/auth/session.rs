//! Session management for authentication
//!
//! Handles user sessions, token validation, and session lifecycle management.

use crate::auth::dto::DeviceInfo;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Session not found")]
    SessionNotFound,

    #[error("Session expired")]
    SessionExpired,

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token generation error")]
    TokenGenerationError,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}

pub struct SessionService;

impl SessionService {
    /// Create a new user session
    pub async fn create_session(
        pool: &PgPool,
        user_id: Uuid,
        device_info: Option<DeviceInfo>,
        remember_me: bool,
    ) -> Result<SessionTokens, SessionError> {
        let session_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = if remember_me {
            now + chrono::Duration::days(30)
        } else {
            now + chrono::Duration::hours(24)
        };

        let session_token = Self::generate_session_token(session_id);

        sqlx::query(
			r"
            INSERT INTO sessions (id, user_id, token, ip_address, user_agent, expires_at, created_at, last_activity)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ",
		)
		  .bind(session_id)
		  .bind(user_id)
		  .bind(&session_token)
		  .bind(device_info.as_ref().and_then(|d| d.ip_address.as_ref()))
		  .bind(device_info.as_ref().and_then(|d| d.user_agent.as_ref()))
		  .bind(expires_at)
		  .bind(now)
		  .bind(now) // last_activity = now
		  .execute(pool)
		  .await
		  .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(SessionTokens {
            token: session_token,
            expires_at: expires_at.timestamp(),
        })
    }

    /// Validate a session token
    pub async fn validate_session(pool: &PgPool, token: &str) -> Result<UserSession, SessionError> {
        let row = sqlx::query(
            r"
            SELECT id, user_id, token, ip_address, user_agent, expires_at, created_at, last_activity
            FROM sessions
            WHERE token = $1 AND expires_at > NOW()
            ",
        )
        .bind(token)
        .fetch_optional(pool)
        .await
        .map_err(|e| SessionError::DatabaseError(e.to_string()))?
        .ok_or(SessionError::SessionNotFound)?;

        let session = UserSession {
            id: row.get("id"),
            user_id: row.get("user_id"),
            token: row.get("token"),
            ip_address: row.get("ip_address"),
            user_agent: row.get("user_agent"),
            expires_at: row.get("expires_at"),
            created_at: row.get("created_at"),
            last_activity: row.get("last_activity"),
        };

        // Update last_activity
        sqlx::query("UPDATE sessions SET last_activity = NOW() WHERE id = $1")
            .bind(session.id)
            .execute(pool)
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(session)
    }

    /// Refresh a session (extend expiration)
    pub async fn refresh_session(
        pool: &PgPool,
        token: &str,
    ) -> Result<SessionTokens, SessionError> {
        let new_expires_at = Utc::now() + chrono::Duration::hours(24);

        let result = sqlx::query(
			"UPDATE sessions SET expires_at = $1, last_activity = NOW() WHERE token = $2 AND expires_at > NOW()"
		)
		  .bind(new_expires_at)
		  .bind(token)
		  .execute(pool)
		  .await
		  .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(SessionError::SessionNotFound);
        }

        Ok(SessionTokens {
            token: token.to_string(),
            expires_at: new_expires_at.timestamp(),
        })
    }

    /// Delete a specific session (log out)
    pub async fn revoke_session(pool: &PgPool, token: &str) -> Result<(), SessionError> {
        sqlx::query("DELETE FROM sessions WHERE token = $1")
            .bind(token)
            .execute(pool)
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    /// Delete all sessions for a user (log out all devices)
    pub async fn revoke_all_sessions(pool: &PgPool, user_id: Uuid) -> Result<usize, SessionError> {
        let result = sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }

    /// List all active sessions for a user
    pub async fn list_sessions(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<SessionInfo>, SessionError> {
        let rows = sqlx::query(
            r"
            SELECT id, ip_address, user_agent, created_at, expires_at, last_activity
            FROM sessions
            WHERE user_id = $1 AND expires_at > NOW()
            ORDER BY last_activity DESC
            ",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        let sessions = rows
            .into_iter()
            .map(|row| SessionInfo {
                id: row.get("id"),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
                created_at: row.get::<DateTime<Utc>, _>("created_at").timestamp(),
                expires_at: row.get::<DateTime<Utc>, _>("expires_at").timestamp(),
                last_activity: row.get::<DateTime<Utc>, _>("last_activity").timestamp(),
            })
            .collect();

        Ok(sessions)
    }

    /// Clean up expired sessions
    pub async fn cleanup_expired_sessions(pool: &PgPool) -> Result<usize, SessionError> {
        let result = sqlx::query("DELETE FROM sessions WHERE expires_at < NOW()")
            .execute(pool)
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(result.rows_affected() as usize)
    }

    /// Generate session token
    fn generate_session_token(session_id: Uuid) -> String {
        format!("sess_{}", session_id.simple())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokens {
    pub token: String,
    pub expires_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_activity: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_session_token() {
        let session_id = Uuid::new_v4();
        let token = SessionService::generate_session_token(session_id);
        assert!(token.starts_with("sess_"));
        assert_eq!(token.len(), 37); // "sess_" + 32 chars UUID simple
    }

    #[tokio::test]
    async fn test_session_tokens_serialization() {
        let tokens = SessionTokens {
            token: "sess_test123".to_string(),
            expires_at: 1_234_567_890,
        };

        let json = serde_json::to_string(&tokens).unwrap();
        let deserialized: SessionTokens = serde_json::from_str(&json).unwrap();

        assert_eq!(tokens.token, deserialized.token);
        assert_eq!(tokens.expires_at, deserialized.expires_at);
    }
}
