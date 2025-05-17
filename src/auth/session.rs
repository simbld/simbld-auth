//! Session management for authenticated users.
//!
//! Handles session tokens, refresh tokens, and device tracking.

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_pg_mapper::PostgresMapper;
use tokio_pg_mapper_derive::PostgresMapper;
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

/// Session data stored in the database
#[derive(Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "user_sessions")]
pub struct UserSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token: String,
    pub refresh_token: String,
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked: bool,
}

/// Session service for managing authenticated sessions
pub struct SessionService;

impl SessionService {
    /// Create a new session for an authenticated user
    pub async fn create_session(
        client: &Client,
        user_id: Uuid,
        device_info: Option<DeviceInfo>,
        remember_me: bool,
    ) -> Result<SessionTokens, SessionError> {
        let session_id = Uuid::new_v4();
        let token = Self::generate_session_token(session_id);
        let refresh_token = Self::generate_refresh_token(session_id);

        let now = Utc::now();
        let duration = if remember_me {
            Duration::days(30) // Longue durée si "remember me"
        } else {
            Duration::hours(24) // Session standard de 24h
        };

        let expires_at = now + duration;

        // Extraire les infos de l'appareil si disponibles
        let (device_id, ip_address, user_agent) = match device_info {
            Some(info) => (info.device_id, info.ip_address, info.user_agent),
            None => (None, None, None),
        };

        // Insérer la session en base de données
        client
            .execute(
                "INSERT INTO user_sessions
                (id, user_id, token, refresh_token, device_id, ip_address, user_agent,
                created_at, expires_at, revoked)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
                &[
                    &session_id,
                    &user_id,
                    &token,
                    &refresh_token,
                    &device_id,
                    &ip_address,
                    &user_agent,
                    &now,
                    &expires_at,
                    &false,
                ],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(SessionTokens {
            token,
            refresh_token,
            expires_at: expires_at.timestamp(),
        })
    }

    /// Validate a session token
    pub async fn validate_session(
        client: &Client,
        token: &str,
    ) -> Result<UserSession, SessionError> {
        let row = client
            .query_opt(
                "SELECT * FROM user_sessions WHERE token = $1 AND revoked = false",
                &[&token],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        let session = match row {
            Some(row) => UserSession::from_row(&row)
                .map_err(|e| SessionError::DatabaseError(e.to_string()))?,
            None => return Err(SessionError::SessionNotFound),
        };

        // Vérifier si la session a expiré
        let now = Utc::now();
        if session.expires_at < now {
            return Err(SessionError::SessionExpired);
        }

        // Mettre à jour last_used_at
        client
            .execute(
                "UPDATE user_sessions SET last_used_at = $1 WHERE id = $2",
                &[&now, &session.id],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(session)
    }

    /// Refresh a session using a refresh token
    pub async fn refresh_session(
        client: &Client,
        refresh_token: &str,
    ) -> Result<SessionTokens, SessionError> {
        // Trouver la session associée au refresh token
        let row = client
            .query_opt(
                "SELECT * FROM user_sessions WHERE refresh_token = $1 AND revoked = false",
                &[&refresh_token],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        let session = match row {
            Some(row) => UserSession::from_row(&row)
                .map_err(|e| SessionError::DatabaseError(e.to_string()))?,
            None => return Err(SessionError::InvalidToken),
        };

        // Vérifier si le refresh token a expiré
        // Typiquement, les refresh tokens peuvent durer plus longtemps que les sessions
        let now = Utc::now();
        if session.expires_at + Duration::days(7) < now {
            return Err(SessionError::SessionExpired);
        }

        // Générer de nouveaux tokens
        let new_token = Self::generate_session_token(session.id);
        let new_refresh_token = Self::generate_refresh_token(session.id);

        // Calculer la nouvelle date d'expiration
        let expires_at = now + Duration::hours(24);

        // Mettre à jour la session
        client
            .execute(
                "UPDATE user_sessions SET token = $1, refresh_token = $2,
                expires_at = $3, last_used_at = $4 WHERE id = $5",
                &[&new_token, &new_refresh_token, &expires_at, &now, &session.id],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(SessionTokens {
            token: new_token,
            refresh_token: new_refresh_token,
            expires_at: expires_at.timestamp(),
        })
    }

    /// Revoke a session (logout)
    pub async fn revoke_session(
        client: &Client,
        token: &str,
    ) -> Result<(), SessionError> {
        let result = client
            .execute(
                "UPDATE user_sessions SET revoked = true WHERE token = $1",
                &[&token],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        if result == 0 {
            return Err(SessionError::SessionNotFound);
        }

        Ok(())
    }

    /// Revoke all sessions for a user (logout from all devices)
    pub async fn revoke_all_sessions(
        client: &Client,
        user_id: Uuid,
    ) -> Result<usize, SessionError> {
        let result = client
            .execute(
                "UPDATE user_sessions SET revoked = true WHERE user_id = $1 AND revoked = false",
                &[&user_id],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        Ok(result as usize)
    }

    /// List all active sessions for a user
    pub async fn list_sessions(
        client: &Client,
        user_id: Uuid,
    ) -> Result<Vec<SessionInfo>, SessionError> {
        let rows = client
            .query(
                "SELECT id, device_id, ip_address, user_agent, created_at, expires_at, last_used_at
                FROM user_sessions
                WHERE user_id = $1 AND revoked = false",
                &[&user_id],
            )
            .await
            .map_err(|e| SessionError::DatabaseError(e.to_string()))?;

        let sessions = rows
            .iter()
            .map(|row| SessionInfo {
                id: row.get("id"),
                device_id: row.get("device_id"),
                ip_address: row.get("ip_address"),
                user_agent: row.get("user_agent"),
                created_at: row.get::<_, DateTime<Utc>>("created_at").timestamp(),
                expires_at: row.get::<_, DateTime<Utc>>("expires_at").timestamp(),
                last_used_at: row.get::<_, Option<DateTime<Utc>>>("last_used_at")
                    .map(|dt| dt.timestamp()),
            })
            .collect();

        Ok(sessions)
    }

    /// Generate a session token
    fn generate_session_token(session_id: Uuid) -> String {
        // Dans une implémentation réelle, utilisez JWT ou un autre mécanisme sécurisé
        format!("session_{}", session_id)
    }

    /// Generate a refresh token
    fn generate_refresh_token(session_id: Uuid) -> String {
        // Dans une implémentation réelle, utilisez un mécanisme sécurisé
        format!("refresh_{}", session_id)
    }
}

/// Device information for session tracking
#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// Session tokens returned after authentication
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionTokens {
    pub token: String,
    pub refresh_token: String,
    pub expires_at: i64,
}

/// Session information for display to users
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: Uuid,
    pub device_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: i64,
    pub expires_at: i64,
    pub last_used_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use tokio_postgres::Client;
    use std::str::FromStr;
    use mockall::{mock, predicate};

    // Mocking the PostgreSQL client for testing
    mock! {
        PostgresClient {}
        impl Clone for PostgresClient {
            fn clone(&self) -> Self;
        }
        // Add other methods that Client has that we need to mock
    }

    #[tokio::test]
    async fn test_create_session() {
        // Arrange
        let user_id = Uuid::new_v4();
        let device_info = Some(DeviceInfo {
            device_id: Some("device123".to_string()),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        });
        let remember_me = true;

        // Setup mock DB
        // Note: This is a simplified example - you would need to set up appropriate
        // expectations based on your actual implementation

        // Act
        let result = SessionService::create_session(&client, user_id, device_info, remember_me).await;

        // Assert
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert!(!tokens.token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
        assert!(tokens.expires_at > Utc::now().timestamp());
    }

    #[tokio::test]
    async fn test_validate_session_valid() {
        // Arrange
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let token = SessionService::generate_session_token(session_id);

        // Act
        let result = SessionService::validate_session(&client, &token).await;

        // Assert
        assert!(result.is_ok());
        let session = result.unwrap();
        assert_eq!(session.id, session_id);
        assert_eq!(session.user_id, user_id);
        assert_eq!(session.token, token);
        assert!(!session.revoked);
    }

    #[tokio::test]
    async fn test_validate_session_expired() {
        // Arrange
        let token = "expired_token";

        // Act
        let result = SessionService::validate_session(&client, token).await;

        // Assert
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SessionError::SessionExpired));
    }

    #[tokio::test]
    async fn test_validate_session_not_found() {
        // Arrange
        let token = "nonexistent_token";

        // Act
        let result = SessionService::validate_session(&client, token).await;

        // Assert
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SessionError::SessionNotFound));
    }

    #[tokio::test]
    async fn test_refresh_session() {
        // Arrange
        let refresh_token = "valid_refresh_token";

        // Act
        let result = SessionService::refresh_session(&client, refresh_token).await;

        // Assert
        assert!(result.is_ok());
        let tokens = result.unwrap();
        assert!(!tokens.token.is_empty());
        assert!(!tokens.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_session() {
        // Arrange
        let token = "valid_token";

        // Act
        let result = SessionService::revoke_session(&client, token).await;

        // Assert
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_revoke_all_sessions() {
        // Arrange
        let user_id = Uuid::new_v4();

        // Act
        let result = SessionService::revoke_all_sessions(&client, user_id).await;

        // Assert
        assert!(result.is_ok());
        assert!(result.unwrap() > 0); // Revoked at least one session
    }

    #[tokio::test]
    async fn test_list_sessions() {
        // Arrange
        let user_id = Uuid::new_v4();

        // Act
        let result = SessionService::list_sessions(&client, user_id).await;

        // Assert
        assert!(result.is_ok());
        let sessions = result.unwrap();
        assert!(!sessions.is_empty());
    }

    #[test]
    fn test_generate_session_token() {
        // Arrange
        let session_id = Uuid::new_v4();

        // Act
        let token = SessionService::generate_session_token(session_id);

        // Assert
        assert!(!token.is_empty());
    }

    #[test]
    fn test_generate_refresh_token() {
        // Arrange
        let session_id = Uuid::new_v4();

        // Act
        let token = SessionService::generate_refresh_token(session_id);

        // Assert
        assert!(!token.is_empty());
    }
}