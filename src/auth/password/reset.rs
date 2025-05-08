//! Password reset functionality.
//!
//! Manages password reset tokens, expiration, and password rotation policies.

use chrono::{DateTime, Duration, Utc};
use deadpool_postgres::Client;
use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_pg_mapper::{FromTokioPostgresRow, PostgresMapper};
use tokio_pg_mapper_derive::PostgresMapper;
use uuid::Uuid;

/// Duration after which a password reset token expires (in hours)
pub const TOKEN_EXPIRY_HOURS: i64 = 24;

/// Duration after which a password should be rotated (in days)
pub const PASSWORD_ROTATION_DAYS: i64 = 90;

#[derive(Debug, Error)]
pub enum PasswordResetError {
  #[error("Database error: {0}")]
  DatabaseError(String),

  #[error("Token generation error: {0}")]
  TokenGenerationError(String),

  #[error("Invalid or expired token")]
  InvalidToken,

  #[error("Password recently used")]
  PasswordRecentlyUsed,
}

/// Password reset token model
#[derive(Serialize, Deserialize, PostgresMapper)]
#[pg_mapper(table = "password_reset_tokens")]
pub struct PasswordResetToken {
  pub id: Uuid,
  pub user_id: Uuid,
  pub token: String,
  pub created_at: DateTime<Utc>,
  pub expires_at: DateTime<Utc>,
  pub used: bool,
}

/// Password rotation status
#[derive(Debug, Serialize, Deserialize)]
pub struct PasswordRotationStatus {
  pub last_changed: DateTime<Utc>,
  pub days_remaining: i64,
  pub rotation_required: bool,
}

impl PasswordResetToken {
  /// Create a new password reset token for a user
  pub async fn create_token(client: &Client, user_id: Uuid) -> Result<String, PasswordResetError> {
    // Generate a random token
    let token: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let now = Utc::now();
    let expires_at = now + Duration::hours(TOKEN_EXPIRY_HOURS);

    // Delete any existing tokens for this user
    let _result = client
        .execute(
          "DELETE FROM password_reset_tokens WHERE user_id = $1",
          &[&user_id],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    // Insert the new token
    let _result = client
        .execute(
          "INSERT INTO password_reset_tokens (id, user_id, token, created_at, expires_at, used)
                 VALUES ($1, $2, $3, $4, $5, $6)",
          &[
            &Uuid::new_v4(),
            &user_id,
            &token,
            &now,
            &expires_at,
            &false,
          ],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(token)
  }

  /// Check if a token is valid and not expired or used
  pub async fn check_token(client: &Client, token: &str) -> Result<Option<Self>, PasswordResetError> {
    let now = Utc::now();

    let row = client
        .query_opt(
          "SELECT id, user_id, token, created_at, expires_at, used
                 FROM password_reset_tokens 
                 WHERE token = $1 AND expires_at > $2 AND used = false",
          &[&token, &now],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    if let Some(row) = row {
      let token_record = PasswordResetToken::from_row(row)
          .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;
      Ok(Some(token_record))
    } else {
      Ok(None)
    }
  }

  /// Mark a token as used
  pub async fn mark_as_used(client: &Client, token: &str) -> Result<(), PasswordResetError> {
    let result = client
        .execute(
          "UPDATE password_reset_tokens SET used = true WHERE token = $1",
          &[&token],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    if result > 0 {
      Ok(())
    } else {
      Err(PasswordResetError::InvalidToken)
    }
  }

  /// Delete a token by its value
  pub async fn delete_by_token(client: &Client, token: &str) -> Result<(), PasswordResetError> {
    let _result = client
        .execute(
          "DELETE FROM password_reset_tokens WHERE token = $1",
          &[&token],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(())
  }

  /// Clean up expired tokens (should be run periodically)
  pub async fn clean_expired_tokens(client: &Client) -> Result<u64, PasswordResetError> {
    let now = Utc::now();

    let result = client
        .execute(
          "DELETE FROM password_reset_tokens WHERE expires_at < $1",
          &[&now],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(result)
  }
}

/// Password rotation management functions
pub struct PasswordRotationManager;

impl PasswordRotationManager {
  /// Check if a password needs rotation based on last change date
  pub fn check_rotation_status(last_changed: DateTime<Utc>) -> PasswordRotationStatus {
    let now = Utc::now();
    let elapsed = now.signed_duration_since(last_changed);
    let elapsed_days = elapsed.num_days();

    let days_remaining = if elapsed_days >= PASSWORD_ROTATION_DAYS {
      0
    } else {
      PASSWORD_ROTATION_DAYS - elapsed_days
    };

    PasswordRotationStatus {
      last_changed,
      days_remaining,
      rotation_required: elapsed_days >= PASSWORD_ROTATION_DAYS,
    }
  }

  /// Update the password last changed timestamp for a user
  pub async fn update_password_changed(client: &Client, user_id: Uuid) -> Result<(), PasswordResetError> {
    let now = Utc::now();

    let _result = client
        .execute(
          "UPDATE users SET password_last_changed = $1 WHERE id = $2",
          &[&now, &user_id],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    Ok(())
  }

  /// Get all users whose passwords need rotation
  pub async fn get_users_needing_rotation(client: &Client) -> Result<Vec<Uuid>, PasswordResetError> {
    let rotation_threshold = Utc::now() - Duration::days(PASSWORD_ROTATION_DAYS);

    let rows = client
        .query(
          "SELECT id FROM users WHERE password_last_changed < $1 OR password_last_changed IS NULL",
          &[&rotation_threshold],
        )
        .await
        .map_err(|e| PasswordResetError::DatabaseError(e.to_string()))?;

    let user_ids = rows.iter()
        .map(|row| row.get::<_, Uuid>("id"))
        .collect();

    Ok(user_ids)
  }
}

/// Password reset notification service
pub struct PasswordResetNotifier;

impl PasswordResetNotifier {
  /// Send a password reset email to a user
  pub async fn send_reset_email(email: &str, token: &str, base_url: &str) -> Result<(), PasswordResetError> {
    // This would integrate with your email service
    // For now, we'll just log the details
    println!(
      "Password reset email would be sent to {} with token {} and reset URL: {}/reset-password?token={}",
      email, token, base_url, token
    );

    Ok(())
  }

  /// Send a password rotation reminder email
  pub async fn send_rotation_reminder(email: &str, days_remaining: i64) -> Result<(), PasswordResetError> {
    // This would integrate with your email service
    println!(
      "Password rotation reminder would be sent to {}. Days remaining: {}",
      email, days_remaining
    );

    Ok(())
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use chrono::Duration;

  #[test]
  fn test_rotation_status_not_required() {
    let last_changed = Utc::now() - Duration::days(30);
    let status = PasswordRotationManager::check_rotation_status(last_changed);

    assert!(!status.rotation_required);
    assert_eq!(status.days_remaining, PASSWORD_ROTATION_DAYS - 30);
  }

  #[test]
  fn test_rotation_status_required() {
    let last_changed = Utc::now() - Duration::days(PASSWORD_ROTATION_DAYS + 1);
    let status = PasswordRotationManager::check_rotation_status(last_changed);

    assert!(status.rotation_required);
    assert_eq!(status.days_remaining, 0);
  }
}