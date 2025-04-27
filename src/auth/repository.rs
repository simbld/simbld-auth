use chrono::{DateTime, Utc};
use deadpool_postgres::Client;
use thiserror::Error;
use tokio_pg_mapper::FromTokioPostgresRow;
use uuid::Uuid;

use crate::auth::models::{User, Role, RefreshToken, OAuthProvider, LoginAttempt};

#[derive(Error, Debug)]
pub enum RepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("User not found")]
    UserNotFound,
    #[error("Role not found")]
    RoleNotFound,
    #[error("Token not found")]
    TokenNotFound,
    #[error("Data error: {0}")]
    DataError(String),
}

pub struct AuthRepository;

impl AuthRepository {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn create_user(
        &self,
        client: &Client,
        username: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<Uuid, RepositoryError> {
        let user_id = Uuid::new_v4();
        let now = Utc::now();

        let query = "INSERT INTO users
            (id, username, email, password_hash, mfa_enabled, account_locked, failed_login_attempts, created_at, updated_at)
            VALUES ($1, $2, $3, $4, false, false, 0, $5, $5)";

        client
            .execute(
                query,
                &[&user_id, &username, &email, &password_hash, &now],
            )
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(user_id)
    }

    pub async fn find_by_email(&self, client: &Client, email: &str) -> Result<User, RepositoryError> {
        let query = "SELECT * FROM users WHERE email = $1";

        let row = client
            .query_one(query, &[&email])
            .await
            .map_err(|_| RepositoryError::UserNotFound)?;

        let user = User::from_row(row)
            .map_err(|e| RepositoryError::DataError(e.to_string()))?;

        Ok(user)
    }

    pub async fn find_by_id(&self, client: &Client, user_id: Uuid) -> Result<User, RepositoryError> {
        let query = "SELECT * FROM users WHERE id = $1";

        let row = client
            .query_one(query, &[&user_id])
            .await
            .map_err(|_| RepositoryError::UserNotFound)?;

        let user = User::from_row(row)
            .map_err(|e| RepositoryError::DataError(e.to_string()))?;

        Ok(user)
    }

    pub async fn update_failed_login_attempts(
        &self,
        client: &Client,
        user_id: Uuid,
        attempts: i32,
        lock_account: bool,
    ) -> Result<(), RepositoryError> {
        let query = "UPDATE users SET failed_login_attempts = $2, account_locked = $3, updated_at = $4 WHERE id = $1";

        client
            .execute(query, &[&user_id, &attempts, &lock_account, &Utc::now()])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn update_last_login(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let now = Utc::now();
        let query = "UPDATE users SET last_login = $2, updated_at = $2 WHERE id = $1";

        client
            .execute(query, &[&user_id, &now])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn enable_mfa(
        &self,
        client: &Client,
        user_id: Uuid,
        mfa_secret: &str,
    ) -> Result<(), RepositoryError> {
        let query = "UPDATE users SET mfa_enabled = true, mfa_secret = $2, updated_at = $3 WHERE id = $1";

        client
            .execute(query, &[&user_id, &mfa_secret, &Utc::now()])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn disable_mfa(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let query = "UPDATE users SET mfa_enabled = false, mfa_secret = NULL, updated_at = $2 WHERE id = $1";

        client
            .execute(query, &[&user_id, &Utc::now()])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn create_refresh_token(
        &self,
        client: &Client,
        user_id: Uuid,
        token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, RepositoryError> {
        let token_id = Uuid::new_v4();
        let now = Utc::now();

        let query = "INSERT INTO refresh_tokens (id, user_id, token, expires_at, created_at) VALUES ($1, $2, $3, $4, $5)";

        client
            .execute(query, &[&token_id, &user_id, &token, &expires_at, &now])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(token_id)
    }

    pub async fn find_refresh_token(
        &self,
        client: &Client,
        token: &str,
    ) -> Result<RefreshToken, RepositoryError> {
        let query = "SELECT * FROM refresh_tokens WHERE token = $1";

        let row = client
            .query_one(query, &[&token])
            .await
            .map_err(|_| RepositoryError::TokenNotFound)?;

        let refresh_token = RefreshToken::from_row(row)
            .map_err(|e| RepositoryError::DataError(e.to_string()))?;

        Ok(refresh_token)
    }

    pub async fn delete_refresh_token(
        &self,
        client: &Client,
        token: &str,
    ) -> Result<(), RepositoryError> {
        let query = "DELETE FROM refresh_tokens WHERE token = $1";

        client
            .execute(query, &[&token])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn delete_user_refresh_tokens(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<(), RepositoryError> {
        let query = "DELETE FROM refresh_tokens WHERE user_id = $1";

        client
            .execute(query, &[&user_id])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn record_login_attempt(
        &self,
        client: &Client,
        user_id: Option<Uuid>,
        ip_address: &str,
        user_agent: &str,
        success: bool,
    ) -> Result<Uuid, RepositoryError> {
        let attempt_id = Uuid::new_v4();
        let now = Utc::now();

        let query = "INSERT INTO login_attempts (id, user_id, ip_address, user_agent, success, created_at)
                     VALUES ($1, $2, $3, $4, $5, $6)";

        client
            .execute(
                query,
                &[&attempt_id, &user_id, &ip_address, &user_agent, &success, &now],
            )
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(attempt_id)
    }

    pub async fn create_oauth_provider(
        &self,
        client: &Client,
        provider_name: &str,
        provider_user_id: &str,
        user_id: Uuid,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<Uuid, RepositoryError> {
        let provider_id = Uuid::new_v4();
        let now = Utc::now();

        let query = "INSERT INTO oauth_providers
                     (id, provider_name, provider_user_id, user_id, access_token, refresh_token, expires_at, created_at, updated_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)";

        client
            .execute(
                query,
                &[
                    &provider_id,
                    &provider_name,
                    &provider_user_id,
                    &user_id,
                    &access_token,
                    &refresh_token,
                    &expires_at,
                    &now,
                ],
            )
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(provider_id)
    }

    pub async fn find_user_by_oauth(
        &self,
        client: &Client,
        provider_name: &str,
        provider_user_id: &str,
    ) -> Result<Uuid, RepositoryError> {
        let query = "SELECT user_id FROM oauth_providers WHERE provider_name = $1 AND provider_user_id = $2";

        let row = client
            .query_one(query, &[&provider_name, &provider_user_id])
            .await
            .map_err(|_| RepositoryError::UserNotFound)?;

        let user_id: Uuid = row.get("user_id");
        Ok(user_id)
    }

    pub async fn assign_role(
        &self,
        client: &Client,
        user_id: Uuid,
        role_name: &str,
    ) -> Result<(), RepositoryError> {
        // Trouver l'ID du rôle par son nom
        let query = "SELECT id FROM roles WHERE name = $1";

        let row = client
            .query_one(query, &[&role_name])
            .await
            .map_err(|_| RepositoryError::RoleNotFound)?;

        let role_id: Uuid = row.get("id");

        // Assigner le rôle à l'utilisateur
        let query = "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)";

        client
            .execute(query, &[&user_id, &role_id])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    pub async fn get_user_roles(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError> {
        let query = "SELECT r.name FROM roles r
                     JOIN user_roles ur ON r.id = ur.role_id
                     WHERE ur.user_id = $1";

        let rows = client
            .query(query, &[&user_id])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        let roles = rows.iter().map(|row| row.get::<_, String>("name")).collect();

        Ok(roles)
    }

    pub async fn get_user_permissions(
        &self,
        client: &Client,
        user_id: Uuid,
    ) -> Result<Vec<String>, RepositoryError> {
        let query = "SELECT DISTINCT p.name FROM permissions p
                     JOIN role_permissions rp ON p.id = rp.permission_id
                     JOIN user_roles ur ON rp.role_id = ur.role_id
                     WHERE ur.user_id = $1";

        let rows = client
            .query(query, &[&user_id])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        let permissions = rows.iter().map(|row| row.get::<_, String>("name")).collect();

        Ok(permissions)
    }

    pub async fn change_password(
        &self,
        client: &Client,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<(), RepositoryError> {
        let query = "UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1";

        client
            .execute(query, &[&user_id, &password_hash, &Utc::now()])
            .await
            .map_err(|e| RepositoryError::DatabaseError(e.to_string()))?;

        Ok(())
    }
}
