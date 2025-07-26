//! User repository implementation
//!
//! Database operations for user management.

use crate::user::error::UserError;
use crate::user::models::{User, UserRole, UserStatus};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

/// User repository trait
#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, UserError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError>;
    async fn update_profile(
        &self,
        user_id: Uuid,
        firstname: Option<String>,
        lastname: Option<String>,
        username: Option<String>,
    ) -> Result<(), UserError>;
    async fn update_password(&self, user_id: Uuid, password: String) -> Result<(), UserError>;
    async fn update_status(&self, user_id: Uuid, status: UserStatus) -> Result<(), UserError>;
    async fn list_users(
        &self,
        limit: i64,
        offset: i64,
        status: Option<UserStatus>,
        search: Option<String>,
    ) -> Result<Vec<User>, UserError>;
    async fn count_users(
        &self,
        status: Option<UserStatus>,
        search: Option<String>,
    ) -> Result<i64, UserError>;
    async fn assign_role(&self, user_id: Uuid, role: UserRole) -> Result<(), UserError>;
    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<UserRole>, UserError>;
    async fn get_user_stats(&self) -> Result<UserStatsData, UserError>;
}

/// PostgreSQL implementation
pub struct PgUserRepository {
    pool: Arc<PgPool>,
}

impl PgUserRepository {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self {
            pool,
        }
    }

    // Fonction helper pour éviter la duplication de code
    fn row_to_user(&self, row: sqlx::postgres::PgRow) -> User {
        User {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            firstname: row.get("firstname"),
            lastname: row.get("lastname"),
            password: row.get("password"),
            email_verified: row.get("email_verified"),
            mfa_enabled: row.get("mfa_enabled"),
            mfa_secret: row.get("mfa_secret"),
            account_locked: row.get("account_locked"),
            failed_login_attempts: row.get("failed_login_attempts"),
            last_login: row.get("last_login"),
            password_changed_at: row.get("password_changed_at"),
            password_history: row.get("password_history"),
            password_expires_at: row.get("password_expires_at"),
            require_password_change: row.get("require_password_change"),
            status: row.get::<Option<UserStatus>, _>("status").unwrap_or(UserStatus::Pending),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, UserError> {
        let user = sqlx::query(
            "
            SELECT id, username, email, firstname, lastname, password,
                   email_verified, mfa_enabled, mfa_secret, account_locked,
                   failed_login_attempts, last_login, password_changed_at,
                   password_history, password_expires_at, require_password_change,
                   status, created_at, updated_at
            FROM users
            WHERE id = $1
            ",
        )
        .bind(id)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user.map(|row| self.row_to_user(row)))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let user = sqlx::query(
            "
            SELECT id, username, email, firstname, lastname, password,
                   email_verified, mfa_enabled, mfa_secret, account_locked,
                   failed_login_attempts, last_login, password_changed_at,
                   password_history, password_expires_at, require_password_change,
                   status, created_at, updated_at
            FROM users
            WHERE email = $1
            ",
        )
        .bind(email)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user.map(|row| self.row_to_user(row)))
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        let user = sqlx::query(
            "
            SELECT id, username, email, firstname, lastname, password,
                   email_verified, mfa_enabled, mfa_secret, account_locked,
                   failed_login_attempts, last_login, password_changed_at,
                   password_history, password_expires_at, require_password_change,
                   status, created_at, updated_at
            FROM users
            WHERE username = $1
            ",
        )
        .bind(username)
        .fetch_optional(&*self.pool)
        .await?;

        Ok(user.map(|row| self.row_to_user(row)))
    }

    async fn update_profile(
        &self,
        user_id: Uuid,
        firstname: Option<String>,
        lastname: Option<String>,
        username: Option<String>,
    ) -> Result<(), UserError> {
        match (&firstname, &lastname, &username) {
            (Some(fn_), Some(ln_), Some(un_)) => {
                sqlx::query!(
                    "UPDATE users SET firstname = $1, lastname = $2, username = $3, updated_at = NOW() WHERE id = $4",
                    fn_, ln_, un_, user_id
                )
				  .execute(&*self.pool)
				  .await?;
            },
            (Some(fn_), Some(ln_), None) => {
                sqlx::query!(
                    "UPDATE users SET firstname = $1, lastname = $2, updated_at = NOW() WHERE id = $3",
                    fn_, ln_, user_id
                )
				  .execute(&*self.pool)
				  .await?;
            },
            (Some(fn_), None, Some(un_)) => {
                sqlx::query!(
                    "UPDATE users SET firstname = $1, username = $2, updated_at = NOW() WHERE id = $3",
                    fn_, un_, user_id
                )
				  .execute(&*self.pool)
				  .await?;
            },
            (None, Some(ln_), Some(un_)) => {
                sqlx::query!(
                    "UPDATE users SET lastname = $1, username = $2, updated_at = NOW() WHERE id = $3",
                    ln_, un_, user_id
                )
				  .execute(&*self.pool)
				  .await?;
            },
            (Some(fn_), None, None) => {
                sqlx::query!(
                    "UPDATE users SET firstname = $1, updated_at = NOW() WHERE id = $2",
                    fn_,
                    user_id
                )
                .execute(&*self.pool)
                .await?;
            },
            (None, Some(ln_), None) => {
                sqlx::query!(
                    "UPDATE users SET lastname = $1, updated_at = NOW() WHERE id = $2",
                    ln_,
                    user_id
                )
                .execute(&*self.pool)
                .await?;
            },
            (None, None, Some(un_)) => {
                sqlx::query!(
                    "UPDATE users SET username = $1, updated_at = NOW() WHERE id = $2",
                    un_,
                    user_id
                )
                .execute(&*self.pool)
                .await?;
            },
            (None, None, None) => {
                sqlx::query!("UPDATE users SET updated_at = NOW() WHERE id = $1", user_id)
                    .execute(&*self.pool)
                    .await?;
            },
        }

        Ok(())
    }

    async fn update_password(&self, user_id: Uuid, password: String) -> Result<(), UserError> {
        let password_for_history = password.clone();

        sqlx::query!(
            "
            UPDATE users
            SET password = $1,
                password_changed_at = NOW(),
                password_history = CASE
                    WHEN password_history IS NULL THEN jsonb_build_array($2::text)
                    ELSE jsonb_insert(password_history, '{0}', to_jsonb($2::text), true)
                END,
                require_password_change = false,
                updated_at = NOW()
            WHERE id = $3
            ",
            password,
            password_for_history,
            user_id
        )
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    async fn update_status(&self, user_id: Uuid, status: UserStatus) -> Result<(), UserError> {
        sqlx::query!(
            "UPDATE users SET status = $1, updated_at = NOW() WHERE id = $2",
            status as UserStatus,
            user_id
        )
        .execute(&*self.pool)
        .await?;

        Ok(())
    }

    async fn list_users(
        &self,
        limit: i64,
        offset: i64,
        status: Option<UserStatus>,
        search: Option<String>,
    ) -> Result<Vec<User>, UserError> {
        let search_pattern = search.as_ref().map(|s| format!("%{}%", s));

        let users = match (status, &search_pattern) {
			(Some(status_filter), Some(pattern)) => {
				sqlx::query(
					"
                    SELECT id, username, email, firstname, lastname, password,
                           email_verified, mfa_enabled, mfa_secret, account_locked,
                           failed_login_attempts, last_login, password_changed_at,
                           password_history, password_expires_at, require_password_change,
                           status, created_at, updated_at
                    FROM users
                    WHERE status = $1 AND (username ILIKE $2 OR email ILIKE $2 OR firstname ILIKE $2 OR lastname ILIKE $2)
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "
				)
				  .bind(status_filter)
				  .bind(pattern)
				  .bind(limit)
				  .bind(offset)
				  .fetch_all(&*self.pool)
				  .await?
			}
			(Some(status_filter), None) => {
				sqlx::query(
					"
                    SELECT id, username, email, firstname, lastname, password,
                           email_verified, mfa_enabled, mfa_secret, account_locked,
                           failed_login_attempts, last_login, password_changed_at,
                           password_history, password_expires_at, require_password_change,
                           status, created_at, updated_at
                    FROM users
                    WHERE status = $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    "
				)
				  .bind(status_filter)
				  .bind(limit)
				  .bind(offset)
				  .fetch_all(&*self.pool)
				  .await?
			}
			(None, Some(pattern)) => {
				sqlx::query(
					"
                    SELECT id, username, email, firstname, lastname, password,
                           email_verified, mfa_enabled, mfa_secret, account_locked,
                           failed_login_attempts, last_login, password_changed_at,
                           password_history, password_expires_at, require_password_change,
                           status, created_at, updated_at
                    FROM users
                    WHERE username ILIKE $1 OR email ILIKE $1 OR firstname ILIKE $1 OR lastname ILIKE $1
                    ORDER BY created_at DESC
                    LIMIT $2 OFFSET $3
                    "
				)
				  .bind(pattern)
				  .bind(limit)
				  .bind(offset)
				  .fetch_all(&*self.pool)
				  .await?
			}
			(None, None) => {
				sqlx::query(
					"
                    SELECT id, username, email, firstname, lastname, password,
                           email_verified, mfa_enabled, mfa_secret, account_locked,
                           failed_login_attempts, last_login, password_changed_at,
                           password_history, password_expires_at, require_password_change,
                           status, created_at, updated_at
                    FROM users
                    ORDER BY created_at DESC
                    LIMIT $1 OFFSET $2
                    "
				)
				  .bind(limit)
				  .bind(offset)
				  .fetch_all(&*self.pool)
				  .await?
			}
		};

        let result = users.into_iter().map(|row| self.row_to_user(row)).collect();

        Ok(result)
    }

    async fn count_users(
        &self,
        status: Option<UserStatus>,
        search: Option<String>,
    ) -> Result<i64, UserError> {
        let search_pattern = search.as_ref().map(|s| format!("%{}%", s));

        let count = match (status, &search_pattern) {
			(Some(status_filter), Some(pattern)) => {
				sqlx::query!(
                    "SELECT COUNT(*) as count FROM users WHERE status = $1 AND (username ILIKE $2 OR email ILIKE $2 OR firstname ILIKE $2 OR lastname ILIKE $2)",
                    status_filter as UserStatus,
                    pattern
                )
				  .fetch_one(&*self.pool)
				  .await?
				  .count
			}
			(Some(status_filter), None) => {
				sqlx::query!(
                    "SELECT COUNT(*) as count FROM users WHERE status = $1",
                    status_filter as UserStatus
                )
				  .fetch_one(&*self.pool)
				  .await?
				  .count
			}
			(None, Some(pattern)) => {
				sqlx::query!(
                    "SELECT COUNT(*) as count FROM users WHERE username ILIKE $1 OR email ILIKE $1 OR firstname ILIKE $1 OR lastname ILIKE $1",
                    pattern
                )
				  .fetch_one(&*self.pool)
				  .await?
				  .count
			}
			(None, None) => {
				sqlx::query!("SELECT COUNT(*) as count FROM users")
				  .fetch_one(&*self.pool)
				  .await?
				  .count
			}
		};

        Ok(count.unwrap_or(0))
    }

    async fn assign_role(&self, user_id: Uuid, role: UserRole) -> Result<(), UserError> {
        let role_name = role.to_string().to_lowercase();
        let role_row = sqlx::query!("SELECT id FROM roles WHERE name = $1", role_name)
            .fetch_optional(&*self.pool)
            .await?;

        let role_id = match role_row {
            Some(row) => row.id,
            None => {
                sqlx::query!(
                    "INSERT INTO roles (name, permissions) VALUES ($1, '{}') RETURNING id",
                    role_name
                )
                .fetch_one(&*self.pool)
                .await?
                .id
            },
        };

        sqlx::query!(
            "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2) ON CONFLICT (user_id, role_id) DO NOTHING",
            user_id,
            role_id
        )
		  .execute(&*self.pool)
		  .await?;

        Ok(())
    }

    async fn get_user_roles(&self, user_id: Uuid) -> Result<Vec<UserRole>, UserError> {
        let roles = sqlx::query!(
            "
            SELECT r.name
            FROM roles r
            JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = $1
            ",
            user_id
        )
        .fetch_all(&*self.pool)
        .await?;

        let result = roles
            .into_iter()
            .filter_map(|row| match row.name.as_str() {
                "user" => Some(UserRole::User),
                "admin" => Some(UserRole::Admin),
                "moderator" => Some(UserRole::Moderator),
                _ => None,
            })
            .collect();

        Ok(result)
    }

    async fn get_user_stats(&self) -> Result<UserStatsData, UserError> {
        let total = sqlx::query!("SELECT COUNT(*) as count FROM users")
            .fetch_one(&*self.pool)
            .await?
            .count
            .unwrap_or(0);

        let active = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE status = 'active'")
            .fetch_one(&*self.pool)
            .await?
            .count
            .unwrap_or(0);

        let pending = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE status = 'pending'")
            .fetch_one(&*self.pool)
            .await?
            .count
            .unwrap_or(0);

        let suspended =
            sqlx::query!("SELECT COUNT(*) as count FROM users WHERE status = 'suspended'")
                .fetch_one(&*self.pool)
                .await?
                .count
                .unwrap_or(0);

        let verified =
            sqlx::query!("SELECT COUNT(*) as count FROM users WHERE email_verified = true")
                .fetch_one(&*self.pool)
                .await?
                .count
                .unwrap_or(0);

        let mfa_enabled =
            sqlx::query!("SELECT COUNT(*) as count FROM users WHERE mfa_enabled = true")
                .fetch_one(&*self.pool)
                .await?
                .count
                .unwrap_or(0);

        let recent_logins = sqlx::query!(
            "SELECT COUNT(*) as count FROM users WHERE last_login > NOW() - INTERVAL '7 days'"
        )
        .fetch_one(&*self.pool)
        .await?
        .count
        .unwrap_or(0);

        Ok(UserStatsData {
            total_users: total,
            active_users: active,
            pending_users: pending,
            suspended_users: suspended,
            verified_emails: verified,
            mfa_enabled,
            recent_logins,
        })
    }
}

/// User statistics data
#[derive(Debug)]
pub struct UserStatsData {
    pub total_users: i64,
    pub active_users: i64,
    pub pending_users: i64,
    pub suspended_users: i64,
    pub verified_emails: i64,
    pub mfa_enabled: i64,
    pub recent_logins: i64,
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_repository_creation() {
        // Simple test placeholder
        assert!(true);
    }
}
