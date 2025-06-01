//! User Repository Module
//!
//! This module defines the repository interface and implementation for user data persistence.
//! It abstracts the database operations required for storing and retrieving user information,
//! providing a clean API for the service layer to interact with the data store.

use super::model::{User, UserRole, UserStatus};
use crate::auth::models::OAuthProvider;
use crate::user::error::UserError;
use async_trait::async_trait;
use chrono::Utc;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

/// Repository trait defining operations for user data persistence
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Finds a user by their unique ID
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>, UserError>;

    /// Finds a user by their email address
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError>;

    /// Finds a user by their username
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError>;

    /// Adds a new OAuth provider for a user
    async fn add_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), UserError>;

    /// Updates an existing OAuth provider
    async fn update_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), UserError>;

    /// Removes an OAuth provider by its ID
    async fn remove_oauth_provider(&self, id: &Uuid) -> Result<(), UserError>;

    /// Finds all OAuth providers for a specific user
    async fn find_oauth_providers_by_user_id(&self, user_id: &Uuid) -> Result<Vec<OAuthProvider>, UserError>;

    /// Finds a user by provider information (OAuth)
    async fn find_by_provider(
        &self,
        provider_name: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, UserError>;

    /// Finds an OAuth provider by provider name and provider user ID
    async fn find_oauth_provider(
        &self,
        provider_name: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthProvider>, UserError>;

    /// Creates a new user in the database
    async fn create(&self, user: &User) -> Result<(), UserError>;

    /// Updates an existing user's information
    async fn update(&self, user: &User) -> Result<(), UserError>;

    /// Deletes a user by their ID
    async fn delete(&self, id: &Uuid) -> Result<(), UserError>;

    /// Assigns a role to a user
    async fn assign_role(&self, user_id: &Uuid, role: UserRole) -> Result<(), UserError>;

    /// Gets all roles assigned to a user
    async fn get_user_roles(&self, user_id: &Uuid) -> Result<Vec<UserRole>, UserError>;

    /// Lists users with pagination
    async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<User>, UserError>;

    /// Counts total number of users
    async fn count_users(&self) -> Result<i64, UserError>;
}

/// PostgreSQL implementation of the UserRepository
pub struct PgUserRepository {
    pool: Arc<Pool<Postgres>>,
}

impl PgUserRepository {
    /// Creates a new PostgreSQL user repository
    pub fn new(pool: Arc<Pool<Postgres>>) -> Self {
        Self {
            pool,
        }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, email_verified, password_hash, mfa_enabled, mfa_secret,
            account_locked, failed_login_attempts, last_login, created_at, updated_at,
            password_changed_at, password_history, password_expires_at, require_password_change,
            provider_name, provider_user_id, display_name, avatar_url, refresh_token,
            profile_image, status as "status: Option<UserStatus>"
        FROM users
        WHERE id = $1
        "#,
        id
    )
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(user)
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, mfa_enabled, mfa_secret,
            account_locked, failed_login_attempts, last_login, created_at, updated_at,
            password_changed_at, password_history, password_expires_at, require_password_change,
            false as email_verified, null as provider_name, null as provider_user_id,
            null as display_name, null as avatar_url, null as refresh_token,
            null as profile_image, null as status
        FROM users
        WHERE email = $1
        "#,
        email
    )
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, password_hash, mfa_enabled, mfa_secret,
            account_locked, failed_login_attempts, last_login, created_at, updated_at,
            password_changed_at, password_history, password_expires_at, require_password_change,
            false as email_verified, null as provider_name, null as provider_user_id, null as display_name,
            null as avatar_url, null as refresh_token, null as profile_image, null as status
        FROM users
        WHERE username = $1
        "#,
        username
    )
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(user)
    }

    async fn add_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), UserError> {
        sqlx::query!(
            r#"
            INSERT INTO oauth_providers (
                id, provider_name, provider_user_id, user_id, access_token,
                refresh_token, expires_at, created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            "#,
            provider.id,
            provider.provider_name,
            provider.provider_user_id,
            provider.user_id,
            provider.access_token,
            provider.refresh_token,
            provider.expires_at,
            provider.created_at,
            provider.updated_at
        )
            .execute(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn update_oauth_provider(&self, provider: &OAuthProvider) -> Result<(), UserError> {
        sqlx::query!(
            r#"
            UPDATE oauth_providers
            SET
                provider_name = $1,
                provider_user_id = $2,
                user_id = $3,
                access_token = $4,
                refresh_token = $5,
                expires_at = $6,
                updated_at = $7
            WHERE id = $8
            "#,
            provider.provider_name,
            provider.provider_user_id,
            provider.user_id,
            provider.access_token,
            provider.refresh_token,
            provider.expires_at,
            Utc::now(),
            provider.id
        )
            .execute(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn remove_oauth_provider(&self, id: &Uuid) -> Result<(), UserError> {
        sqlx::query!(
            r#"
            DELETE FROM oauth_providers
            WHERE id = $1
            "#,
            id
        )
            .execute(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn find_oauth_providers_by_user_id(&self, user_id: &Uuid) -> Result<Vec<OAuthProvider>, UserError> {
        let providers = sqlx::query_as!(
            OAuthProvider,
            r#"
            SELECT *
            FROM oauth_providers
            WHERE user_id = $1
            "#,
            user_id
        )
            .fetch_all(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(providers)
    }

    async fn find_by_provider(
        &self,
        provider_name: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
        User,
        r#"
        SELECT
            u.id, u.username, u.email, u.password_hash, u.mfa_enabled, u.mfa_secret,
            u.account_locked, u.failed_login_attempts, u.last_login, u.created_at, u.updated_at,
            u.password_changed_at, u.password_history, u.password_expires_at, u.require_password_change,
            op.provider_name, op.provider_user_id, u.display_name, false as email_verified, null as profile_image, null as status
        FROM users u
        JOIN oauth_providers op ON u.id = op.user_id
        WHERE op.provider_name = $1 AND op.provider_user_id = $2
        "#,
        provider_name,
        provider_user_id
    )
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(user)
    }
    async fn find_oauth_provider(
        &self,
        provider_name: &str,
        provider_user_id: &str,
    ) -> Result<Option<OAuthProvider>, UserError> {
        let provider = sqlx::query_as!(
        OAuthProvider,
        r#"
        SELECT *
        FROM oauth_providers
        WHERE provider_name = $1 AND provider_user_id = $2
        "#,
        provider_name,
        provider_user_id
    )
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(provider)
    }

    async fn create(&self, user: &User) -> Result<(), UserError> {
        sqlx::query(
            r#"
        INSERT INTO users (
            id, username, email, password_hash, display_name, profile_image, mfa_enabled, mfa_secret, account_locked,
            failed_login_attempts, last_login, password_changed_at, password_expires_at,
            require_password_change, created_at, updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20
        )
        "#
        )
            .bind(&user.id)
            .bind(&user.username)
            .bind(&user.email)
            .bind(&user.email_verified)
            .bind(&user.password_hash)
            .bind(&user.provider_name)
            .bind(&user.provider_user_id)
            .bind(&user.display_name)
            .bind(&user.profile_image)
            .bind(&user.mfa_enabled)
            .bind(&user.mfa_secret)
            .bind(&user.account_locked)
            .bind(&user.failed_login_attempts)
            .bind(&user.last_login)
            .bind(&user.password_changed_at)
            .bind(&user.password_expires_at)
            .bind(&user.require_password_change)
            .bind(&user.status)
            .bind(&user.created_at)
            .bind(&user.updated_at)

            .execute(&mut *self.pool.acquire().await?)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), UserError> {
        sqlx::query!(
        r#"
        UPDATE users
        SET
            username = $1,
            email = $2,
            password_hash = $3,
            mfa_enabled = $4,
            mfa_secret = $5,
            account_locked = $6,
            failed_login_attempts = $7,
            last_login = $8,
            updated_at = $9,
            password_changed_at = $10,
            password_history = $11,
            password_expires_at = $12,
            require_password_change = $13
        WHERE id = $14
        "#,
        user.username,
        user.email,
        user.password_hash,
        user.mfa_enabled,
        user.mfa_secret,
        user.account_locked,
        user.failed_login_attempts,
        user.last_login,
        user.updated_at,
        user.password_changed_at,
        &user.password_history,
        user.password_expires_at,
        user.require_password_change,
        user.id
    )
            .execute(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn delete(&self, id: &Uuid) -> Result<(), UserError> {
        sqlx::query!(
        r#"
        DELETE FROM users
        WHERE id = $1
        "#,
        id
    )
            .execute(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn assign_role(&self, user_id: &Uuid, role: UserRole) -> Result<(), UserError> {
        sqlx::query!(
        r#"
        INSERT INTO user_roles (user_id, role_id)
        VALUES ($1, $2)
        ON CONFLICT (user_id, role_id) DO NOTHING
        "#,
        user_id,
        role as i32
    )
            .execute(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(())
    }

    async fn get_user_roles(&self, user_id: &Uuid) -> Result<Vec<UserRole>, UserError> {
        let roles = sqlx::query_as!(
        UserRole,
        r#"
        SELECT user_id, role_id
        FROM user_roles
        WHERE user_id = $1
        "#,
        user_id
    )
            .fetch_all(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(roles)
    }

    async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<User>, UserError> {
        let users = sqlx::query_as!(
        User,
        r#"
        SELECT
            id, username, email, email_verified, password_hash, mfa_enabled, mfa_secret,
            provider, provider_user_id, display_name, profile_image, bio,
            account_locked, failed_login_attempts, last_login, password_changed_at,
            password_history, password_expires_at, require_password_change, status,
            created_at, updated_at
        FROM users
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
        limit,
        offset
    )
            .fetch_all(&*self.pool)
            .await
            .map_err(Into::into)?;

        Ok(users)
    }

    async fn count_users(&self) -> Result<i64, UserError> {
        let count = sqlx::query!(
        r#"
        SELECT COUNT(*) as count
        FROM users
        "#
    )
            .fetch_one(&*self.pool)
            .await
            .map_err(Into::into)?;
        .count;

        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::config::get_connection_pool;
    use chrono::Utc;
    use dotenv::dotenv;
    use sqlx::migrate::MigrateDatabase;

    async fn setup_test_db() -> Arc<Pool<Postgres>> {
        dotenvy::dotenv().ok();

        // Use a unique test database for each test run
        let db_url = &format!(
            "postgres://postgres:postgres@localhost/user_repo_test_{}",
            Uuid::new_v4().to_string().replace("-", "")
        );

        // Create and migrate the test database
        if !Postgres::database_exists(db_url).await.unwrap_or(false) {
            Postgres::create_database(db_url).await.unwrap();
        }

        let pool = get_connection_pool(db_url).await.unwrap();

        // Create test tables
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id UUID PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                provider VARCHAR(50) NOT NULL DEFAULT 'local',
                provider_user_id VARCHAR(255) NOT NULL DEFAULT '',
                display_name VARCHAR(255),
                profile_image VARCHAR(255),
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS user_roles (
                user_id UUID NOT NULL REFERENCES users(id),
                role VARCHAR(50) NOT NULL,
                assigned_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (user_id, role)
            )
            "#,
        )
        .execute(&pool)
        .await
        .unwrap();

        Arc::new(pool)
    }

    async fn teardown_test_db(pool: Arc<Pool<Postgres>>) {
        // Drop the test database
        let conn = pool.acquire().await.unwrap();
        let db_name = conn.database_name().unwrap().to_string();
        drop(conn);
        drop(pool);

        // Connect to default postgres database to drop the test database
        let default_url = "postgres://postgres:postgres@localhost/postgres";
        let default_pool = get_connection_pool(default_url).await.unwrap();
        let pool = Pool::<Postgres>::connect(default_url).await.unwrap();

        sqlx::query(&format!("DROP DATABASE IF EXISTS {}", db_name))
            .execute(&default_pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_create_and_find_user() {
        let pool = setup_test_db().await;
        let repo = PgUserRepository::new(pool.clone());

        // Create a test user
        let user = User {
            id: Uuid::new_v4(),
            username: "test_user".to_string(),
            email: "test@example.com".to_string(),
            email_verified: false,
            password_hash: "hashed_password".to_string(),
            provider_name: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: Some("Test_User".to_string()),
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
            status: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        repo.create(&user).await.unwrap();

        // Find user by ID
        let found_user = repo.find_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(found_user.id, user.id);
        assert_eq!(found_user.username, user.username);
        assert_eq!(found_user.email, user.email);

        // Find user by email
        let found_user = repo.find_by_email(&user.email).await.unwrap().unwrap();
        assert_eq!(found_user.id, user.id);

        // Find user by username
        let found_user = repo.find_by_username(&user.username).await.unwrap().unwrap();
        assert_eq!(found_user.id, user.id);

        teardown_test_db(pool).await;
    }

    #[tokio::test]
    async fn test_update_user() {
        let pool = setup_test_db().await;
        let repo = PgUserRepository::new(pool.clone());

        // Create a test user
        let mut user = User {
            id: Uuid::new_v4(),
            username: "updater".to_string(),
            email: "update@example.com".to_string(),
            email_verified: false,
            password_hash: "hashed_password".to_string(),
            provider_user_id: "".to_string(),
            display_name: None,
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
            status: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            provider_name: "".to_string()
        };

        repo.create(&user).await.unwrap();

        // Update user
        user.display_name = Some("Updated_Name".to_string());
        user.profile_image = Some("https://example.com/image.jpg".to_string());
        user.updated_at = Utc::now();

        repo.update(&user).await.unwrap();

        // Verify update
        let updated_user = repo.find_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(updated_user.display_name, user.display_name);
        assert_eq!(updated_user.profile_image, user.profile_image);

        teardown_test_db(pool).await;
    }

    #[tokio::test]
    async fn test_delete_user() {
        let pool = setup_test_db().await;
        let repo = PgUserRepository::new(pool.clone());

        // Create a test user
        let user = User {
            id: Uuid::new_v4(),
            username: "delete_user".to_string(),
            email: "delete@example.com".to_string(),
            email_verified: false,
            password_hash: "hashed_password".to_string(),
            provider_name: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: None,
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
            status: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        repo.create(&user).await.unwrap();

        // Delete user
        repo.delete(&user.id).await.unwrap();

        // Verify deletion
        let deleted_user = repo.find_by_id(&user.id).await.unwrap();
        assert!(deleted_user.is_none());

        teardown_test_db(pool).await;
    }

    #[tokio::test]
    async fn test_user_roles() {
        let pool = setup_test_db().await;
        let repo = PgUserRepository::new(pool.clone());

        // Create a test user
        let user = User {
            id: Uuid::new_v4(),
            username: "roller".to_string(),
            email: "role@example.com".to_string(),
            email_verified: false,
            password_hash: "hashed_password".to_string(),
            provider_name: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: None,
            profile_image: None,
            mfa_enabled: false,
            mfa_secret: None,
            account_locked: false,
            failed_login_attempts: 0,
            last_login: None,
            password_changed_at: None,
            password_history: vec![],
            password_expires_at: None,
            require_password_change: false,
            status: Default::default(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        repo.create(&user).await.unwrap();

        // Assign roles
        repo.assign_role(&user.id, UserRole::Admin).await.unwrap();
        repo.assign_role(&user.id, UserRole::Moderator).await.unwrap();

        // Get roles
        let roles = repo.get_user_roles(&user.id).await.unwrap();
        assert_eq!(roles.len(), 2);
        assert!(roles.contains(&UserRole::Admin));
        assert!(roles.contains(&UserRole::Moderator));

        teardown_test_db(pool).await;
    }
}
