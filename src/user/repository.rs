//! User Repository Module
//!
//! This module defines the repository interface and implementation for user data persistence.
//! It abstracts the database operations required for storing and retrieving user information,
//! providing a clean API for the service layer to interact with the data store.

use async_trait::async_trait;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use super::model::{User, UserRole};
use crate::error::UserError;
use crate::user::error::UserError;

/// Repository trait defining operations for user data persistence
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Finds a user by their unique ID
    async fn find_by_id(&self, id: &Uuid) -> Result<Option<User>, UserError>;

    /// Finds a user by their email address
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError>;

    /// Finds a user by their username
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError>;

    /// Finds a user by provider information (OAuth)
    async fn find_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, UserError>;

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
                id, username, email, password_hash, provider, provider_user_id,
                display_name, profile_image, created_at, updated_at
            FROM users
            WHERE id = $1
            "#,
            id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, provider, provider_user_id,
                display_name, profile_image, created_at, updated_at
            FROM users
            WHERE email = $1
            "#,
            email
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, provider, provider_user_id,
                display_name, profile_image, created_at, updated_at
            FROM users
            WHERE username = $1
            "#,
            username
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, UserError> {
        let user = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, provider, provider_user_id,
                display_name, profile_image, created_at, updated_at
            FROM users
            WHERE provider = $1 AND provider_user_id = $2
            "#,
            provider,
            provider_user_id
        )
        .fetch_optional(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(user)
    }

    async fn create(&self, user: &User) -> Result<(), UserError> {
        sqlx::query!(
            r#"
            INSERT INTO users
                (id, username, email, password_hash, provider, provider_user_id,
                 display_name, profile_image, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
            user.id,
            user.username,
            user.email,
            user.password_hash,
            user.provider,
            user.provider_user_id,
            user.display_name,
            user.profile_image,
            user.created_at,
            user.updated_at
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("unique constraint") {
                if e.to_string().contains("users_email_key") {
                    return UserError::EmailAlreadyExists;
                } else if e.to_string().contains("users_username_key") {
                    return UserError::UsernameAlreadyExists;
                }
            }
            UserError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    async fn update(&self, user: &User) -> Result<(), UserError> {
        sqlx::query!(
            r#"
            UPDATE users SET
                username = $1,
                email = $2,
                password_hash = $3,
                provider = $4,
                provider_user_id = $5,
                display_name = $6,
                profile_image = $7,
                updated_at = $8
            WHERE id = $9
            "#,
            user.username,
            user.email,
            user.password_hash,
            user.provider,
            user.provider_user_id,
            user.display_name,
            user.profile_image,
            user.updated_at,
            user.id
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("unique constraint") {
                if e.to_string().contains("users_email_key") {
                    return UserError::EmailAlreadyExists;
                } else if e.to_string().contains("users_username_key") {
                    return UserError::UsernameAlreadyExists;
                }
            }
            UserError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    async fn delete(&self, id: &Uuid) -> Result<(), UserError> {
        // First delete user roles
        sqlx::query!(r#"DELETE FROM user_roles WHERE user_id = $1"#, id)
            .execute(&*self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        // Then delete the user
        sqlx::query!(r#"DELETE FROM users WHERE id = $1"#, id)
            .execute(&*self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn assign_role(&self, user_id: &Uuid, role: UserRole) -> Result<(), UserError> {
        // Convert the role enum to a string for storage
        let role_str = match role {
            UserRole::User => "user",
            UserRole::Admin => "admin",
            UserRole::Moderator => "moderator",
        };

        sqlx::query!(
            r#"
            INSERT INTO user_roles (user_id, role, assigned_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (user_id, role) DO NOTHING
            "#,
            user_id,
            role_str
        )
        .execute(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(())
    }

    async fn get_user_roles(&self, user_id: &Uuid) -> Result<Vec<UserRole>, UserError> {
        let roles = sqlx::query!(
            r#"
            SELECT role FROM user_roles WHERE user_id = $1
            "#,
            user_id
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        // Convert the role strings to UserRole enum
        let mut result = Vec::new();
        for record in roles {
            let role = match record.role.as_str() {
                "user" => UserRole::User,
                "admin" => UserRole::Admin,
                "moderator" => UserRole::Moderator,
                _ => continue, // Skip unknown roles
            };
            result.push(role);
        }

        Ok(result)
    }

    async fn list_users(&self, limit: i64, offset: i64) -> Result<Vec<User>, UserError> {
        let users = sqlx::query_as!(
            User,
            r#"
            SELECT
                id, username, email, password_hash, provider, provider_user_id,
                display_name, profile_image, created_at, updated_at
            FROM users
            ORDER BY created_at DESC
            LIMIT $1 OFFSET $2
            "#,
            limit,
            offset
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(users)
    }

    async fn count_users(&self) -> Result<i64, UserError> {
        let count = sqlx::query!(r#"SELECT COUNT(*) as count FROM users"#)
            .fetch_one(&*self.pool)
            .await
            .map_err(|e| UserError::DatabaseError(e.to_string()))?;

        Ok(count.count.unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres::config::get_connection_pool;
    use chrono::Utc;
    use dotenv::dotenv;
    use sqlx::migrate::MigrateDatabase;
    use std::env;

    async fn setup_test_db() -> Arc<Pool<Postgres>> {
        dotenv().ok();

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
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hashedpassword".to_string(),
            provider: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: Some("Test User".to_string()),
            profile_image: None,
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
            username: "updateuser".to_string(),
            email: "update@example.com".to_string(),
            password_hash: "hashedpassword".to_string(),
            provider: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: None,
            profile_image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        repo.create(&user).await.unwrap();

        // Update user
        user.display_name = Some("Updated Name".to_string());
        user.profile_image = Some("http://example.com/image.jpg".to_string());
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
            username: "deleteuser".to_string(),
            email: "delete@example.com".to_string(),
            password_hash: "hashedpassword".to_string(),
            provider: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: None,
            profile_image: None,
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
            username: "roleuser".to_string(),
            email: "role@example.com".to_string(),
            password_hash: "hashedpassword".to_string(),
            provider: "local".to_string(),
            provider_user_id: "".to_string(),
            display_name: None,
            profile_image: None,
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
