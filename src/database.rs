use crate::types::ApiError;
use sqlx::{PgPool, Row};

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, ApiError> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to connect: {e}")))?;

        let _test = sqlx::query("SELECT 1")
            .fetch_one(&pool)
            .await
            .map_err(|e| ApiError::Database(format!("Connexion test failed: {e}")))?;

        println!("✅ Database connection established successfully.");

        Ok(Database {
            pool,
        })
    }

    pub async fn setup_tables(&self) -> Result<(), ApiError> {
        sqlx::query("DROP TABLE IF EXISTS test_users CASCADE")
            .execute(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to drop tables: {e}")))?;

        sqlx::query(
            r#"
            CREATE TABLE test_users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to create tables: {e}")))?;

        println!("✅ Tables created successfully!");
        Ok(())
    }

    pub async fn user_exists(&self, email: &str) -> Result<bool, ApiError> {
        let result = sqlx::query("SELECT COUNT(*) as count FROM test_users WHERE email = $1")
            .bind(email)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to check user existence: {e}")))?;

        let count: i64 = result
            .try_get("count")
            .map_err(|e| ApiError::Database(format!("Failed to get count: {e}")))?;

        Ok(count > 0)
    }

    pub async fn create_user(
        &self,
        email: &str,
        username: &str,
        password: &str,
    ) -> Result<i32, ApiError> {
        let result = sqlx::query(
            "INSERT INTO test_users (email, username, password) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(email)
        .bind(username)
        .bind(password)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to create user: {e}")))?;

        let id: i32 = result
            .try_get("id")
            .map_err(|e| ApiError::Database(format!("Failed to get user ID: {e}")))?;

        Ok(id)
    }

    pub async fn verify_user_login(&self, email: &str, password: &str) -> Result<bool, ApiError> {
        let result = sqlx::query(
            "SELECT COUNT(*) as count FROM test_users WHERE email = $1 AND password = $2",
        )
        .bind(email)
        .bind(password)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to verify user login: {e}")))?;

        let count: i64 = result
            .try_get("count")
            .map_err(|e| ApiError::Database(format!("Failed to get count: {e}")))?;

        Ok(count > 0)
    }
}
