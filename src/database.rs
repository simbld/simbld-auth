use crate::types::ApiError;
use sqlx::PgPool;

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
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"#
        )
        .execute(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to create tables: {e}")))?;

        println!("✅ Tables created successfully!");
        Ok(())
    }

    pub async fn user_exists(&self, email: &str) -> Result<Bool, ApiError> {
        let result = sqlx::query!("SELECT COUNT(*) as count FROM users WHERE email = $1", email)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| ApiError::Database(format!("Failed to check user existence: {e}")))?;

        Ok(result.count.unwrap_or(0) > 0)
    }

    pub async fn create_user(
        &self,
        email: &str,
        username: &str,
        password_hash: &str,
    ) -> Result<i32, ApiError> {
        let result = sqlx::query!(
            "INSERT INTO users (email, username, password_hash) VALUES ($1, $2, $3) RETURNING id",
            email,
            username,
            password_hash
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ApiError::Database(format!("Failed to create user: {e}")))?;

        Ok(result.id)
    }
}
