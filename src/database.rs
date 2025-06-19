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
}
