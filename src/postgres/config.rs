//! PostgreSQL connection pool configuration and setup
//!
//! This module handles the creation and configuration of a connection pool
//! for PostgreSQL database access.

pub(crate) use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use std::env;
use std::time::Duration;
use tokio_postgres::{tls::MakeTlsConnect, NoTls, Socket};

/// Default values for database configuration
const DEFAULT_PORT: u16 = 5432;
const DEFAULT_MAX_CONNECTIONS: usize = 16;
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 5;

/// Creates a PostgreSQL connection pool configured from environment variables
///
/// Environment variables:
/// - PG_HOST: Database host (required)
/// - PG_PORT: Database port (optional, default: 5432)
/// - PG_USER: Database user (required)
/// - PG_PASSWORD: Database password (required)
/// - PG_DBNAME: Database name (required)
/// - PG_MAX_CONNECTIONS: Maximum connections in pool (optional, default: 16)
/// - PG_CONNECT_TIMEOUT: Connection timeout in seconds (optional, default: 5)
pub fn create_pool() -> Pool {
    create_pool_with_tls(NoTls)
}

/// Creates a PostgreSQL connection pool with TLS support
pub fn create_pool_with_tls<T>(tls: T) -> Pool
where
    T: MakeTlsConnect<Socket> + Send + Sync + 'static,
    <T as MakeTlsConnect<Socket>>::TlsConnect: Send,
    <T as MakeTlsConnect<Socket>>::Stream: Send + Sync,
{
    let mut cfg = Config::new();

    // Load required configurations from environment variables
    cfg.host = Some(env::var("PG_HOST").expect("PG_HOST must be set"));
    cfg.user = Some(env::var("PG_USER").expect("PG_USER must be set"));
    cfg.password = Some(env::var("PG_PASSWORD").expect("PG_PASSWORD must be set"));
    cfg.dbname = Some(env::var("PG_DBNAME").expect("PG_DBNAME must be set"));

    // Load optional configurations with defaults
    cfg.port = Some(env::var("PG_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(DEFAULT_PORT));

    // Configure connection pool parameters
    let max_connections = env::var("PG_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_CONNECTIONS);

    let connect_timeout = env::var("PG_CONNECT_TIMEOUT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_CONNECT_TIMEOUT_SECS);

    let pool_config = PoolConfig::new(max_connections);
    cfg.pool = Some(pool_config);

    // Set connection timeout
    cfg.connect_timeout = Some(Duration::from_secs(connect_timeout));

    // Create the connection pool
    cfg.create_pool(Some(Runtime::Tokio1), tls)
        .expect("Failed to create PostgreSQL connection pool")
}

/// Checks if the database connection is working
pub async fn health_check(pool: &Pool) -> Result<(), String> {
    let client =
        pool.get().await.map_err(|e| format!("Failed to get database connection: {}", e))?;

    client
        .query_one("SELECT 1", &[])
        .await
        .map_err(|e| format!("Database health check failed: {}", e))?;

    Ok(())
}
