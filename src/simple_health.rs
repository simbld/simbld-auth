//! Simple Health Check Module
//!
//! Module simplifié pour les vérifications de santé avec support de connexion BDD réelle
//! Compatible avec main.rs sans dépendances complexes

use actix_web::{HttpResponse, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SimpleStatus {
    Healthy,
    Degraded,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleDatabaseStatus {
    pub status: SimpleStatus,
    pub connection_available: bool,
    pub response_time_ms: Option<u64>,
    pub error_message: Option<String>,
    pub last_check: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleHealthResponse {
    pub service_status: SimpleStatus,
    pub timestamp: String,
    pub version: String,
    pub database: SimpleDatabaseStatus,
    pub system: SimpleSystemInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleSystemInfo {
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
}

/// Convert duration to milliseconds, ensuring it fits in u64
fn safe_duration_to_ms(duration: std::time::Duration) -> u64 {
    let millis = duration.as_millis();
    millis.try_into().unwrap_or(u64::MAX)
}

/// Test `PostgreSQL` connection and return status
pub async fn test_postgresql_connection(connection_string: &str) -> SimpleDatabaseStatus {
    let start_time = Instant::now();

    // Attempt to connect to the PostgreSQL database
    match sqlx::PgPool::connect(connection_string).await {
        Ok(pool) => match sqlx::query("SELECT 1").fetch_one(&pool).await {
            Ok(_) => {
                pool.close().await;
                SimpleDatabaseStatus {
                    status: SimpleStatus::Healthy,
                    connection_available: true,
                    response_time_ms: Some(safe_duration_to_ms(start_time.elapsed())),
                    error_message: None,
                    last_check: chrono::Utc::now().to_rfc3339(),
                }
            },
            Err(e) => SimpleDatabaseStatus {
                status: SimpleStatus::Degraded,
                connection_available: true,
                response_time_ms: Some(safe_duration_to_ms(start_time.elapsed())),
                error_message: Some(format!("Query failed: {e}")),
                last_check: chrono::Utc::now().to_rfc3339(),
            },
        },
        Err(e) => SimpleDatabaseStatus {
            status: SimpleStatus::Unhealthy,
            connection_available: false,
            response_time_ms: Some(safe_duration_to_ms(start_time.elapsed())),
            error_message: Some(format!("Connexion failed: {e}")),
            last_check: chrono::Utc::now().to_rfc3339(),
        },
    }
}

/// Test `Mock` database connection and return status
pub async fn test_mock_database() -> SimpleDatabaseStatus {
    // Simulates a latency
    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

    SimpleDatabaseStatus {
        status: SimpleStatus::Healthy,
        connection_available: false,
        response_time_ms: Some(10),
        error_message: Some("Mock mode: No real database configured".to_string()),
        last_check: chrono::Utc::now().to_rfc3339(),
    }
}

/// Health endpoint with real BDD test
pub async fn simple_health_with_db() -> Result<HttpResponse> {
    let db_connection = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost:5434/test".to_string());

    println!("🔍 Testing database connection: {}", db_connection.replace(":password@", ":***@"));

    let db_status = if db_connection.starts_with("postgresql://") {
        test_postgresql_connection(&db_connection).await
    } else {
        test_mock_database().await
    };

    let overall_status = match db_status.status {
        SimpleStatus::Healthy => SimpleStatus::Healthy,
        SimpleStatus::Unhealthy | SimpleStatus::Degraded => SimpleStatus::Degraded,
    };

    let response = SimpleHealthResponse {
        service_status: overall_status,
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: "1.0.0".to_string(),
        database: db_status.clone(),
        system: SimpleSystemInfo {
            hostname: gethostname::gethostname().to_string_lossy().to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            pid: std::process::id(),
        },
    };

    match response.database.status {
        SimpleStatus::Healthy => println!("✅ Database connection: SUCCESS"),
        SimpleStatus::Degraded => println!("⚠️ Database connection: DEGRADED"),
        SimpleStatus::Unhealthy => println!("❌ Database connection: FAILED"),
    }

    Ok(HttpResponse::Ok().json(response))
}

/// BDD test endpoint only
pub async fn database_test_only() -> Result<HttpResponse> {
    let db_connection = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost:5434/test".to_string());

    println!("🔍 Testing database connection: {}", db_connection.replace(":password@", ":***@"));

    let db_status = if db_connection.starts_with("postgresql://") {
        test_postgresql_connection(&db_connection).await
    } else {
        test_mock_database().await
    };

    let response = json!({
        "database_test": {
            "connection_string": db_connection.replace(":password@", ":***@"),
            "status": db_status.status,
            "connection_available": db_status.connection_available,
            "response_time_ms": db_status.response_time_ms,
            "error_message": db_status.error_message,
            "last_check": db_status.last_check
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "test_type": "database_only"
    });

    match db_status.status {
        SimpleStatus::Healthy => {
            println!("✅ Database test: SUCCESS");
            Ok(HttpResponse::Ok().json(response))
        },
        SimpleStatus::Degraded => {
            println!("⚠️ Database test: DEGRADED");
            Ok(HttpResponse::Ok().json(response))
        },
        SimpleStatus::Unhealthy => {
            println!("❌ Database test: FAILED");
            Ok(HttpResponse::ServiceUnavailable().json(response))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_database_status() {
        let status = test_mock_database().await;
        assert_eq!(status.status, SimpleStatus::Healthy);
        assert!(!status.connection_available);
        assert!(status.response_time_ms.is_some());
    }

    #[test]
    fn test_simple_status_serialization() {
        let status = SimpleStatus::Healthy;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"healthy\"");
    }

    #[tokio::test]
    async fn test_postgresql_connection_invalid() {
        // Test with an invalid connection string
        let status =
            test_postgresql_connection("postgresql://invalid:invalid@nonexistent:5432/test").await;
        assert_eq!(status.status, SimpleStatus::Unhealthy);
        assert!(!status.connection_available);
        assert!(status.error_message.is_some());
    }

    #[test]
    fn test_safe_duration_conversion() {
        let duration = std::time::Duration::from_millis(100);
        let ms = safe_duration_to_ms(duration);
        assert_eq!(ms, 100);
    }
}
