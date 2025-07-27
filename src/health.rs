//! Health Check Handler
//!
//! This module provides comprehensive health check capability for the authentication service.
//! It includes system status monitoring, dependency checks, and detailed service information.
//!
//! # Features
//! - Basic health status endpoint
//! - Detailed system information
//! - Database connectivity check
//! - Service metrics and uptime
//! - Hybrid responses (JSON for API, HTML for browsers)
//!
//! # Endpoints
//! - `/health` - Basic health check
//! - `/health/detailed` - Comprehensive system status
//! - `/health/ready` - Readiness probe for orchestration
//! - `/health/live` - Liveness probe for orchestration

use crate::sqlx::database::Database;
use crate::utils::response_handler::ResponseHandler;
use actix_web::{web, HttpRequest, Responder};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use simbld_http::responses::{ResponsesSuccessCodes, ResponsesTypes};
use std::time::{Duration, SystemTime};

/// Service health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Overall service status
    pub status: ServiceStatus,
    /// Service identification
    pub service: String,
    /// Service version
    pub version: String,
    /// Current timestamp
    pub timestamp: DateTime<Utc>,
    /// Service uptime in seconds
    pub uptime: u64,
    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

/// Detailed health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetailedHealth {
    /// Basic health status
    #[serde(flatten)]
    pub basic: HealthStatus,
    /// System information
    pub system: SystemInfo,
    /// Dependencies status
    pub dependencies: DependenciesStatus,
    /// Performance metrics
    pub metrics: HealthMetrics,
}

/// Service status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ServiceStatus {
    /// Service is fully operational
    Healthy,
    /// Service is operational but with warnings
    Degraded,
    /// Service is not operational
    Unhealthy,
}

/// System information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Hostname
    pub hostname: String,
    /// Operating system
    pub os: String,
    /// Architecture
    pub arch: String,
    /// Number of CPU cores
    pub cpu_cores: usize,
    /// Available memory information
    pub memory: MemoryInfo,
    /// CPU usage information
    pub cpu: CpuInfo,
    /// Disk usage information
    pub disk: DiskInfo,
}

/// Memory information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryInfo {
    /// Total memory in bytes
    pub total: u64,
    /// Available memory in bytes
    pub available: u64,
    /// Used memory in bytes
    pub used: u64,
    /// Memory usage percentage
    pub usage_percent: f64,
}

/// CPU information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    /// CPU usage percentage
    pub usage_percent: f32,
    /// CPU frequency in MHz
    pub frequency: u64,
    /// CPU brand
    pub brand: String,
}

/// Disk information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    /// Total disk space in bytes
    pub total: u64,
    /// Available disk space in bytes
    pub available: u64,
    /// Used disk space in bytes
    pub used: u64,
    /// Disk usage percentage
    pub usage_percent: f64,
}

/// Dependencies status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependenciesStatus {
    /// Database connection status
    pub database: DependencyStatus,
    /// External services status
    pub external_services: Vec<ExternalServiceStatus>,
}

/// Individual dependency status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyStatus {
    /// Dependency name
    pub name: String,
    /// Status
    pub status: ServiceStatus,
    /// Response time in milliseconds
    pub response_time_ms: u64,
    /// Last check timestamp
    pub last_check: DateTime<Utc>,
    /// Error message if unhealthy
    pub error: Option<String>,
}

/// External service status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalServiceStatus {
    /// Service name
    pub name: String,
    /// Service URL
    pub url: String,
    /// Status
    pub status: ServiceStatus,
    /// Response time in milliseconds
    pub response_time_ms: u64,
}

/// Health metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    /// Total requests served
    pub total_requests: u64,
    /// Requests per second (approximation)
    pub requests_per_second: f64,
    /// Average response time in milliseconds
    pub avg_response_time_ms: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
    /// Active connections
    pub active_connections: u32,
}

/// Application state for health tracking
#[derive(Debug, Clone)]
pub struct HealthState {
    /// Service start time
    pub start_time: SystemTime,
    /// Service version
    pub version: String,
    /// Service name
    pub service_name: String,
}

impl HealthState {
    /// Create a new health state
    pub fn new(service_name: String, version: String) -> Self {
        Self {
            start_time: SystemTime::now(),
            version,
            service_name,
        }
    }

    /// Get service uptime in seconds
    pub fn uptime(&self) -> u64 {
        self.start_time.elapsed().unwrap_or(Duration::from_secs(0)).as_secs()
    }
}

/// Basic health check endpoint
pub async fn health_check(
    req: HttpRequest,
    health_state: web::Data<HealthState>,
) -> impl Responder {
    let start_time = std::time::Instant::now();

    let status = HealthStatus {
        status: ServiceStatus::Healthy,
        service: health_state.service_name.clone(),
        version: health_state.version.clone(),
        timestamp: Utc::now(),
        uptime: health_state.uptime(),
        metadata: Some(json!({
            "check_type": "basic",
            "endpoint": "/health"
        })),
    };

    let response_type = ResponsesTypes::Success(ResponsesSuccessCodes::Ok);
    let response_body = serde_json::to_string(&status).unwrap_or_else(|_| {
        json!({
            "status": "healthy",
            "service": health_state.service_name.clone(),
            "error": "Failed to serialize response"
        })
        .to_string()
    });

    ResponseHandler::create_hybrid_response(
        &req,
        response_type,
        Some("Service Health Check"),
        Some(&response_body),
        start_time.elapsed(),
    )
}

/// Detailed health check endpoint
pub async fn detailed_health_check(
    req: HttpRequest,
    health_state: web::Data<HealthState>,
    database: web::Data<Database>,
) -> impl Responder {
    let start_time = std::time::Instant::now();

    // Check database connectivity
    let db_status = check_database_health(&database).await;

    // Determine overall status
    let overall_status = if db_status.status == ServiceStatus::Healthy {
        ServiceStatus::Healthy
    } else {
        ServiceStatus::Degraded
    };

    let detailed_health = DetailedHealth {
        basic: HealthStatus {
            status: overall_status,
            service: health_state.service_name.clone(),
            version: health_state.version.clone(),
            timestamp: Utc::now(),
            uptime: health_state.uptime(),
            metadata: Some(json!({
                "check_type": "detailed",
                "endpoint": "/health/detailed"
            })),
        },
        system: get_system_info(),
        dependencies: DependenciesStatus {
            database: db_status,
            external_services: vec![], // TODO: Add external services
        },
        metrics: get_health_metrics(),
    };

    let response_type = ResponsesTypes::Success(ResponsesSuccessCodes::Ok);
    let response_body = serde_json::to_string_pretty(&detailed_health).unwrap_or_else(|_| {
        json!({
            "status": "healthy",
            "service": health_state.service_name.clone(),
            "error": "Failed to serialize detailed response"
        })
        .to_string()
    });

    ResponseHandler::create_hybrid_response(
        &req,
        response_type,
        Some("Detailed Health Check"),
        Some(&response_body),
        start_time.elapsed(),
    )
}

/// Readiness probe endpoint
pub async fn readiness_probe(req: HttpRequest, database: web::Data<Database>) -> impl Responder {
    let start_time = std::time::Instant::now();

    // Check if the service is ready
    let db_status = check_database_health(&database).await;
    let is_ready = db_status.status == ServiceStatus::Healthy;

    let response_type = if is_ready {
        ResponsesTypes::Success(ResponsesSuccessCodes::Ok)
    } else {
        ResponsesTypes::ServerError(
            simbld_http::responses::ResponsesServerCodes::ServiceUnavailable,
        )
    };

    let status = json!({
        "ready": is_ready,
        "timestamp": Utc::now(),
        "checks": {
            "database": db_status.status
        }
    });

    ResponseHandler::create_hybrid_response(
        &req,
        response_type,
        Some("Readiness Probe"),
        Some(&status.to_string()),
        start_time.elapsed(),
    )
}

/// Liveness probe endpoint
pub async fn liveness_probe(req: HttpRequest) -> impl Responder {
    let start_time = std::time::Instant::now();

    let response_type = ResponsesTypes::Success(ResponsesSuccessCodes::Ok);
    let status = json!({
        "alive": true,
        "timestamp": Utc::now(),
        "pid": std::process::id()
    });

    ResponseHandler::create_hybrid_response(
        &req,
        response_type,
        Some("Liveness Probe"),
        Some(&status.to_string()),
        start_time.elapsed(),
    )
}

/// Check database health
async fn check_database_health(database: &Database) -> DependencyStatus {
    let start_time = std::time::Instant::now();

    // Try a simple database query
    let (status, error) = match database.user_exists("health_check@example.com").await {
        Ok(_) => (ServiceStatus::Healthy, None),
        Err(e) => (ServiceStatus::Unhealthy, Some(e.to_string())),
    };

    DependencyStatus {
        name: "PostgreSQL Database".to_string(),
        status,
        response_time_ms: start_time.elapsed().as_millis() as u64,
        last_check: Utc::now(),
        error,
    }
}

/// Get system information
fn get_system_info() -> SystemInfo {
    SystemInfo {
        hostname: gethostname::gethostname().to_string_lossy().to_string(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        cpu_cores: num_cpus::get(),
        memory: get_memory_info(),
        cpu: get_cpu_info(),
        disk: get_disk_info(),
    }
}

/// Get CPU information
fn get_cpu_info() -> CpuInfo {
    CpuInfo {
        usage_percent: 0.0,
        frequency: 0,
        brand: "Unknown".to_string(),
    }
}

/// Get disk information
fn get_disk_info() -> DiskInfo {
    DiskInfo {
        total: 0,
        available: 0,
        used: 0,
        usage_percent: 0.0,
    }
}

/// Get memory information
fn get_memory_info() -> MemoryInfo {
    MemoryInfo {
        total: 0,
        available: 0,
        used: 0,
        usage_percent: 0.0,
    }
}

/// Get health metrics
fn get_health_metrics() -> HealthMetrics {
    // This is a placeholder implementation
    // In a real app, collect these metrics from a monitoring system
    HealthMetrics {
        total_requests: 0,
        requests_per_second: 0.0,
        avg_response_time_ms: 0.0,
        error_rate_percent: 0.0,
        active_connections: 0,
    }
}

/// Configure health check routes
pub fn configure_health_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/health")
            .route("", web::get().to(health_check))
            .route("/detailed", web::get().to(detailed_health_check))
            .route("/ready", web::get().to(readiness_probe))
            .route("/live", web::get().to(liveness_probe)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web::Data};

    #[test]
    async fn test_health_state_creation() {
        let state = HealthState::new("test_service".to_string(), "1.0.0".to_string());
        assert_eq!(state.service_name, "test_service");
        assert_eq!(state.version, "1.0.0");
        assert!(state.uptime() < 1); // Should be recent
    }

    #[test]
    async fn test_service_status_serialization() {
        let status = ServiceStatus::Healthy;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"healthy\"");
    }

    #[tokio::test]
    async fn test_liveness_probe() {
        let req = test::TestRequest::default()
            .insert_header(("Accept", "application/json"))
            .to_http_request();

        let response = liveness_probe(req).await;
        let response = response.respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(response.status(), 200);
    }

    #[test]
    async fn test_system_info() {
        let info = get_system_info();
        assert!(!info.hostname.is_empty());
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());
        assert!(info.cpu_cores > 0);
        assert!(info.memory.total > 0);
        assert!(info.cpu.usage_percent >= 0.0);
        assert!(info.disk.total > 0);
    }

    #[test]
    async fn test_health_status_serialization() {
        let status = HealthStatus {
            status: ServiceStatus::Healthy,
            service: "test".to_string(),
            version: "1.0.0".to_string(),
            timestamp: Utc::now(),
            uptime: 3600,
            metadata: Some(json!({"test": "data"})),
        };

        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("healthy"));
        assert!(json.contains("test"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    async fn test_memory_info() {
        let info = get_memory_info();
        assert!(info.usage_percent >= 0.0);
        assert!(info.usage_percent <= 100.0);
    }

    #[tokio::test]
    async fn test_health_check_basic() {
        let req = test::TestRequest::default()
            .insert_header(("Accept", "application/json"))
            .to_http_request();

        let health_state =
            Data::new(HealthState::new("test_service".to_string(), "1.0.0".to_string()));

        let response = health_check(req, health_state).await;
        let response = response.respond_to(&test::TestRequest::default().to_http_request());
        assert_eq!(response.status(), 200);
    }

    #[test]
    async fn test_dependency_status() {
        let status = DependencyStatus {
            name: "Test DB".to_string(),
            status: ServiceStatus::Healthy,
            response_time_ms: 50,
            last_check: Utc::now(),
            error: None,
        };

        assert_eq!(status.name, "Test DB");
        assert_eq!(status.status, ServiceStatus::Healthy);
        assert_eq!(status.response_time_ms, 50);
        assert!(status.error.is_none());
    }
}
