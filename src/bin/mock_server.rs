//! Mock server for testing and development
//! Uses only simulated responses, no real database

use actix_web::{web, App, HttpResponse, HttpServer};
use serde_json::json;

/// Mock protected route handler - simulates authenticated endpoints
async fn mock_protected() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "message": "Protected route accessed successfully",
        "user_id": "mock-user-123",
        "authenticated": true
    })))
}

/// List users endpoint - returns paginated user collection
async fn mock_users() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "users": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "testuser",
                "email": "test@example.com",
                "status": "active"
            }
        ],
        "total": 1,
        "limit": 50,
        "offset": 0
    })))
}

/// Get user by ID endpoint - returns detailed user information
async fn mock_user_by_id(path: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();
    Ok(HttpResponse::Ok().json(json!({
        "id": user_id,
        "username": "testuser",
        "email": "test@example.com",
        "firstname": "Test",
        "lastname": "User",
        "display_name": "Test User",
        "status": "active",
        "email_verified": true,
        "mfa_enabled": false,
        "created_at": chrono::Utc::now().to_rfc3339(),
        "updated_at": chrono::Utc::now().to_rfc3339()
    })))
}

/// User authentication endpoint - validates credentials and returns JWT tokens
async fn mock_login(payload: web::Json<serde_json::Value>) -> actix_web::Result<HttpResponse> {
    let email = payload.get("email").and_then(|v| v.as_str());
    let password = payload.get("password").and_then(|v| v.as_str());

    // Basic validation
    if email.is_none() || password.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Invalid credentials",
            "message": "Email and password are required"
        })));
    }

    Ok(HttpResponse::Ok().json(json!({
        "access_token": "mock_access_token_12345",
        "refresh_token": "mock_refresh_token_67890",
        "token_type": "Bearer",
        "expires_in": 3600,
        "user": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "email": email.unwrap(),
            "username": "testuser"
        },
        "login_timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// User registration endpoint - creates a new user account
async fn mock_register(payload: web::Json<serde_json::Value>) -> actix_web::Result<HttpResponse> {
    let email = payload.get("email").and_then(|v| v.as_str());
    let username = payload.get("username").and_then(|v| v.as_str());
    let password = payload.get("password").and_then(|v| v.as_str());

    // Validation
    if email.is_none() || username.is_none() || password.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "message": "Email, username, and password are required"
        })));
    }

    Ok(HttpResponse::Created().json(json!({
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "email": email.unwrap(),
        "username": username.unwrap(),
        "message": "User registered successfully",
        "status": "pending_verification",
        "created_at": chrono::Utc::now().to_rfc3339()
    })))
}

/// Change user password endpoint - validates and updates user credentials
async fn mock_change_password(
    path: web::Path<String>,
    payload: web::Json<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();
    let current_password = payload.get("current_password").and_then(|v| v.as_str());
    let new_password = payload.get("new_password").and_then(|v| v.as_str());

    // Input validation
    if current_password.is_none() || new_password.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "message": "Both current_password and new_password are required"
        })));
    }

    // Password strength validation (mock)
    if let Some(pwd) = new_password {
        if pwd.len() < 8 {
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": "Validation failed",
                "message": "The new password must be at least 8 characters long"
            })));
        }
    }

    Ok(HttpResponse::Ok().json(json!({
        "message": "Password changed successfully",
        "user_id": user_id,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Health check endpoint - returns server status and metadata
async fn health_check() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
        "message": "API server is running"
    })))
}

/// Simple detailed health check - mock version
async fn simple_detailed_health() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "healthy",
        "service": "API Mock Server",
        "version": "1.0.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "database": {
            "status": "mocked",
            "message": "No real database connected - using mock responses",
            "postgresql_available": false,
            "connection_string": "NOT_CONFIGURED",
            "response_time_ms": null
        },
        "system": {
            "hostname": "localhost",
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "pid": std::process::id(),
            "cpu_cores": num_cpus::get()
        },
        "metrics": {
            "uptime_seconds": 3600,
            "total_requests": 42,
            "active_connections": 1,
            "avg_response_time_ms": 45.2,
            "error_rate_percent": 0.1
        }
    })))
}

/// Readiness probe
async fn readiness_probe() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "ready": true,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "checks": {
            "server": "healthy",
            "database": "mocked",
            "memory": "normal",
            "disk": "sufficient"
        }
    })))
}

/// Liveness probe
async fn liveness_probe() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "alive": true,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "pid": std::process::id(),
        "uptime": 3600
    })))
}

/// Update user profile endpoint - modifies user personal information
async fn mock_update_profile(
    path: web::Path<String>,
    payload: web::Json<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();

    Ok(HttpResponse::Ok().json(json!({
        "message": "Profile updated successfully",
        "user_id": user_id,
        "updated_fields": payload.into_inner(),
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Update user status endpoint - admin-only user account management
async fn mock_update_status(
    path: web::Path<String>,
    payload: web::Json<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();
    let status = payload.get("status").and_then(|v| v.as_str()).unwrap_or("active");

    Ok(HttpResponse::Ok().json(json!({
        "message": "User status updated successfully",
        "user_id": user_id,
        "new_status": status,
        "updated_by": "admin",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Assign role endpoint - admin-only role management
async fn mock_assign_role(
    path: web::Path<String>,
    payload: web::Json<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();
    let role = payload.get("role").and_then(|v| v.as_str()).unwrap_or("user");

    Ok(HttpResponse::Ok().json(json!({
        "message": "Role assigned successfully",
        "user_id": user_id,
        "role": role,
        "assigned_by": "admin",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Get user roles endpoint - returns user permission set
async fn mock_get_user_roles(path: web::Path<String>) -> actix_web::Result<HttpResponse> {
    let user_id = path.into_inner();

    Ok(HttpResponse::Ok().json(json!({
        "user_id": user_id,
        "roles": ["user", "customer"],
        "permissions": ["read_profile", "update_profile", "create_orders"]
    })))
}

/// User statistics endpoint - admin-only analytics data
async fn mock_user_stats() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "total_users": 1547,
        "active_users": 1289,
        "pending_users": 156,
        "suspended_users": 102,
        "verified_emails": 1203,
        "mfa_enabled": 687,
        "recent_logins": 845,
        "generated_at": chrono::Utc::now().to_rfc3339()
    })))
}

/// Find a user by email endpoint - admin-only user lookup
async fn mock_user_by_email(
    query: web::Query<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    let email = query.get("email").and_then(|v| v.as_str()).unwrap_or("unknown");

    if email == "unknown" {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Missing parameter",
            "message": "Email parameter is required"
        })));
    }

    Ok(HttpResponse::Ok().json(json!({
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "username": "testuser",
        "email": email,
        "firstname": "Test",
        "lastname": "User",
        "status": "active",
        "found_by": "email"
    })))
}

/// Find user by username endpoint - admin-only user lookup
async fn mock_user_by_username(
    query: web::Query<serde_json::Value>,
) -> actix_web::Result<HttpResponse> {
    let username = query.get("username").and_then(|v| v.as_str()).unwrap_or("unknown");

    if username == "unknown" {
        return Ok(HttpResponse::BadRequest().json(json!({
            "error": "Missing parameter",
            "message": "Username parameter is required"
        })));
    }

    Ok(HttpResponse::Ok().json(json!({
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "username": username,
        "email": "test@example.com",
        "firstname": "Test",
        "lastname": "User",
        "status": "active",
        "found_by": "username"
    })))
}

/// Mock database connection test - simulates real DB connectivity
async fn mock_db_test() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "database_status": "mocked",
        "connection": "simulated",
        "test_query": "SELECT 1",
        "result": "success (mock)",
        "message": "This is a mock response. Real database would return actual connection status.",
        "postgresql_available": false,
        "mock_mode": true,
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Mock database tables info - simulates table listing
async fn mock_db_tables() -> actix_web::Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "tables": [
            {
                "name": "users",
                "rows": 1547,
                "size": "2.3MB"
            },
            {
                "name": "sessions",
                "rows": 234,
                "size": "0.8MB"
            },
            {
                "name": "roles",
                "rows": 12,
                "size": "0.1MB"
            }
        ],
        "total_tables": 3,
        "database_size": "3.2MB",
        "status": "mocked",
        "message": "Mock table information. A real database would show actual tables.",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Configure all mock routes
fn configure_mock_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Health routes with mock mode
        .service(
            web::scope("/simple-health")
                .route("", web::get().to(simple_health_with_db))
                .route("/db-only", web::get().to(database_test_only)),
        )
        .route("/api/v1/health", web::get().to(health_check))
        .route("/health", web::get().to(health_check))
        .route("/health/detailed", web::get().to(simple_detailed_health))
        .route("/health/ready", web::get().to(readiness_probe))
        .route("/health/live", web::get().to(liveness_probe))
        // Authentication routes - MOCK
        .service(
            web::scope("/api/v1/auth")
                .route("/login", web::post().to(mock_login))
                .route("/register", web::post().to(mock_register)),
        )
        // Protected routes - MOCK
        .service(
            web::scope("/api/v1/protected")
                .route("", web::get().to(mock_protected))
                .route("/profile", web::get().to(mock_protected))
                .route("/settings", web::put().to(mock_protected))
                .route("/orders", web::get().to(mock_protected))
                .route("/logout", web::post().to(mock_protected)),
        )
        // User management routes - MOCK
        .service(
            web::scope("/api/v1/users")
                .route("", web::get().to(mock_users))
                .route("/stats", web::get().to(mock_user_stats))
                .route("/by-email", web::get().to(mock_user_by_email))
                .route("/by-username", web::get().to(mock_user_by_username))
                .route("/{id}", web::get().to(mock_user_by_id))
                .route("/{id}/profile", web::put().to(mock_update_profile))
                .route("/{id}/password", web::put().to(mock_change_password))
                .route("/{id}/status", web::put().to(mock_update_status))
                .route("/{id}/roles", web::post().to(mock_assign_role))
                .route("/{id}/roles", web::get().to(mock_get_user_roles)),
        )
        // Debug routes - MOCK
        .service(
            web::scope("/api/v1/debug")
                .route("/db-test", web::get().to(mock_db_test))
                .route("/db-tables", web::get().to(mock_db_tables)),
        );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    // Server startup information
    println!(" Mock Server started on http://localhost:3001");
    println!("\n Available endpoints:");
    println!("┌─ Health & System");
    println!("│GET/api/v1/health");
    println!("│GET/health ⭐ WORKING.");
    println!("│GET/health/detailed ⭐ WORKING.");
    println!("│GET/health/ready ⭐ WORKING.");
    println!("│GET/health/live ⭐ WORKING.");
    println!("├─ Authentication");
    println!("│POST/api/v1/auth/login");
    println!("│POST/api/v1/auth/register");
    println!("├─ Protected Routes");
    println!("│GET/api/v1/protected");
    println!("│GET/api/v1/protected/profile");
    println!("│PUT/api/v1/protected/settings");
    println!("│GET/api/v1/protected/orders");
    println!("│POST/api/v1/protected/logout");
    println!("├─ User Management");
    println!("│GET/api/v1/users");
    println!("│GET/api/v1/users/{{id}}");
    println!("│PUT/api/v1/users/{{id}}/profile");
    println!("│PUT/api/v1/users/{{id}}/password ⭐ TARGET.");
    println!("│PUT/api/v1/users/{{id}}/status");
    println!("│POST/api/v1/users/{{id}}/roles");
    println!("│GET/api/v1/users/{{id}}/roles");
    println!("│GET/api/v1/users/stats");
    println!("│GET/api/v1/users/by-email");
    println!("│GET/api/v1/users/by-username");
    println!("└─ Database Debug");
    println!("GET/api/v1/debug/db-test ⭐ NEW!");
    println!("GET/api/v1/debug/db-tables ⭐ NEW!");
    println!("\n All endpoints are mocked for testing purposes");
    println!("Database: MOCKED - No real PostgreSQL connection");
    println!("Use debug endpoints to simulate DB connectivity checks");

    HttpServer::new(|| App::new().configure(configure_mock_routes))
        .bind("127.0.0.1:3001")?
        .run()
        .await
}
