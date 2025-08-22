//! Shared mock handlers
use actix_web::{web, HttpResponse};
use serde_json::{json, Value};

/// Health check endpoint
pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
        "message": "Mock API server"
    }))
}

/// Mock login endpoint
pub async fn mock_login(payload: web::Json<Value>) -> HttpResponse {
    let email = payload.get("email").and_then(|v| v.as_str());
    let password = payload.get("password").and_then(|v| v.as_str());

    if email.is_none() || password.is_none() {
        return HttpResponse::BadRequest().json(json!({
            "error": "Invalid credentials",
            "message": "Email and password are required"
        }));
    }

    HttpResponse::Ok().json(json!({
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
    }))
}

/// Mock register endpoint
pub async fn mock_register(payload: web::Json<Value>) -> HttpResponse {
    let email = payload.get("email").and_then(|v| v.as_str());
    let username = payload.get("username").and_then(|v| v.as_str());
    let password = payload.get("password").and_then(|v| v.as_str());

    if email.is_none() || username.is_none() || password.is_none() {
        return HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "message": "Email, username, and password are required"
        }));
    }

    HttpResponse::Created().json(json!({
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "email": email.unwrap(),
        "username": username.unwrap(),
        "message": "User registered successfully",
        "status": "pending_verification",
        "created_at": chrono::Utc::now().to_rfc3339()
    }))
}

/// Mock change password endpoint
pub async fn mock_change_password(
    path: web::Path<String>,
    payload: web::Json<Value>,
) -> HttpResponse {
    let user_id = path.into_inner();
    let current_password = payload.get("current_password").and_then(|v| v.as_str());
    let new_password = payload.get("new_password").and_then(|v| v.as_str());

    if current_password.is_none() || new_password.is_none() {
        return HttpResponse::BadRequest().json(json!({
            "error": "Validation failed",
            "message": "Both current_password and new_password are required"
        }));
    }

    if let Some(pwd) = new_password {
        if pwd.len() < 8 {
            return HttpResponse::BadRequest().json(json!({
                "error": "Validation failed",
                "message": "The new password must be at least 8 characters long"
            }));
        }
    }

    HttpResponse::Ok().json(json!({
        "message": "Password changed successfully",
        "user_id": user_id,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}
