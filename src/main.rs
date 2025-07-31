//! Serveur ultra-minimal pour tester les routes
//! SANS aucune dépendance compliquée

use actix_web::{web, App, HttpResponse, HttpServer, Result};
use serde_json::json;

/// Route de santé ultra-simple (pas de modules externes)
async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
        "message": "Serveur de test fonctionnel"
    })))
}

/// Route protégée mockée (sans vraie auth)
async fn mock_protected() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "message": "Protected route (mocked)",
        "user_id": "mock-user-123",
        "authenticated": true
    })))
}

/// Route utilisateurs mockée
async fn mock_users() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "users": [
            {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "username": "testuser",
                "email": "test@example.com",
                "status": "active"
            }
        ],
        "total": 1
    })))
}

/// Route utilisateur par ID mockée
async fn mock_user_by_id(path: web::Path<String>) -> Result<HttpResponse> {
    let user_id = path.into_inner();
    Ok(HttpResponse::Ok().json(json!({
        "id": user_id,
        "username": "testuser",
        "email": "test@example.com",
        "firstname": "Test",
        "lastname": "User",
        "status": "active",
        "email_verified": true,
        "created_at": chrono::Utc::now().to_rfc3339()
    })))
}

/// Route de login mockée
async fn mock_login(payload: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("unknown");

    Ok(HttpResponse::Ok().json(json!({
        "access_token": "mock_access_token_12345",
        "refresh_token": "mock_refresh_token_67890",
        "Expires in": 3600,
        "user": {
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "email": email,
            "username": "testuser"
        }
    })))
}

/// Route de register mockée
async fn mock_register(payload: web::Json<serde_json::Value>) -> Result<HttpResponse> {
    let email = payload.get("email").and_then(|v| v.as_str()).unwrap_or("unknown");

    Ok(HttpResponse::Created().json(json!({
        "user_id": "550e8400-e29b-41d4-a716-446655440000",
        "email": email,
        "message": "User registered successfully"
    })))
}

/// Configuration des routes ultra-simples
fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Routes de santé
        .route("/api/v1/health", web::get().to(health_check))
        // Routes d'authentification mocks
        .service(
            web::scope("/api/v1/auth")
                .route("/login", web::post().to(mock_login))
                .route("/register", web::post().to(mock_register)),
        )
        // Routes protégées mocks
        .service(
            web::scope("/api/v1/protected")
                .route("", web::get().to(mock_protected))
                .route("/profile", web::get().to(mock_protected))
                .route("/settings", web::put().to(mock_protected))
                .route("/orders", web::get().to(mock_protected))
                .route("/logout", web::post().to(mock_protected)),
        )
        // Routes utilisateurs mocks
        .service(
            web::scope("/api/v1/users")
                .route("", web::get().to(mock_users))
                .route("/{id}", web::get().to(mock_user_by_id))
                .route("/stats", web::get().to(mock_users))
                .route("/by-email", web::get().to(mock_users))
                .route("/by-username", web::get().to(mock_users)),
        );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("🚀 Serveur ultra-minimal démarré sur http://localhost:3000");
    println!("📋 Routes disponibles :");
    println!("   GET /api/v1/health");
    println!("   POST /api/v1/auth/login");
    println!("   POST /api/v1/auth/register");
    println!("   GET /api/v1/protected");
    println!("   GET /api/v1/protected/profile");
    println!("   GET /api/v1/users");
    println!("   GET /api/v1/users/{{id}}");

    HttpServer::new(|| App::new().configure(configure_routes)).bind("127.0.0.1:3000")?.run().await
}
