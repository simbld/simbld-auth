//! Server with `PostgreSQL` database connection

mod simple_health;

use crate::simple_health::{database_test_only, simple_health_with_db};
use actix_web::{web, App, HttpResponse, HttpServer, Result};
use serde_json::json;

/// Health check endpoint
async fn health_check() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": "1.0.0",
        "message": "API server with PostgreSQL"
    })))
}

/// Configure real routes
fn configure_real_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Health with a database
        .service(
            web::scope("/simple-health")
                .route("", web::get().to(simple_health_with_db))
                .route("/db-only", web::get().to(database_test_only)),
        )
        .route("/health", web::get().to(health_check));

    // TODO: Add real auth/user routes here when ready
    // .configure(configure_auth_routes)
    // .configure(configure_user_routes)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    println!("Server started on http://localhost:3000");
    println!("Mode: PRODUCTION with PostgreSQL");
    println!(" Database: Uses your migration schema");
    println!("\n✅ Currently available endpoints:");
    println!("GET/simple-health/db-only ← TEST DB.");
    println!("GET/simple-health ← FULL DB STATUS.");
    println!("GET/health ← BASIC HEALTH!");
    println!("\n Coming soon:");
    println!("POST /api/v1/auth/register ← When auth module ready");
    println!("PUT  /api/v1/users/{{id}}/password ← When user module ready");

    HttpServer::new(|| App::new().configure(configure_real_routes))
        .bind("127.0.0.1:3000")?
        .run()
        .await
}
