//! Simbld_auth Secure Authentication Service
//!
//! A comprehensive authentication microservice with multiple provider support using simbld_http API

pub mod auth;
pub mod handlers;
pub mod postgres;
pub mod types;
pub mod user;

use crate::postgres::config;
use actix_web::{middleware::Logger, web, App, HttpServer};
use dotenvy::dotenv;
use simbld_http::responses::ResponsesServerCodes;
use simbld_http::UnifiedMiddleware;
use std::{sync::Arc, time::Duration};
pub use types::StartupError;

#[actix_web::main]
async fn main() -> Result<(), StartupError> {
    // Initialize environment
    dotenv().ok();
    env_logger::init();

    println!("🚀 Starting simbld_auth server...");

    // Load configuration
    let config = config::load_config().map_err(|e| {
        eprintln!("❌ Configuration error: {}", e);
        eprintln!("   This would be HTTP: {:?}", ResponsesServerCodes::InternalServerError);
        StartupError::Config(e.to_string())
    })?;

    // Connect to database
    let db = postgres::Database::new(&config.database_url).await.map_err(|e| {
        eprintln!("❌ Database connection error: {}", e);
        eprintln!("   This would be HTTP: {:?}", ResponsesServerCodes::InternalServerError);
        StartupError::Database(e.to_string())
    })?;

    let db = Arc::new(db);
    let bind_address = config::get_bind_address(&config);

    // Server info using YOUR response context
    println!("✅ Configuration loaded - Status: {:?}", ResponsesServerCodes::Ok);
    println!("✅ Database connected - Status: {:?}", ResponsesServerCodes::Ok);
    println!("🌐 Server binding to: {}", bind_address);
    println!("📊 Rate limit: {} req/min", config.rate_limit);
    println!("🔗 CORS origins: {:?}", config.cors_origins);

    // Start HTTP server
    let server_result = HttpServer::new(move || {
        App::new()
            // Inject dependencies
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(config.clone()))
            // YOUR simbld_http middleware stack
            .wrap(UnifiedMiddleware::simple(
                config.cors_origins.clone(),
                config.rate_limit,
                Duration::from_secs(60),
            ))
            .wrap(Logger::default())
            // Routes using YOUR API handlers
            .service(
                web::scope("/api/v1").route("/health", web::get().to(handlers::health_check)), // .route("/auth/register", web::post().to(handlers::auth::register))
                                                                                               // .route("/auth/login", web::post().to(handlers::auth::login))
            )
            // Root health check
            .route("/health", web::get().to(handlers::health_check))
    })
    .bind(&bind_address)
    .map_err(|e| {
        eprintln!("❌ Server binding error: {}", e);
        eprintln!("   This would be HTTP: {:?}", ResponsesServerCodes::InternalServerError);
        StartupError::ServerBind(format!("Failed to bind to {}: {}", bind_address, e))
    })?
    .run()
    .await;

    // Handle server runtime errors
    server_result.map_err(|e| {
        eprintln!("❌ Server runtime error: {}", e);
        eprintln!("   This would be HTTP: {:?}", ResponsesServerCodes::InternalServerError);
        StartupError::ServerBind(format!("Server runtime error: {}", e))
    })?;

    println!("✅ simbld_auth server shutdown complete");
    Ok(())
}
