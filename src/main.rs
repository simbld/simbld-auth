//! Simbld_auth Secure Authentication Service
//!
//! A comprehensive authentication microservice with multiple provider support

mod auth;
mod postgres;
mod types;
mod user;

use crate::postgres::config;
use actix_web::{web, App, HttpServer};
use dotenvy::dotenv;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    // Load configuration
    let config = config::load_config().map_err(|e| {
        eprintln!("❌ Configuration error: {}", e);
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;

    // Connect to database
    let db = Arc::new(postgres::Database::new(&config.database_url).await.map_err(|e| {
        eprintln!("❌ Database connection error: {}", e);
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())
    })?);

    let bind_address = config::get_bind_address(&config);

    println!("🚀 simbld_auth server starting on {}", bind_address);
    println!("📊 Rate limit: {} req/min", config.rate_limit);
    println!("🔗 CORS origins: {:?}", config.cors_origins);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .app_data(web::Data::new(config.clone()))
            .route("/health", web::get().to(health_check))
    })
    .bind(bind_address)?
    .run()
    .await
}

/// Health check endpoint
async fn health_check() -> impl actix_web::Responder {
    use simbld_http::responses::ResponsesSuccessCodes;
    ResponsesSuccessCodes::Ok.into_response()
}
