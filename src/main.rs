mod config;
mod database;
mod types;

use actix_web::{web, App, HttpServer, Responder};
use dotenvy::dotenv;
use std::sync::Arc;
use std::time::Duration;

use crate::database::Database;
use simbld_http::responses::{
    ResponsesClientCodes, ResponsesLocalApiCodes, ResponsesServerCodes, ResponsesSuccessCodes,
};
use simbld_http::{AuthMiddleware, HttpInterceptor, UnifiedMiddleware};

#[derive(serde::Deserialize)]
struct CreateUser {
    email: String,
    password: String,
    first_name: String,
    last_name: String,
}

#[derive(serde::Deserialize)]
struct LoginCredentials {
    email: String,
    password: String,
}

/// Register a new user
async fn register_user(
    user_data: web::Json<CreateUser>,
    db: web::Data<Arc<Database>>,
) -> impl Responder {
    match validate_user(&user_data, &db).await {
        Ok(()) => {
            // Simulate user creation in the database
            match db.create_user(&user_data.email, &user_data.first_name, &user_data.password).await
            {
                Ok(user_id) => {
                    println!(
                        "👤 New user created: {first_name} {last_name} {user_id}",
                        first_name = user_data.first_name,
                        last_name = user_data.last_name,
                        user_id = user_id
                    );
                    ResponsesSuccessCodes::Created.into_response()
                },
                Err(e) => {
                    println!("❌ Failed to create user: {e}");
                    ResponsesServerCodes::InternalServerError.into_response()
                },
            }
        },
        Err(ValidationError::EmailExists) => ResponsesClientCodes::Conflict.into_response(),
        Err(ValidationError::InvalidEmail) => ResponsesLocalApiCodes::InvalidEmail.into_response(),
        Err(ValidationError::WeakPassword) => {
            ResponsesLocalApiCodes::InvalidPassword.into_response()
        },
    }
}

/// Log in a user
async fn login_user(
    credentials: web::Json<LoginCredentials>,
    db: web::Data<Arc<Database>>,
) -> impl Responder {
    match authenticate(&credentials, &db).await {
        Ok(()) => ResponsesSuccessCodes::Ok.into_response(),
        Err(AuthError::InvalidCredentials) => {
            ResponsesLocalApiCodes::AuthentificationFailed.into_response()
        },
        Err(AuthError::AccountLocked) => ResponsesClientCodes::Forbidden.into_response(),
        Err(AuthError::DatabaseError) => ResponsesServerCodes::InternalServerError.into_response(),
    }
}

/// Validate user input
async fn validate_user(user_data: &CreateUser, db: &Database) -> Result<(), ValidationError> {
    use regex::Regex;

    // Email regex
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&user_data.email) {
        return Err(ValidationError::InvalidEmail);
    }

    // Password strength
    if user_data.password.len() < 8 {
        return Err(ValidationError::WeakPassword);
    }

    // Check email exists
    if db.user_exists(&user_data.email).await.unwrap_or(false) {
        return Err(ValidationError::EmailExists);
    }

    Ok(())
}

/// Simulated authentication function
async fn authenticate(credentials: &LoginCredentials, db: &Database) -> Result<(), AuthError> {
    if db.verify_user_login(&credentials.email, &credentials.password).await.unwrap_or(false) {
        Ok(())
    } else {
        Err(AuthError::InvalidCredentials)
    }
}

#[derive(Debug)]
enum ValidationError {
    InvalidEmail,
    WeakPassword,
    EmailExists,
}

#[derive(Debug)]
enum AuthError {
    InvalidCredentials,
    AccountLocked,
    DatabaseError,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    env_logger::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/simbld_auth".to_string());

    let database = Database::new(&database_url).await.expect("Failed to connect to the database");

    database.setup_tables().await.expect("Failed to setup database tables");

    let db_data = web::Data::new(Arc::new(database));

    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let cors_origins: Vec<String> = std::env::var("CORS_ORIGINS")
        .unwrap_or_else(|_| "*".to_string())
        .split(',')
        .map(str::to_string)
        .collect();

    let rate_limit: usize =
        std::env::var("RATE_LIMIT").unwrap_or_else(|_| "100".to_string()).parse().unwrap_or(100);

    println!("🚀 Server started on {bind_address}");
    println!("📊 Rate limit: {rate_limit} req/min");

    HttpServer::new(move || {
        App::new()
            .app_data(db_data.clone())
            .wrap(UnifiedMiddleware::simple(
                cors_origins.clone(),
                rate_limit,
                Duration::from_secs(60),
            ))
            .wrap(HttpInterceptor)
            .wrap(AuthMiddleware)
            .route("/auth/register", web::post().to(register_user))
            .route("/auth/login", web::post().to(login_user))
            .route("/health", web::get().to(|| async { ResponsesSuccessCodes::Ok.into_response() }))
    })
    .bind(bind_address)?
    .run()
    .await
}
