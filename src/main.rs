use actix_web::{web, App, HttpServer, Responder};
use dotenv::dotenv;
use env_logger;
use std::time::Duration;

// Vos imports
use simbld_http::middlewares::{AuthMiddleware, HttpInterceptor, UnifiedMiddleware};
use simbld_http::responses::{
    ResponsesClientCodes, ResponsesLocalApiCodes, ResponsesServerCodes, ResponsesSuccessCodes,
};
use simbld_http::UnifiedMiddleware;

// Structs pour l'auth
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

// Handlers avec VOS codes
async fn register_user(user_data: web::Json<CreateUser>) -> impl Responder {
    match validate_user(&user_data).await {
        Ok(_) => {
            // ✅ Utilisateur créé avec votre code précis !
            ResponsesSuccessCodes::Created.into_response()
        },
        Err(ValidationError::EmailExists) => {
            // ✅ Email existe déjà
            ResponsesClientCodes::Conflict.into_response()
        },
        Err(ValidationError::InvalidEmail) => {
            // ✅ Votre code spécialisé !
            ResponsesLocalApiCodes::InvalidEmail.into_response()
        },
        Err(ValidationError::WeakPassword) => {
            // ✅ Votre code spécialisé !
            ResponsesLocalApiCodes::InvalidPassword.into_response()
        },
    }
}

async fn login_user(credentials: web::Json<LoginCredentials>) -> impl Responder {
    match authenticate(&credentials).await {
        Ok(_) => ResponsesSuccessCodes::Ok.into_response(),
        Err(AuthError::InvalidCredentials) => {
            // ✅ Auth échouée - votre code spécialisé !
            ResponsesLocalApiCodes::AuthentificationFailed.into_response()
        },
        Err(AuthError::AccountLocked) => ResponsesClientCodes::Forbidden.into_response(),
        Err(AuthError::DatabaseError) => ResponsesServerCodes::InternalServerError.into_response(),
    }
}

/// Validate user input
async fn validate_user(user: &CreateUser) -> Result<(), ValidationError> {
    use regex::Regex;

    // Email regex
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&user.email) {
        return Err(ValidationError::InvalidEmail);
    }

    // Password strength
    if user.password.len() < 8 {
        return Err(ValidationError::WeakPassword);
    }

    // Check email exists (simulation)
    if user.email == "test@example.com" {
        return Err(ValidationError::EmailExists);
    }

    Ok(())
}

/// Simulated authentication function
async fn authenticate(credentials: &LoginCredentials) -> Result<(), AuthError> {
    if credentials.email == "user@test.com" && credentials.password == "password123" {
        Ok(())
    } else if credentials.email == "locked@test.com" {
        Err(AuthError::AccountLocked)
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
    dotenvy::dotenv().ok();
    env_logger::init();

    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let cors_origins = std::env::var("CORS_ORIGINS")
        .unwrap_or_else(|_| "*".to_string())
        .split(',')
        .map(|s| s.to_string())
        .collect();

    let rate_limit: u32 =
        std::env::var("RATE_LIMIT").unwrap_or_else(|_| "100".to_string()).parse().unwrap_or(100);

    println!("🚀 Serveur démarré sur {}", bind_address);
    println!("📊 Rate limit: {} req/min", rate_limit);

    HttpServer::new(move || {
        App::new()
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
