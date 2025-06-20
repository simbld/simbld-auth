mod config;
mod database;
mod types;

use actix_web::{web, App, HttpServer, Responder};
use simbld_http::{
    AuthMiddleware, HttpInterceptor, ResponsesClientCodes, ResponsesSuccessCodes, UnifiedMiddleware,
};
use std::time::Duration;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenvy::dotenv().ok();
    env_logger::init();

    let bind_address =
        std::env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:8080".to_string());

    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    HttpServer::new(|| {
        App::new()
            .wrap(UnifiedMiddleware::simple(vec!["*".to_string()], 100, Duration::from_secs(60)))
            .wrap(HttpInterceptor)
            .wrap(AuthMiddleware)
            .route("/auth/register", web::post().to(register_user))
            .route("/auth/login", web::post().to(login_user))
    })
    .bind(bind_address)?
    .run()
    .await
}

async fn register_user(user_data: Json<CreateUser>) -> impl Responder {
    match validate_user(&user_data).await {
        Ok(_) => ResponsesSuccessCodes::Created.into_response(),
        Err(ValidationError::EmailExists) => ResponsesClientCodes::Conflict.into_response(),
        Err(ValidationError::WeakPassword) => ResponsesClientCodes::BadRequest.into_response(),
    }
}

async fn login_user(credentials: Json<LoginCredentials>) -> impl Responder {
    match authenticate(&credentials).await {
        Ok(_) => ResponsesSuccessCodes::Ok.into_response(),
        Err(AuthError::InvalidCredentials) => ResponsesClientCodes::Unauthorized.into_response(),
        Err(AuthError::AccountLocked) => ResponsesClientCodes::Forbidden.into_response(),
    }
}
