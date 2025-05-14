pub mod auth;
pub mod mocks;
pub mod postgres;
pub mod protected;
pub mod user;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use auth::auth_routes::configure_auth_routes;
use auth::oauth::configure_oauth_routes;
use dotenvy::dotenv;
use log::info;
use protected::configure_protected_routes;
use user::routes::configure_user_routes;
use auth::password::routes::configure_password_routes;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
  // Initialize environment variables and logger
  dotenv().ok();
  env_logger::init();
  info!("Starting simbld-auth backend...");

  // Configure the PostgreSQL database
  let pool = crate::postgres::config::create_pool();

  // Test the database connection
  if let Err(e) = pool.get().await {
    panic!("Failed to connect to the database: {}", e);
  } else {
    info!("Database connection test successful.");
  }

  // Start the HTTP server
  HttpServer::new(move || {
    App::new()
      .wrap(Cors::default().allow_any_origin().allow_any_method().allow_any_header())
      .app_data(web::Data::new(pool.clone()))
      .route("/", web::get().to(|| async { "CORS configuré avec succès !" }))
      .route("/test_connection", web::get().to(|| async { "Database connection test successful!" }))
      .configure(configure_auth_routes)
      .configure(configure_user_routes)
      .configure(configure_password_routes)
      .configure(configure_protected_routes)
      .configure(configure_oauth_routes)
  })
  .bind("127.0.0.1:8081")?
  .run()
  .await
}
