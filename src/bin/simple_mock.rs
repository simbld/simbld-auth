//! Simple mock server sans sqlx dependencies

use actix_web::{web, App, HttpServer};

/// Configure routes
fn configure_simple_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/health", web::get().to(health_check))
        .service(
            web::scope("/api/v1/auth")
                .route("/register", web::post().to(mock_register))
                .route("/login", web::post().to(mock_login)),
        )
        .service(
            web::scope("/api/v1/users")
                .route("/{id}/password", web::put().to(mock_change_password)),
        );
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("🚀 Simple Mock Server started on http://localhost:3001");
    println!("\n✅ Available endpoints:");
    println!("GET/health");
    println!("POST/api/v1/auth/register");
    println!("POST/api/v1/auth/login");
    println!("PUT/api/v1/users/{{id}}/password");

    HttpServer::new(|| App::new().configure(configure_simple_routes))
        .bind("127.0.0.1:3001")?
        .run()
        .await
}
