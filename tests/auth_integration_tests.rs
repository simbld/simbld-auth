use actix_web::http::StatusCode;
use actix_web::{test, web, App};
use serde_json::json;
use simbld_auth::auth::jwt::JwtService;
use simbld_auth::auth::routes::configure_auth_routes;
use simbld_auth::auth::service::AuthService;
use simbld_auth::sqlx::Database;
use std::env;

/// Creates an authentication service for testing.
/// If the database isn't available, this function will panic
/// properly (Code 101) instead of crashing the memory (Code 102).
async fn create_test_auth_service() -> web::Data<AuthService> {
    let jwt_service = JwtService::new("test_secret");

    // We are trying to connect. For an integration test,
    // a database must be active (eg: via Docker).
    let db_url = env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://simbld:2929@localhost:5434/simbld_auth".to_string());

    match Database::new(&db_url).await {
        Ok(database) => web::Data::new(AuthService::new(database, jwt_service)),
        Err(e) => panic!("\n[TEST ERROR]Unable to connect to DB : {e:?}\nMake sure Postgres is running or skip this test with #[ignore].\n"),
    }
}

#[actix_web::test]
async fn test_integration_login_endpoint() {
    if env::var("SKIP_DB_TESTS").is_ok() {
        return;
    }

    env::set_var("JWT_SECRET", "test_secret");
    let auth_service = create_test_auth_service().await;

    let app = test::init_service(App::new().configure(|cfg| {
        cfg.service(configure_auth_routes(auth_service.clone()));
    }))
    .await;

    let payload = json!({
      "email": "test@example.com",
      "password": "password123"
    });

    let req = test::TestRequest::post().uri("/auth/login").set_json(&payload).to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_client_error() || resp.status().is_success());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[actix_web::test]
    #[ignore = "Requires an active Postgres database"]
    async fn test_integration_login_flow() {
        let auth_service = create_test_auth_service().await;

        let app = test::init_service(App::new().configure(|cfg| {
            cfg.service(configure_auth_routes(auth_service.clone()));
        }))
        .await;

        let login_payload = json!({
            "email": "test_email@example.com",
            "password": "password123",
        });

        let login_req =
            test::TestRequest::post().uri("/auth/login").set_json(&login_payload).to_request();
        let login_resp = test::call_service(&app, login_req).await;

        assert_ne!(login_resp.status(), StatusCode::NOT_FOUND);
    }
}
