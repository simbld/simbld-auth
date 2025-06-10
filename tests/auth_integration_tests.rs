use actix_web::http::StatusCode;
use actix_web::{test, App};
use serde_json::json;
use simbld_auth::auth::auth_routes::configure_auth_routes;
use std::env;

#[actix_web::test]
async fn test_integration_login_endpoint() {
    env::set_var("JWT_SECRET", "test_secret");

    let app = test::init_service(
        App::new().configure(crate::auth::auth_routes::configure_auth_routes), // TODO: Add test DB configuration, middleware, etc.
    )
        .await;

    // Simulate a login request
    let payload = json!({
      "email": "test@example.com",
      "password": "password123"
    });

    let req = test::TestRequest::post().uri("/login").set_json(&payload).to_request();

    let resp = test::call_service(&app, req).await;

    // Check the returned HTTP status code
    assert_eq!(resp.status(), StatusCode::OK);

    // Check the response body
    let resp_body = test::read_body(resp).await;
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(resp_json["code"], 200);
    assert!(resp_json["data"]["token"].is_string());
}

#[actix_web::test]
async fn test_integration_register_endpoint() {
    env::set_var("JWT_SECRET", "test_secret");

    let app = test::init_service(
        App::new().configure(crate::auth::auth_routes::configure_auth_routes), // TODO: config test DB...
    )
        .await;

    let payload = json!({
      "login": "testlogin",
      "username": "Test User",
      "email": "register_test@example.com",
      "password": "password123"
    });

    let req = test::TestRequest::post().uri("/register").set_json(&payload).to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let resp_body = test::read_body(resp).await;
    let resp_json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
    assert_eq!(resp_json["code"], 201);
    assert!(resp_json["data"]["token"].is_string());
}

#[cfg(test)]
mod tests {
    use actix_web::{test, web, App};
    use dotenvy::dotenv;
    use reqwest::StatusCode;
    use simbld_http::helpers::response_helpers::ok;

    #[actix_web::test]
    async fn test_integration_login_flow() {
        dotenv().ok();

        let app = test::init_service(
            App::new()
                .configure(crate::auth::auth_routes::configure_auth_routes)
                .app_data(web::Data::new(pool.clone()))
                .route("/", web::get().to(|| async { ok() })),
        )
            .await;

        // register request
        let register_payload = json!({
            "login": "testlogin",
            "username": "Test User",
            "email": "test_email@example.com",
            "password": "password123",
        });

        let register_req =
            test::TestRequest::post().uri("/register").set_json(&register_payload).to_request();
        let register_resp = test::call_service(&app, register_req).await;
        assert_eq!(register_resp.status(), StatusCode::CREATED);

        // login request
        let login_payload = json!({
            "email": "test_email@example.com",
            "password": "password123",
        });

        let login_req =
            test::TestRequest::post().uri("/login").set_json(&login_payload).to_request();
        let login_resp = test::call_service(&app, login_req).await;
        assert_eq!(login_resp.status(), StatusCode::OK);

        let login_resp_body = test::read_body(login_resp).await;
        let login_resp_json: serde_json::Value = serde_json::from_slice(&login_resp_body).unwrap();
        assert_eq!(login_resp_json["code"], 200);
        assert!(login_resp_json["data"]["token"].is_string());

        // validate token request
        let token = login_resp_json["data"]["token"].as_str().unwrap();
        let validate_req = test::TestRequest::get()
            .uri("/validate")
            .insert_header("Authorization", format!("Bearer {}", token))
            .to_request();
        let validate_resp = test::call_service(&app, validate_req).await;
        assert_eq!(validate_resp.status(), StatusCode::OK);

        let validate_resp_body = test::read_body(validate_resp).await;
        let validate_resp_json: serde_json::Value =
            serde_json::from_slice(&validate_resp_body).unwrap();
        assert_eq!(validate_resp_json["code"], 200);
    }
}
