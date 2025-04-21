use crate::auth::auth_dto::{LoginRequest, RegisterRequest, UpdatePasswordRequest};
use crate::auth::auth_service::AuthService;
use actix_web::{web, HttpResponse, Responder};
use serde_json::json;
use simbld_http::responses::client::{bad_request, unauthorized};
use simbld_http::responses::server::internal_server_error;
use simbld_http::responses::success::{created, ok};

// Handles user login requests.
pub async fn login(
  req: web::Json<LoginRequest>,
  pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return respond_internal_error(),
  };

  match AuthService::login(&req.email, &req.password, &*client).await {
    Ok(login_resp) => {
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        if let Some(token) = login_resp.token {
          obj.insert("data".to_string(), json!({ "token": token }));
        } else {
          obj.insert("data".to_string(), json!({}));
        }
      }
      HttpResponse::Ok().json(base_json)
    },
    Err(e) => respond_auth_error(e),
  }
}

// Handles user registration requests.
pub async fn register(
  body: web::Json<RegisterRequest>,
  pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return respond_internal_error(),
  };

  match AuthService::register(body.into_inner(), &*client).await {
    Ok(resp) => {
      let base_str = created();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        if let Some(token) = resp.token {
          obj.insert("data".to_string(), json!({ "token": token }));
        } else {
          obj.insert("data".to_string(), json!({}));
        }
      }
      HttpResponse::Created().json(base_json)
    },
    Err(e) => respond_auth_error(e),
  }
}

// Handles update password requests.
pub async fn update_password(
  body: web::Json<UpdatePasswordRequest>,
  pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
  let client = match pool.get().await {
    Ok(c) => c,
    Err(_) => return respond_internal_error(),
  };

  match AuthService::update_password(body.into_inner(), &*client).await {
    Ok(_) => {
      let base_str = ok();
      let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
      HttpResponse::Ok().json(base_json)
    },
    Err(e) => respond_auth_error(e),
  }
}

// Helper function to return `unauthorized` response.
fn respond_unauthorized() -> HttpResponse {
  let base_str = unauthorized();
  let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
  HttpResponse::Unauthorized().json(base_json)
}

// Helper function to return `bad_request` response.
fn respond_bad_request() -> HttpResponse {
  let base_str = bad_request();
  let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
  HttpResponse::BadRequest().json(base_json)
}

// Helper function to return `internal_server_error` response.
fn respond_internal_error() -> HttpResponse {
  let base_str = internal_server_error();
  let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
  HttpResponse::InternalServerError().json(base_json)
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::auth::auth_dto::LoginRequest;
  use actix_web::{test, web, App};
  use dotenvy::dotenv;

  #[actix_web::test]
  async fn test_login_handler_no_db_connection() {
    dotenv().ok();

    let mut cfg = deadpool_postgres::Config::new();
    cfg.dbname = Some("your_db_name".to_string());
    cfg.user = Some("your_db_user".to_string());
    cfg.password = Some("your_db_password".to_string());
    cfg.host = Some("your_db_host".to_string());
    let pool = match cfg.create_pool(tokio_postgres::NoTls).await {
      Ok(p) => p,
      Err(e) => {
        eprintln!("Error creating pool: {}", e);
        return;
      },
    };
    let app = test::init_service(
      App::new().app_data(web::Data::new(pool)).route("/login", web::post().to(login)),
    )
    .await;

    let req_body = LoginRequest {
      email: "nosuchuser@example.com".to_string(),
      password: "password".to_string(),
    };

    let req = test::TestRequest::post().uri("/login").set_json(&req_body).to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(
      resp.status(),
      actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
      "Without a valid DB, an internal error is expected"
    );
  }
}
