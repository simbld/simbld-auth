use crate::auth::service::AuthService;
use crate::utils::password_generator::generate_password;
use crate::utils::password_validator::validate_password;
use simbld_http::responses::client::{bad_request, unauthorized};
use simbld_http::responses::local::invalid_token;
use simbld_http::responses::server::internal_server_error;
use simbld_http::responses::success::ok;

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde_json::json;
use simbld_http::helpers::response_helpers::{internal_server_error, ok, unauthorized};

pub async fn generate_password_handler(req: HttpRequest) -> impl Responder {
  // Authentication
  let token = match extract_bearer_token(&req) {
    Some(t) => t,
    None => return unauthorized(),
  };

  // Token validation
  match AuthService::validate_token(token).await {
    Ok(_email) => {
      // Here, we assume that generate_password() cannot fail. If it could, we could handle the error and return internal_server_error().
      let password = generate_password();
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "password": password }));
      }
      HttpResponse::ok().json(base_json)
    },
    Err(invalid_token) => unauthorized(),
    Err(_) => unauthorized(),
  }
}

pub async fn validate_password_handler(
  req: HttpRequest,
  password: web::Json<String>,
) -> impl Responder {
  // Authentication
  let token = match extract_bearer_token(&req) {
    Some(t) => t,
    None => return unauthorized(),
  };

  // Token validation
  match AuthService::validate_token(token).await {
    Ok(_email) => {
      let pwd_str = password.into_inner();
      if pwd_str.trim().is_empty() {
        // Here we decide that if the password is empty, it is a bad request
        let base_str = unauthorized();
        let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
        return HttpResponse::bad_request().json(base_json);
      }

      let is_valid = validate_password(&pwd_str);
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "is_valid": is_valid }));
      }
      HttpResponse::ok().json(base_json)
    },
    Err(invalid_token) => unauthorized(),
    Err(_) => unauthorized(),
  }
}

// Attempts to extract the Bearer token from the Authorization header
fn extract_bearer_token(req: &HttpRequest) -> Option<&str> {
  let auth_header = req.headers().get("Authorization")?.to_str().ok()?;
  if auth_header.starts_with("Bearer ") {
    Some(&auth_header["Bearer ".len()..])
  } else {
    None
  }
}
