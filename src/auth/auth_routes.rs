use crate::auth::auth_controller::{login, register, update_password};
use crate::auth::auth_service::AuthService;
use actix_web::{web, HttpRequest, HttpResponse};
use simbld_http::helpers::response_helpers::{ok, unauthorized};

pub fn configure_auth_routes(cfg: &mut web::ServiceConfig) {
  cfg
    .route("/validate", web::get().to(validate_token))
    .route("/login", web::post().to(login))
    .route("/register", web::post().to(register))
    .route("/update_password", web::put().to(update_password));
}

async fn validate_token(req: HttpRequest) -> HttpResponse {
  let token = if let Some(auth_header) = req.headers().get("Authorization") {
    if let Ok(hdr_str) = auth_header.to_str() {
      if hdr_str.starts_with("Bearer ") {
        &hdr_str["Bearer ".len()..]
      } else {
        return respond_unauthorized();
      }
    } else {
      return respond_unauthorized();
    }
  } else {
    return respond_unauthorized();
  };

  match AuthService::validate_token(token).await {
    Ok(email) => {
      // Return ok() response with the user's email as data.
      let base_str = ok(); // returns code=200, desc="OK"
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), serde_json::json!({ "email": email }));
      }
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => respond_unauthorized(),
  }
}

/// Helper function to return unauthorized response in a standardized way.
fn respond_unauthorized() -> HttpResponse {
  let base_str = unauthorized();
  let base_json: serde_json::Value = serde_json::from_str(&base_str).unwrap();
  HttpResponse::Unauthorized().json(base_json)
}
