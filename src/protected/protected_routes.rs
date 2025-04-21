use crate::auth::auth_service::AuthService;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde_json::json;
use simbld_http::responses::client::unauthorized;
use simbld_http::responses::local::missing_token;
use simbld_http::responses::success::ok;

async fn protected_route(req: HttpRequest) -> impl Responder {
  let auth_header = match req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
    Some(h) => h,
    None => {
      let (code, description) = missing_token();
      return HttpResponse::build(StatusCode::from_u16(code).unwrap()).body(description);
    },
  };

  if !auth_header.starts_with("Bearer ") {
    let (code, description) = unauthorized();
    return HttpResponse::build(StatusCode::from_u16(code).unwrap()).body(description);
  }

  let token = &auth_header["Bearer ".len()..];

  match AuthService::validate_token(token).await {
    Ok(email) => {
      let (code, description) = authentication_successful();
      let body = json!({
          "code": code,
          "desc": description,
          "data": {
              "message": "Access Granted",
              "email": email
          }
      });
      HttpResponse::build(StatusCode::from_u16(code).unwrap()).json(body)
    },
    Err((code, desc)) => HttpResponse::build(StatusCode::from_u16(code).unwrap()).body(desc),
  }
}

pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
  cfg.route("/protected", web::get().to(protected_route));
}
