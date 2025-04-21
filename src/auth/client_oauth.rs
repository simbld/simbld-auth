use actix_web::{web, HttpResponse, Responder};
use oauth2::{
  basic::BasicClient, reqwest::async_http_client, AuthorizationCode, CsrfToken, TokenResponse,
};
use serde_json::json;
use simbld_http::responses::local::user_already_exists;
use simbld_http::responses::server::internal_server_error;
use simbld_http::responses::success::ok;
use std::env;

use crate::auth::auth_jwt::generate_jwt;
use crate::user::user_service::UserService;

async fn login_with_google() -> impl Responder {
  let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
  let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET not set");
  let redirect_url = env::var("GOOGLE_REDIRECT_URL")
    .unwrap_or_else(|_| "http://localhost:8081/auth/google/callback".to_string());

  let client = BasicClient::new(
    oauth2::ClientId::new(client_id),
    Some(oauth2::ClientSecret::new(client_secret)),
    oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())
      .expect("Invalid AuthUrl"),
    Some(
      oauth2::TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid TokenUrl"),
    ),
  )
  .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url).expect("Invalid RedirectUrl"));

  let (auth_url, _csrf_token) = client.authorize_url(CsrfToken::new_random).url();

  // Redirection vers la page de login Google
  HttpResponse::Found().append_header("Location", auth_url.to_string()).finish()
}
async fn google_callback(
  query: web::Query<std::collections::HashMap<String, String>>,
  pool: web::Data<deadpool_postgres::Pool>,
) -> impl Responder {
  let client_id = env::var("GOOGLE_CLIENT_ID").expect("GOOGLE_CLIENT_ID not set");
  let client_secret = env::var("GOOGLE_CLIENT_SECRET").expect("GOOGLE_CLIENT_SECRET not set");
  let redirect_url = env::var("GOOGLE_REDIRECT_URL")
    .unwrap_or_else(|_| "http://localhost:8081/auth/google/callback".to_string());

  let client = BasicClient::new(
    oauth2::ClientId::new(client_id),
    Some(oauth2::ClientSecret::new(client_secret)),
    oauth2::AuthUrl::new("https://accounts.google.com/o/oauth2/auth".to_string())
      .expect("Invalid AuthUrl"),
    Some(
      oauth2::TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
        .expect("Invalid TokenUrl"),
    ),
  )
  .set_redirect_uri(oauth2::RedirectUrl::new(redirect_url).expect("Invalid RedirectUrl"));

  let code = match query.get("code") {
    Some(c) => c,
    None => {
      let mut base_json = serde_json::from_str::<serde_json::Value>(internal_server_error());
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "error": "Missing code parameter" }));
      }
      return HttpResponse::InternalServerError().json(base_json);
    },
  };

  let token_result = client
    .exchange_code(AuthorizationCode::new(code.to_string()))
    .request_async(async_http_client)
    .await;

  match token_result {
    Ok(token) => {
      let access_token = token.access_token().secret();
      let http_client = reqwest::Client::new();
      let userinfo_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo";
      let userinfo_resp = http_client.get(userinfo_endpoint).bearer_auth(access_token).send().await;

      if let Ok(resp) = userinfo_resp {
        if resp.status().is_success() {
          let user_data: serde_json::Value = resp.json().await.unwrap_or(json!({}));
          let email = user_data["email"].as_str().unwrap_or("");

          let db_client = match pool.get().await {
            Ok(c) => c,
            Err(_) => {
              let mut base_json =
                serde_json::from_str::<serde_json::Value>(internal_server_error());
              return HttpResponse::InternalServerError().json(base_json);
            },
          };

          let user = UserService::find_by_login_or_email(&db_client, "", email).await;
          if user.is_none() {
            match UserService::add_user(
              &db_client,
              "username_from_google",
              "login_from_google",
              email,
              None,
            )
            .await
            {
              Ok(_) => ok(),
              Err(_) => internal_server_error(),
            }
          } else {
            user_already_exists()
          }

          let jwt = generate_jwt(email);

          let mut resp_json = serde_json::from_str::<serde_json::Value>(ok());
          if let Some(obj) = resp_json.as_object_mut() {
            obj.insert(
              "data".to_string(),
              json!({"message": "Connexion Google réussie", "email": email}),
            );
          }

          // Cookie HTTP-only
          use actix_web::cookie::Cookie;
          let cookie = Cookie::build("auth_token", jwt)
            .http_only(true)
            .secure(true)
            .same_site(actix_web::cookie::SameSite::Strict)
            .finish();

          return HttpResponse::Ok().cookie(cookie).json(resp_json);
        } else {
          let mut base_json = serde_json::from_str::<serde_json::Value>(internal_server_error());
          if let Some(obj) = base_json.as_object_mut() {
            obj.insert(
              "data".to_string(),
              json!({ "error": "Failed to fetch user info from Google" }),
            );
          }
          return HttpResponse::InternalServerError().json(base_json);
        }
      } else {
        let mut base_json = serde_json::from_str::<serde_json::Value>(internal_server_error());
        if let Some(obj) = base_json.as_object_mut() {
          obj.insert(
            "data".to_string(),
            json!({ "error": "Failed to fetch user info from Google" }),
          );
        }
        return HttpResponse::InternalServerError().json(base_json);
      }
    },
    Err(e) => {
      let mut base_json = serde_json::from_str::<serde_json::Value>(internal_server_error());
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "error": format!("Token exchange failed: {}", e) }));
      }
      HttpResponse::InternalServerError().json(base_json)
    },
  }
}

pub fn configure_oauth_routes(cfg: &mut web::ServiceConfig) {
  cfg.service(
    web::scope("/auth")
      .route("/google", web::get().to(login_with_google))
      .route("/google/callback", web::get().to(google_callback)),
  );
}
