//! Password management controller.
//!
//! This module provides HTTP handlers for password-related operations:
//! - Password generation with secure defaults
//! - Password validation against security requirements
//! - Password reset workflow (request, verification, reset)

use crate::auth::service::AuthService;
use crate::user::models::User;
use crate::utils::password::generator::generate_password;
use crate::utils::password::reset::PasswordResetToken;
use crate::utils::password::security::PasswordService;
use crate::utils::password::validator::validate_password;
use actix_web::{web, HttpRequest, HttpResponse, Responder};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use simbld_http::responses::client::{bad_request, not_found, unauthorized};
use simbld_http::responses::server::internal_server_error;
use simbld_http::responses::success::ok;

#[derive(Serialize, Deserialize)]
pub struct PasswordResetRequest {
  email: String,
}

#[derive(Serialize, Deserialize)]
pub struct NewPasswordRequest {
  password: String,
}

/// Generate a strong random password
///
/// Requires authentication via bearer token
pub async fn generate_password_handler(req: HttpRequest) -> impl Responder {
  // Extract authentication token
  let token = match extract_bearer_token(&req) {
    Some(t) => t,
    None => return unauthorized(),
  };

  // Validate token
  match AuthService::validate_token(token).await {
    Ok(_email) => {
      // Generate a secure password
      let password = generate_password();
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "password": password }));
      }
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => unauthorized(),
  }
}

/// Validate a password against security requirements
///
/// Requires authentication via bearer token
pub async fn validate_password_handler(
  req: HttpRequest,
  password: web::Json<String>,
) -> impl Responder {
  // Extract authentication token
  let token = match extract_bearer_token(&req) {
    Some(t) => t,
    None => return unauthorized(),
  };

  // Validate token
  match AuthService::validate_token(token).await {
    Ok(_email) => {
      let pwd_str = password.into_inner();
      if pwd_str.trim().is_empty() {
        return bad_request("Password cannot be empty");
      }

      // Validate password against security requirements
      let is_valid = validate_password(&pwd_str);
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "is_valid": is_valid }));
      }
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => unauthorized(),
  }
}

/// Request a password reset token by email
pub async fn request_password_reset_handler(
  request: web::Json<PasswordResetRequest>,
  db_pool: web::Data<Pool>,
) -> impl Responder {
  // Get a connection from the pool
  let client = match db_pool.get().await {
    Ok(client) => client,
    Err(_) => return internal_server_error(),
  };

  // Find the user by email
  let user = match User::find_by_email(&client, &request.email).await {
    Ok(Some(user)) => user,
    Ok(None) => return not_found(), // Don't leak information about existing emails
    Err(_) => return internal_server_error(),
  };

  // Create a reset token
  match PasswordResetToken::create_token(&client, user.id).await {
    Ok(token) => {
      // In a real application, send an email with the token
      // For now, just return the token in the response
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "token": token }));
      }
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => internal_server_error(),
  }
}

/// Verify if a reset token is valid
pub async fn verify_reset_token_handler(
  token: web::Path<String>,
  db_pool: web::Data<Pool>,
) -> impl Responder {
  // Get a connection from the pool
  let client = match db_pool.get().await {
    Ok(client) => client,
    Err(_) => return internal_server_error(),
  };

  // Check if token exists and is valid
  match PasswordResetToken::check_token(&client, &token).await {
    Ok(Some(_)) => {
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "valid": true }));
      }
      HttpResponse::Ok().json(base_json)
    },
    Ok(None) => {
      let base_str = ok();
      let mut base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      if let Some(obj) = base_json.as_object_mut() {
        obj.insert("data".to_string(), json!({ "valid": false }));
      }
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => internal_server_error(),
  }
}

/// Reset a password using a valid token
pub async fn reset_password_handler(
  token: web::Path<String>,
  new_password: web::Json<NewPasswordRequest>,
  db_pool: web::Data<Pool>,
) -> impl Responder {
  // Get a connection from the pool
  let client = match db_pool.get().await {
    Ok(client) => client,
    Err(_) => return internal_server_error(),
  };

  // Validate password strength
  if !validate_password(&new_password.password) {
    return bad_request("Password does not meet security requirements");
  }

  // Check the token
  let token_record = match PasswordResetToken::check_token(&client, &token).await {
    Ok(Some(token)) => token,
    Ok(None) => return bad_request("Invalid or expired token"),
    Err(_) => return internal_server_error(),
  };

  // Hash the new password
  let hashed_password = match PasswordService::hash_password(&new_password.password) {
    Ok(hash) => hash,
    Err(_) => return internal_server_error(),
  };

  // Update the user's password
  match User::update_password(&client, token_record.user_id, &hashed_password).await {
    Ok(_) => {
      // Delete the used token
      let _ = PasswordResetToken::delete_by_token(&client, &token).await;

      let base_str = ok();
      let base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => internal_server_error(),
  }
}

/// Update a user's password (when logged in)
pub async fn update_password_handler(
  req: HttpRequest,
  passwords: web::Json<UpdatePasswordRequest>,
  db_pool: web::Data<Pool>,
) -> impl Responder {
  // Extract and validate token
  let token = match extract_bearer_token(&req) {
    Some(t) => t,
    None => return unauthorized(),
  };

  let email = match AuthService::validate_token(token).await {
    Ok(email) => email,
    Err(_) => return unauthorized(),
  };

  // Get database connection
  let client = match db_pool.get().await {
    Ok(client) => client,
    Err(_) => return internal_server_error(),
  };

  // Find user by email
  let user = match User::find_by_email(&client, &email).await {
    Ok(Some(user)) => user,
    Ok(None) => return not_found(),
    Err(_) => return internal_server_error(),
  };

  // Verify current password
  let is_valid = match PasswordService::verify_password(&passwords.current_password, &user.password_hash) {
    Ok(valid) => valid,
    Err(_) => return internal_server_error(),
  };

  if !is_valid {
    return bad_request("Current password is incorrect");
  }

  // Validate new password
  if !validate_password(&passwords.new_password) {
    return bad_request("New password does not meet security requirements");
  }

  // Hash and update new password
  let hashed_password = match PasswordService::hash_password(&passwords.new_password) {
    Ok(hash) => hash,
    Err(_) => return internal_server_error(),
  };

  match User::update_password(&client, user.id, &hashed_password).await {
    Ok(_) => {
      let base_str = ok();
      let base_json = serde_json::from_str::<serde_json::Value>(&base_str).unwrap();
      HttpResponse::Ok().json(base_json)
    },
    Err(_) => internal_server_error(),
  }
}

#[derive(Serialize, Deserialize)]
pub struct UpdatePasswordRequest {
  current_password: String,
  new_password: String,
}

/// Extract bearer token from authorization header
fn extract_bearer_token(req: &HttpRequest) -> Option<&str> {
  let auth_header = req.headers().get("Authorization")?.to_str().ok()?;
  if auth_header.starts_with("Bearer ") {
    Some(&auth_header["Bearer ".len()..])
  } else {
    None
  }
}