use serde::{Deserialize, Serialize};

/// Represents a login request payload.
#[derive(Deserialize, Serialize)]
pub struct LoginRequest {
  pub email: String,
  pub password: String,
}

/// Represents a successful login response with a token.
/// The token is user data, allowed as `data` in the final response.
#[derive(Serialize)]
pub struct LoginResponse {
  pub token: Option<String>,
}

/// Represents a registration request payload.
#[derive(Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
  pub login: String,
  pub username: String,
  pub email: String,
  pub password: String,
}

/// Represents a request to update a user's password.
#[derive(Deserialize)]
pub struct UpdatePasswordRequest {
  pub email: String,
  pub new_password: String,
}

/// Represents JWT Claims extracted from the token.
#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
  pub sub: String, // NOTE: Will store user email
  pub exp: usize,
}
