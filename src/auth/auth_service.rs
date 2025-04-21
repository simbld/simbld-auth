use crate::auth::auth_dto::{LoginResponse, RegisterRequest, UpdatePasswordRequest};
use crate::auth::auth_jwt::generate_jwt;
use crate::user::user::User;
use crate::user::user_methods::UserMethods;
use argon2::{
  self,
  password_hash::{PasswordHash, SaltString},
  Argon2, PasswordHasher, PasswordVerifier,
};
use simbld_http::responses::client::{invalid_token, page_expired};
use simbld_http::responses::local::missing_token;
use simbld_http::responses::local::{hashing_error, invalid_credentials, user_not_found};
use simbld_http::responses::success::authentication_successful;
use tokio_postgres::GenericClient;

pub struct AuthService;

impl AuthService {
  pub async fn validate_token(token: &str) -> Result<String, (u16, &'static str)> {
    // Exemple fictif. À toi de l'adapter selon ta logique:
    // Si le token est vide :
    if token.is_empty() {
      return Err(missing_token());
    }
    // Si token == "expired" => token expiré
    if token == "expired" {
      return Err(page_expired());
    }
    // Si token == "invalid" => token invalide
    if token == "invalid" {
      return Err(invalid_token());
    }
    // Sinon, on considère que c'est un token valide
    authentication_successful("user@example.com".to_string())
  }

  // Attempt to login a user given an email and password.
  // Returns a `LoginResponse` with a token if successful.
  pub async fn login(
    email: &str,
    password: &str,
    client: &(impl GenericClient + Sync),
  ) -> Result<LoginResponse, (u16, &'static str)> {
    let user = User::find_by_login_or_email(client, email, email).await?.ok_or(user_not_found)?;

    if !Self::verify_password(&user.password, password) {
      return Err(invalid_credentials);
    }

    let token = generate_jwt(&user.email);
    Ok(LoginResponse {
      token: Some(token),
    })
  }

  // Register a new user.
  // Returns a `LoginResponse` with a token if successful.
  pub async fn register(
    body: RegisterRequest,
    client: &(impl GenericClient + Sync),
  ) -> Result<LoginResponse, (u16, &'static str)> {
    let email = &body.email;

    if User::find_by_login_or_email(client, email, email).await?.is_some() {
      return Err(user_already_exists);
    }

    let hashed_password = Self::hash_password(&body.password)?;

    User::add_user(client, &body.username, email, &hashed_password).await?;
    let token = generate_jwt(email);

    Ok(LoginResponse {
      token: Some(token),
    })
  }

  // Update a user's password.
  // Returns Ok if successful.
  pub async fn update_password(
    body: UpdatePasswordRequest,
    client: &(impl GenericClient + Sync),
  ) -> Result<(), (u16, &'static str)> {
    let email = &body.email;

    let user = User::find_by_login_or_email(client, email, email).await?.ok_or(user_not_found)?;

    let hashed_password = Self::hash_password(&body.new_password)?;
    User::update_password(client, &user.id, &hashed_password).await?;
    Ok(())
  }

  // Validate a JWT token and return the associated email.
  pub async fn validate_token(token: &str) -> Result<String, (u16, &'static str)> {
    crate::auth::auth_jwt::validate_jwt(token)
  }

  // Verifies if a provided password matches the stored hash.
  fn verify_password(hash: &str, password: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).ok();
    let argon2 = Argon2::default();
    parsed_hash
      .map(|hash| argon2.verify_password(password.as_bytes(), &hash).is_ok())
      .unwrap_or(false)
  }

  // Hashes a password using Argon2.
  fn hash_password(password: &str) -> Result<String, (u16, &'static str)> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let argon2 = Argon2::default();
    argon2
      .hash_password(password.as_bytes(), &salt)
      .map(|ph| ph.to_string())
      .map_err(hashing_error())
  }
}

// With DB test
#[cfg(test)]
mod tests {
  use super::*;
  use crate::auth::auth_dto::RegisterRequest;
  use dotenvy::dotenv;
  use simbld_http::responses::*;
  use tokio_postgres::{Client, NoTls};

  async fn get_test_client() -> Client {
    dotenv().ok();
    let host = std::env::var("PG_HOST").unwrap();
    let port = std::env::var("PG_PORT").unwrap();
    let user = std::env::var("PG_USER").unwrap();
    let password = std::env::var("PG_PASSWORD").unwrap();
    let dbname = std::env::var("PG_DBNAME").unwrap();

    let conn_str =
      format!("host={} port={} user={} password={} dbname={}", host, port, user, password, dbname);
    let (client, connection) = tokio_postgres::connect(&conn_str, NoTls).await.unwrap();
    tokio::spawn(async move { connection.await });
    client
  }

  #[tokio::test]
  async fn test_register_new_user() {
    let client = get_test_client().await;

    let register_request = RegisterRequest {
      login: "testlogin".to_string(),
      username: "Test Username".to_string(),
      email: "test_email@example.com".to_string(),
      password: "password123".to_string(),
    };

    let response = AuthService::register(register_request, &client).await;
    assert!(response.is_ok(), "Registration should succeed");
    let login_resp = response.unwrap();
    assert!(login_resp.token.is_some(), "Token should be returned after registration");
  }

  #[tokio::test]
  async fn test_login_user_not_found() {
    let client = get_test_client().await;

    let result = AuthService::login("unknown@example.com", "password", &client).await;
    assert!(matches!(result, Err(user_not_found)), "Should return user_not_found error");
  }
}

// With MockClient
#[cfg(test)]
mod mock_tests {
  use super::*;
  use crate::auth::auth_dto::RegisterRequest;
  use crate::mocks::mock_client::MockClient;
  use async_trait::async_trait;
  use tokio_postgres::types::ToSql;
  use tokio_postgres::{Error, Row};

  #[tokio::test]
  async fn test_register_with_mock() {
    let mock_client = MockClient;

    let register_request = RegisterRequest {
      login: "mocklogin".to_string(),
      username: "Mock Username".to_string(),
      email: "mockemail@example.com".to_string(),
      password: "password123".to_string(),
    };

    let response = AuthService::register(register_request, &mock_client).await;
    assert!(response.is_ok(), "Registration with mock should succeed");
  }
}
