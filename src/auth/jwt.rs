//! # JWT Authentication
//!
//! This module handles JWT (JSON Web Token) creation, validation, and management.
//! It provides the core functionality for secure token-based authentication in the application.

use uuid::Uuid;
use chrono::{DateTime, Duration, Utc};
use serde::{Serialize, Deserialize};
use jsonwebtoken::{encode, decode, Header, Validation, Algorithm, EncodingKey, DecodingKey, errors::Error as JwtError};
use std::sync::OnceLock;
use std::env;

/// JWT Claims structure
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
  /// Subject (user ID)
  pub sub: Uuid,

  /// Expiration time (as UTC timestamp)
  pub exp: usize,

  /// Issued at (as UTC timestamp)
  pub iat: usize,

  /// Session ID
  pub session_id: Uuid,
}

/// Global JWT secret key
pub static JWT_SECRET: JwtSecretKey = JwtSecretKey::new();

/// JWT Secret Key wrapper that loads the key from environment or uses a default
pub struct JwtSecretKey {
  key: OnceLock<String>,
}

impl JwtSecretKey {
  /// Create a new JwtSecretKey
  pub const fn new() -> Self {
    Self {
      key: OnceLock::new(),
    }
  }

  /// Get the JWT secret from environment or use a default
  fn get_or_init(&self) -> &str {
    self.key.get_or_init(|| {
      env::var("JWT_SECRET").unwrap_or_else(|_| {
        eprintln!("WARNING: Using default JWT secret. This is insecure for production.");
        "default_jwt_secret_please_change_in_production".to_string()
      })
    })
  }
}

impl AsRef<[u8]> for JwtSecretKey {
  fn as_ref(&self) -> &[u8] {
    self.get_or_init().as_bytes()
  }
}

/// Type for JWT token
pub type Token = String;

/// JWT Token Manager
pub struct JwtManager {
  /// Secret used for signing tokens
  encoding_key: EncodingKey,

  /// Key used for verifying signatures
  decoding_key: DecodingKey,

  /// Default token expiration in seconds
  token_expiration: i64,
}

impl JwtManager {
  /// Create a new JWT manager
  ///
  /// # Arguments
  ///
  /// * `token_expiration` - Default token expiration in seconds
  ///
  /// # Returns
  ///
  /// New JwtManager instance
  pub fn new(token_expiration: i64) -> Self {
    let secret = JWT_SECRET.as_ref();

    Self {
      encoding_key: EncodingKey::from_secret(secret),
      decoding_key: DecodingKey::from_secret(secret),
      token_expiration,
    }
  }

  /// Create a JWT manager with default expiration (1 hour)
  ///
  /// # Returns
  ///
  /// New JwtManager instance with default settings
  pub fn default() -> Self {
    Self::new(3600) // 1 hour default expiration
  }

  /// Generate a JWT for a user
  ///
  /// # Arguments
  ///
  /// * `user_id` - The user's ID
  /// * `session_id` - The associated session ID
  /// * `expiration` - Optional custom expiration in seconds
  ///
  /// # Returns
  ///
  /// JWT token string
  pub fn generate_token(
    &self,
    user_id: Uuid,
    session_id: Uuid,
    expiration: Option<i64>,
  ) -> Result<Token, JwtError> {
    let now = Utc::now();
    let exp_duration = Duration::seconds(expiration.unwrap_or(self.token_expiration));
    let exp = now + exp_duration;

    let claims = Claims {
      sub: user_id,
      exp: exp.timestamp() as usize,
      iat: now.timestamp() as usize,
      session_id,
    };

    encode(&Header::default(), &claims, &self.encoding_key)
  }

  /// Verify and decode a JWT
  ///
  /// # Arguments
  ///
  /// * `token` - JWT token to verify
  ///
  /// # Returns
  ///
  /// Decoded claims if token is valid
  pub fn verify_token(&self, token: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.leeway = 5; // 5 seconds of leeway for clock drift

    let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;

    Ok(token_data.claims)
  }

  /// Extract claims without full validation (useful in middleware)
  ///
  /// # Arguments
  ///
  /// * `token` - JWT token to decode
  ///
  /// # Returns
  ///
  /// Decoded claims if token structure is valid
  pub fn decode_token(&self, token: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.validate_nbf = false;

    let token_data = decode::<Claims>(token, &self.decoding_key, &validation)?;

    Ok(token_data.claims)
  }

  /// Check if a token is expired
  ///
  /// # Arguments
  ///
  /// * `token` - JWT token to check
  ///
  /// # Returns
  ///
  /// true if token is expired, false otherwise
  pub fn is_token_expired(&self, token: &str) -> bool {
    if let Ok(claims) = self.decode_token(token) {
      let exp = DateTime::<Utc>::from_timestamp(claims.exp as i64, 0)
          .unwrap_or_else(|| Utc::now());

      Utc::now() > exp
    } else {
      true // If we can't decode the token, consider it expired
    }
  }

  /// Get the time remaining until token expiration
  ///
  /// # Arguments
  ///
  /// * `token` - JWT token to check
  ///
  /// # Returns
  ///
  /// Duration until expiration or None if expired or invalid
  pub fn time_until_expiration(&self, token: &str) -> Option<Duration> {
    if let Ok(claims) = self.decode_token(token) {
      let exp = DateTime::<Utc>::from_timestamp(claims.exp as i64, 0)?;
      let now = Utc::now();

      if exp > now {
        Some(exp - now)
      } else {
        None // Token is expired
      }
    } else {
      None // Invalid token
    }
  }

  /// Extract the user ID from a token
  ///
  /// # Arguments
  ///
  /// * `token` - JWT token to process
  ///
  /// # Returns
  ///
  /// User ID if token is valid
  pub fn extract_user_id(&self, token: &str) -> Result<Uuid, JwtError> {
    let claims = self.decode_token(token)?;
    Ok(claims.sub)
  }

  /// Extract the session ID from a token
  ///
  /// # Arguments
  ///
  /// * `token` - JWT token to process
  ///
  /// # Returns
  ///
  /// Session ID if token is valid
  pub fn extract_session_id(&self, token: &str) -> Result<Uuid, JwtError> {
    let claims = self.decode_token(token)?;
    Ok(claims.session_id)
  }
}

/// Convert a JWT error to an API error
///
/// # Arguments
///
/// * `err` - The JWT error
///
/// # Returns
///
/// API error with appropriate message and status code
pub fn map_jwt_error(err: JwtError) -> crate::errors::ApiError {
  use crate::errors::ApiError;

  match err.kind() {
    jsonwebtoken::errors::ErrorKind::ExpiredSignature => ApiError::new(
      401,
      "Token has expired".to_string(),
    ),
    jsonwebtoken::errors::ErrorKind::InvalidToken => ApiError::new(
      401,
      "Invalid token format".to_string(),
    ),
    jsonwebtoken::errors::ErrorKind::InvalidSignature => ApiError::new(
      401,
      "Invalid token signature".to_string(),
    ),
    _ => ApiError::new(
      401,
      "Authentication error".to_string(),
    ),
  }
}

/// Middleware function to extract claims from a request
///
/// This helper function is used in actix-web handlers to extract
/// and validate the JWT token from the request headers.
///
/// # Arguments
///
/// * `req` - The HTTP request
/// * `jwt_manager` - The JWT manager instance
///
/// # Returns
///
/// Claims if a valid token is found
pub fn extract_claims_from_request(
  req: &actix_web::HttpRequest,
  jwt_manager: &JwtManager,
) -> Result<Claims, crate::errors::ApiError> {
  // Get the Authorization header
  let auth_header = req
      .headers()
      .get("Authorization")
      .ok_or_else(|| crate::errors::ApiError::new(
        401,
        "No authorization header found".to_string(),
      ))?
      .to_str()
      .map_err(|_| crate::errors::ApiError::new(
        401,
        "Invalid authorization header".to_string(),
      ))?;

  // Check if it's a Bearer token
  if !auth_header.starts_with("Bearer ") {
    return Err(crate::errors::ApiError::new(
      401,
      "Invalid authentication scheme".to_string(),
    ));
  }

  // Extract the token
  let token = &auth_header[7..]; // Skip "Bearer "

  // Verify the token
  jwt_manager
      .verify_token(token)
      .map_err(map_jwt_error)
}

/// Implementation of From<JwtError> for ApiError
impl From<JwtError> for crate::errors::ApiError {
  fn from(err: JwtError) -> Self {
    map_jwt_error(err)
  }
}