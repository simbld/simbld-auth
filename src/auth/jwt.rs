use crate::auth::auth_dto::JwtClaims;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use simbld_http::responses::local::invalid_token;
use std::env;

/// Generates a JWT for a given email address.
pub fn generate_jwt(email: &str) -> String {
  let secret = env::var("JWT_SECRET").expect("JWT_SECRET must be set");
  let expires_in = Duration::days(365);

  let claims = JwtClaims {
    sub: email.to_owned(),
    exp: (Utc::now() + expires_in).timestamp() as usize,
  };

  encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref())).unwrap()
}

/// Validates a JWT and returns the user email if valid.
pub fn validate_jwt(token: &str) -> Result<String, (u16, &'static str)> {
  let secret = env::var("JWT_SECRET").map_err(|_| invalid_token)?;
  let validation = Validation::default();
  let decoded = decode::<JwtClaims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)
    .map_err(|_| invalid_token)?;

  Ok(decoded.claims.sub)
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::env;

  #[test]
  fn test_generate_jwt_and_validate() {
    dotenvy::dotenv().ok(); // NOTE dotenv/JWT_SECRET or std::env::set_var()
    env::set_var("JWT_SECRET", "test_secret");

    let email = "test@example.com";
    let token = generate_jwt(email);
    let validated_email = validate_jwt(&token).expect("Token should be valid");
    assert_eq!(validated_email, email, "Validated email should match the original");
  }

  #[test]
  fn test_validate_jwt_invalid_token() {
    dotenvy::dotenv().ok();
    env::set_var("JWT_SECRET", "test_secret");

    let result = validate_jwt(invalid_token);
    assert!(matches!(result, Err(invalid_token)));
  }
}
