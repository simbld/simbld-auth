//! JWT token management
//!
//! Handles creation, validation, and parsing of JWT tokens for authentication
//! and authorisation purposes.

use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::ApiError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub user_id: Uuid,
    pub exp: i64,
    pub iat: i64,
    pub token_type: TokenType,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TokenType {
    Access,
    Refresh,
}

impl Claims {
    pub fn new(user_id: Uuid) -> Self {
        let now = Utc::now();

        Self {
            user_id,
            iat: now.timestamp(),
            exp: (now + Duration::hours(1)).timestamp(), // Default to 1 hour
            token_type: TokenType::Access,
        }
    }

    pub fn new_refresh(user_id: Uuid) -> Self {
        let now = Utc::now();

        Self {
            user_id,
            iat: now.timestamp(),
            exp: (now + Duration::days(30)).timestamp(), // 30 days for refresh
            token_type: TokenType::Refresh,
        }
    }
}

// Custom Debug implementation to hide sensitive keys
pub struct JwtService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
}

impl std::fmt::Debug for JwtService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwtService")
            .field("encoding_key", &"<hidden>")
            .field("decoding_key", &"<hidden>")
            .finish()
    }
}

impl Clone for JwtService {
    fn clone(&self) -> Self {
        // EncodingKey et DecodingKey ne sont pas Clone, on doit les recréer
        // On ne peut pas cloner les clés directement, donc on retourne une erreur pour l’instant
        panic!("JwtService can't be cloned–keys must be recreated with new()")
    }
}

impl JwtService {
    pub fn new(secret: &str) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
        }
    }

    pub fn generate_access_token(&self, claims: &Claims) -> Result<String, ApiError> {
        let mut access_claims = claims.clone();
        access_claims.token_type = TokenType::Access;
        access_claims.exp = (Utc::now() + Duration::hours(1)).timestamp();

        encode(&Header::default(), &access_claims, &self.encoding_key)
            .map_err(|e| ApiError::Auth(format!("Failed to generate an access token: {}", e)))
    }

    pub fn generate_refresh_token(&self, claims: &Claims) -> Result<String, ApiError> {
        let mut refresh_claims = claims.clone();
        refresh_claims.token_type = TokenType::Refresh;
        refresh_claims.exp = (Utc::now() + Duration::days(30)).timestamp();

        encode(&Header::default(), &refresh_claims, &self.encoding_key)
            .map_err(|e| ApiError::Auth(format!("Failed to generate refresh token: {}", e)))
    }

    pub fn validate_access_token(&self, token: &str) -> Result<Claims, ApiError> {
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => match token_data.claims.token_type {
                TokenType::Access => Ok(token_data.claims),
                TokenType::Refresh => {
                    Err(ApiError::Auth("Invalid token type for access token".to_string()))
                },
            },
            Err(e) => Err(ApiError::Auth(format!("Invalid access token: {}", e))),
        }
    }

    pub fn validate_refresh_token(&self, token: &str) -> Result<Claims, ApiError> {
        let validation = Validation::new(Algorithm::HS256);

        match decode::<Claims>(token, &self.decoding_key, &validation) {
            Ok(token_data) => match token_data.claims.token_type {
                TokenType::Refresh => Ok(token_data.claims),
                TokenType::Access => {
                    Err(ApiError::Auth("Invalid token type for refresh token".to_string()))
                },
            },
            Err(e) => Err(ApiError::Auth(format!("Invalid refresh token: {}", e))),
        }
    }

    pub fn get_claims(&self, token: &str) -> Result<Claims, ApiError> {
        let validation = Validation::new(Algorithm::HS256);

        decode::<Claims>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| ApiError::Auth(format!("Failed to get claims: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_service_creation() {
        let service = JwtService::new("test_secret");
        // Test service can be created
    }

    #[test]
    fn test_claims_creation() {
        let user_id = Uuid::new_v4();
        let claims = Claims::new(user_id);

        assert_eq!(claims.user_id, user_id);
        assert!(matches!(claims.token_type, TokenType::Access));
    }

    #[test]
    fn test_token_generation_and_validation() {
        let service = JwtService::new("test_secret");
        let user_id = Uuid::new_v4();
        let claims = Claims::new(user_id);

        let token = service.generate_access_token(&claims).unwrap();
        let validated_claims = service.validate_access_token(&token).unwrap();

        assert_eq!(validated_claims.user_id, user_id);
    }
}
