use oauth2::{
  basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl,
  AuthorizationCode, CsrfToken, PkceCodeChallenge, TokenResponse,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum OAuthError {
  #[error("OAuth configuration error: {0}")]
  ConfigError(String),
  #[error("OAuth request error: {0}")]
  RequestError(String),
  #[error("Failed to parse OAuth response: {0}")]
  ParseError(String),
  #[error("OAuth token error: {0}")]
  TokenError(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GoogleUserInfo {
  pub id: String,
  pub email: String,
  pub verified_email: bool,
  pub name: String,
  pub given_name: Option<String>,
  pub family_name: Option<String>,
  pub picture: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GithubUserInfo {
  pub id: i64,
  pub login: String,
  pub name: Option<String>,
  pub email: Option<String>,
  pub avatar_url: Option<String>,
}

pub enum OAuthProvider {
  Google,
  Github,
  // Ajoutez d'autres fournisseurs selon vos besoins
}

pub struct OAuthService {
  http_client: Client,
  providers: std::collections::HashMap<OAuthProvider, BasicClient>,
}

impl OAuthService {
  pub fn new() -> Self {
    let http_client = Client::new();
    let providers = std::collections::HashMap::new();
    Self { http_client, providers }
  }

  pub fn configure_google(&mut self, client_id: String, client_secret: String, redirect_url: String) -> Result<(), OAuthError> {
    let google_client = BasicClient::new(
      ClientId::new(client_id),
      Some(ClientSecret::new(client_secret)),
      AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
          .map_err(|e| OAuthError::ConfigError(e.to_string()))?,
      Some(TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
          .map_err(|e| OAuthError::ConfigError(e.to_string()))?),
    )
        .set_redirect_uri(RedirectUrl::new(redirect_url)
            .map_err(|e| OAuthError::ConfigError(e.to_string()))?);

    self.providers.insert(OAuthProvider::Google, google_client);
    Ok(())
  }

  pub fn configure_github(&mut self, client_id: String, client_secret: String, redirect_url: String) -> Result<(), OAuthError> {
    let github_client = BasicClient::new(
      ClientId::new(client_id),
      Some(ClientSecret::new(client_secret)),
      AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
          .map_err(|e| OAuthError::ConfigError(e.to_string()))?,
      Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
          .map_err(|e| OAuthError::ConfigError(e.to_string()))?),
    )
        .set_redirect_uri(RedirectUrl::new(redirect_url)
            .map_err(|e| OAuthError::ConfigError(e.to_string()))?);

    self.providers.insert(OAuthProvider::Github, github_client);
    Ok(())
  }

  pub fn get_authorization_url(&self, provider: &OAuthProvider) -> Result<(String, CsrfToken), OAuthError> {
    let client = self.providers.get(provider)
        .ok_or_else(|| OAuthError::ConfigError("Provider not configured".into()))?;

    let (pkce_challenge, _pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .add_scope(oauth2::Scope::new("email".to_string()))
        .add_scope(oauth2::Scope::new("profile".to_string()))
        .url();

    Ok((auth_url.to_string(), csrf_token))
  }

  pub async fn exchange_code_for_token(&self, provider: &OAuthProvider, code: &str) -> Result<String, OAuthError> {
    let client = self.providers.get(provider)
        .ok_or_else(|| OAuthError::ConfigError("Provider not configured".into()))?;

    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| OAuthError::TokenError(e.to_string()))?;

    Ok(token_result.access_token().secret().clone())
  }

  pub async fn get_google_user_info(&self, access_token: &str) -> Result<GoogleUserInfo, OAuthError> {
    let response = self.http_client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| OAuthError::RequestError(e.to_string()))?;

    response.json::<GoogleUserInfo>()
        .await
        .map_err(|e| OAuthError::ParseError(e.to_string()))
  }

  pub async fn get_github_user_info(&self, access_token: &str) -> Result<GithubUserInfo, OAuthError> {
    let response = self.http_client
        .get("https://api.github.com/user")
        .bearer_auth(access_token)
        .header("User-Agent", "Rust OAuth Client")
        .send()
        .await
        .map_err(|e| OAuthError::RequestError(e.to_string()))?;

    response.json::<GithubUserInfo>()
        .await
        .map_err(|e| OAuthError::ParseError(e.to_string()))
  }
}
