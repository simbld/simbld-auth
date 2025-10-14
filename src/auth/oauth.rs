use crate::auth::jwt::JwtService;
use crate::auth::session::SessionTokens;
use crate::db::PgPool;
use crate::models::user::User;
use crate::types::{ApiError, AppConfig};
use actix_web::{cookie::Cookie, http::header, web, HttpRequest, HttpResponse};
use chrono::Utc;
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope,
    TokenResponse, TokenUrl,
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum OAuthProvider {
    Google,
    GitHub,
    Facebook,
    Microsoft,
}

impl std::fmt::Display for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProvider::Google => write!(f, "google"),
            OAuthProvider::GitHub => write!(f, "github"),
            OAuthProvider::Facebook => write!(f, "facebook"),
            OAuthProvider::Microsoft => write!(f, "microsoft"),
        }
    }
}

impl From<&str> for OAuthProvider {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "github" => OAuthProvider::GitHub,
            "facebook" => OAuthProvider::Facebook,
            "microsoft" => OAuthProvider::Microsoft,
            _ => OAuthProvider::Google, // default to Google
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthState {
    pub csrf_token: String,
    pub redirect_uri: String,
}

type StateStore = Arc<RwLock<HashMap<String, OAuthState>>>;

#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub provider: OAuthProvider,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub profile_image: Option<String>,
}

pub struct OAuthService {
    clients: HashMap<OAuthProvider, Arc<dyn OAuthClient>>,
    state_store: StateStore,
    jwt_manager: JwtService,
    db_client: Arc<dyn DbClient>,
}

pub trait OAuthClient: Send + Sync {
    async fn authorize_url(&self, redirect_uri: &str, state: &str) -> Result<String, OAuthError>;
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<String, OAuthError>;
    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, OAuthError>;
}

pub trait DbClient: Send + Sync {
    async fn query_opt<T: FromRow>(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<T>, Error>;
    async fn execute(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error>;
}

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("OAuth client error: {0}")]
    ClientError(String),

    #[error("Invalid state")]
    InvalidState,

    #[error("Token exchange error: {0}")]
    TokenExchangeError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("User info error: {0}")]
    UserInfoError(String),
}

impl From<OAuthError> for ApiError {
    fn from(err: OAuthError) -> Self {
        match err {
            OAuthError::InvalidState => ApiError::BadRequest("Invalid OAuth state".to_string()),
            _ => ApiError::InternalServerError(err.to_string()),
        }
    }
}

impl OAuthService {
    pub fn new(config: &AppConfig, jwt_manager: JwtService) -> Self {
        let mut clients: HashMap<OAuthProvider, Arc<dyn OAuthClient>> = HashMap::new();

        // Configure Google OAuth client
        if let (Some(client_id), Some(client_secret)) =
            (&config.google_client_id, &config.google_client_secret)
        {
            let client = GoogleOAuthClient::new(
                client_id.clone(),
                client_secret.clone(),
                format!("{}/auth/oauth/google/callback", config.base_url),
            );
            clients.insert(OAuthProvider::Google, Arc::new(client));
        }

        // Configure GitHub OAuth client
        if let (Some(client_id), Some(client_secret)) =
            (&config.github_client_id, &config.github_client_secret)
        {
            let client = GitHubOAuthClient::new(
                client_id.clone(),
                client_secret.clone(),
                format!("{}/auth/oauth/github/callback", config.base_url),
            );
            clients.insert(OAuthProvider::GitHub, Arc::new(client));
        }

        // Configure Facebook OAuth client
        if let (Some(client_id), Some(client_secret)) =
            (&config.facebook_client_id, &config.facebook_client_secret)
        {
            let client = FacebookOAuthClient::new(
                client_id.clone(),
                client_secret.clone(),
                format!("{}/auth/oauth/facebook/callback", config.base_url),
            );
            clients.insert(OAuthProvider::Facebook, Arc::new(client));
        }

        // Configure Microsoft OAuth client
        if let (Some(client_id), Some(client_secret)) =
            (&config.microsoft_client_id, &config.microsoft_client_secret)
        {
            let client = MicrosoftOAuthClient::new(
                client_id.clone(),
                client_secret.clone(),
                format!("{}/auth/oauth/microsoft/callback", config.base_url),
            );
            clients.insert(OAuthProvider::Microsoft, Arc::new(client));
        }

        OAuthService {
            clients,
            state_store: Arc::new(RwLock::new(HashMap::new())),
            jwt_manager,
            db_client: Arc::new(PgPool::get_client_wrapper()),
        }
    }

    pub async fn authorize(
        &self,
        provider: OAuthProvider,
        redirect_uri: &str,
    ) -> Result<String, ApiError> {
        let client = match self.clients.get(&provider) {
            Some(client) => client,
            None => {
                return Err(ApiError::BadRequest(format!(
                    "OAuth provider {} not configured",
                    provider
                )))
            },
        };

        // Generate a random state ID and CSRF token
        let state_id = Uuid::new_v4().to_string();
        let csrf_token: String =
            thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();

        // Store state in state store
        let state = OAuthState {
            csrf_token: csrf_token.clone(),
            redirect_uri: redirect_uri.to_string(),
        };

        self.state_store.write().unwrap().insert(state_id.clone(), state);

        // Get authorization URL from the client
        let auth_url = client.authorize_url(redirect_uri, &state_id).await?;

        Ok(auth_url)
    }

    pub async fn callback(
        &self,
        provider: OAuthProvider,
        code: &str,
        state: &str,
        req: &HttpRequest,
    ) -> Result<HttpResponse, ApiError> {
        // Retrieve and validate state
        let state_data = {
            let state_store = self.state_store.read().unwrap();
            match state_store.get(state) {
                Some(state_data) => state_data.clone(),
                None => return Err(OAuthError::InvalidState.into()),
            }
        };

        // Remove the state from the store after use
        self.state_store.write().unwrap().remove(state);

        // Get the client for the provider
        let client = match self.clients.get(&provider) {
            Some(client) => client,
            None => {
                return Err(ApiError::BadRequest(format!(
                    "OAuth provider {} not configured",
                    provider
                )))
            },
        };

        // Exchange authorization code for access token
        let access_token = client.exchange_code(code, &state_data.redirect_uri).await?;

        // Get user info from provider
        let user_info = client.get_user_info(&access_token).await?;

        // Find or create user
        let user_id = self.find_or_create_user(&user_info).await?;

        // Create a new session
        let session = SessionTokens::new(&user_id);
        self.save_session(&session).await?;

        // Generate JWT
        let token = self.jwt_manager.create_token(&user_id)?;

        // Set cookie with JWT
        let cookie = Cookie::build("token", token.clone())
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(actix_web::cookie::SameSite::Lax)
            .finish();

        // Redirect to the original redirect URI with the token
        let redirect_url = if state_data.redirect_uri.contains('?') {
            format!("{}&token={}", state_data.redirect_uri, token)
        } else {
            format!("{}?token={}", state_data.redirect_uri, token)
        };

        Ok(HttpResponse::TemporaryRedirect()
            .cookie(cookie)
            .append_header((header::LOCATION, redirect_url))
            .finish())
    }

    async fn exchange_token(
        &self,
        provider: OAuthProvider,
        code: &str,
        redirect_uri: &str,
    ) -> Result<String, OAuthError> {
        let client = match self.clients.get(&provider) {
            Some(client) => client,
            None => {
                return Err(OAuthError::ClientError(format!(
                    "OAuth provider {:?} not configured",
                    provider
                )))
            },
        };

        client.exchange_code(code, redirect_uri).await
    }

    async fn find_or_create_user(&self, user_info: &OAuthUserInfo) -> Result<String, ApiError> {
        // Try to find existing user with this provider and provider_user_id
        let query = "
            SELECT id FROM users 
            WHERE provider = $1 AND provider_user_id = $2
        ";

        let existing_user: Option<User> = self
            .db_client
            .query_opt(query, &[&user_info.provider.to_string(), &user_info.provider_user_id])
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

        if let Some(user) = existing_user {
            return Ok(user.id);
        }

        // Generate a unique username
        let base_username = match &user_info.display_name {
            Some(name) => {
                // Convert to lowercase and remove special characters
                let name = name.to_lowercase();
                let name = name
                    .chars()
                    .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
                    .collect::<String>();

                if name.is_empty() {
                    "user".to_string()
                } else {
                    name
                }
            },
            None => "user".to_string(),
        };

        let username = self.get_unique_username(&base_username).await?;

        // Create new user
        let user_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let query = "
            INSERT INTO users (
                id, username, email, provider, provider_user_id, display_name, 
                profile_image, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8, $9
            )
        ";

        self.db_client
            .execute(
                query,
                &[
                    &user_id,
                    &username,
                    &user_info.email.as_deref().unwrap_or(""),
                    &user_info.provider.to_string(),
                    &user_info.provider_user_id,
                    &user_info.display_name.as_deref().unwrap_or(""),
                    &user_info.profile_image.as_deref().unwrap_or(""),
                    &now,
                    &now,
                ],
            )
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(user_id)
    }

    async fn get_unique_username(&self, base_username: &str) -> Result<String, ApiError> {
        let client = PgPool::get_client().await?;
        let mut attempt = 0;
        let mut username = base_username.to_string();

        loop {
            let exists: bool = client
                .query_one("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)", &[&username])
                .await
                .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?
                .get(0);

            if !exists {
                break;
            }

            attempt += 1;
            username = format!("{}_{}", base_username, attempt);

            if attempt > 100 {
                return Err(ApiError::InternalServerError(
                    "Failed to generate unique username".to_string(),
                ));
            }
        }

        Ok(username)
    }

    async fn save_session(&self, session: &SessionTokens) -> Result<(), ApiError> {
        let query = "
            INSERT INTO sessions (id, user_id, created_at, expires_at)
            VALUES ($1, $2, $3, $4)
        ";

        self.db_client
            .execute(
                query,
                &[&session.id, &session.user_id, &session.created_at, &session.expires_at],
            )
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Database error: {}", e)))?;

        Ok(())
    }
}

// Implementation of the OAuth clients for different providers

struct GoogleOAuthClient {
    client: BasicClient,
    api_client: Client,
}

impl GoogleOAuthClient {
    fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string()).unwrap(),
            Some(TokenUrl::new("https://www.googleapis.com/oauth2/v4/token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap());

        GoogleOAuthClient {
            client,
            api_client: Client::new(),
        }
    }
}

impl OAuthClient for GoogleOAuthClient {
    async fn authorize_url(&self, _redirect_uri: &str, state: &str) -> Result<String, OAuthError> {
        let (auth_url, _) = self
            .client
            .authorize_url(CsrfToken::new(state.to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> Result<String, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::TokenExchangeError(e.to_string()))?;

        Ok(token_result.access_token().secret().clone())
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, OAuthError> {
        let user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo";

        let resp = self
            .api_client
            .get(user_info_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OAuthError::UserInfoError(format!(
                "Failed to get user info, status: {}",
                resp.status()
            )));
        }

        let data: serde_json::Value =
            resp.json().await.map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        let provider_user_id = data["sub"]
            .as_str()
            .ok_or_else(|| OAuthError::UserInfoError("Missing 'sub' field".to_string()))?
            .to_string();

        let email = data["email"].as_str().map(|s| s.to_string());
        let display_name = data["name"].as_str().map(|s| s.to_string());
        let profile_image = data["picture"].as_str().map(|s| s.to_string());

        Ok(OAuthUserInfo {
            provider_user_id,
            provider: OAuthProvider::Google,
            email,
            display_name,
            profile_image,
        })
    }
}

struct GitHubOAuthClient {
    client: BasicClient,
    api_client: Client,
}

impl GitHubOAuthClient {
    fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).unwrap(),
            Some(TokenUrl::new("https://github.com/login/oauth/access_token".to_string()).unwrap()),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap());

        GitHubOAuthClient {
            client,
            api_client: Client::new(),
        }
    }
}

impl OAuthClient for GitHubOAuthClient {
    async fn authorize_url(&self, _redirect_uri: &str, state: &str) -> Result<String, OAuthError> {
        let (auth_url, _) = self
            .client
            .authorize_url(CsrfToken::new(state.to_string()))
            .add_scope(Scope::new("user:email".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> Result<String, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::TokenExchangeError(e.to_string()))?;

        Ok(token_result.access_token().secret().clone())
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, OAuthError> {
        // Get user profile
        let user_info_url = "https://api.github.com/user";

        let resp = self
            .api_client
            .get(user_info_url)
            .header("Authorization", format!("token {}", access_token))
            .header("User-Agent", "Rust OAuth Client")
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OAuthError::UserInfoError(format!(
                "Failed to get user info, status: {}",
                resp.status()
            )));
        }

        let user_data: serde_json::Value =
            resp.json().await.map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        // Get user emails (to get primary email)
        let email_url = "https://api.github.com/user/emails";

        let resp = self
            .api_client
            .get(email_url)
            .header("Authorization", format!("token {}", access_token))
            .header("User-Agent", "Rust OAuth Client")
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        let email = if resp.status().is_success() {
            let emails: Vec<serde_json::Value> =
                resp.json().await.map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

            // Find primary email
            emails
                .iter()
                .find(|e| e["primary"].as_bool().unwrap_or(false))
                .and_then(|e| e["email"].as_str())
                .or_else(|| emails.first().and_then(|e| e["email"].as_str()))
                .map(|s| s.to_string())
        } else {
            None
        };

        let provider_user_id = user_data["id"]
            .as_u64()
            .ok_or_else(|| OAuthError::UserInfoError("Missing 'id' field".to_string()))?
            .to_string();

        let display_name = user_data["name"].as_str().map(|s| s.to_string());
        let profile_image = user_data["avatar_url"].as_str().map(|s| s.to_string());

        Ok(OAuthUserInfo {
            provider_user_id,
            provider: OAuthProvider::GitHub,
            email,
            display_name,
            profile_image,
        })
    }
}

struct FacebookOAuthClient {
    client: BasicClient,
    api_client: Client,
}

impl FacebookOAuthClient {
    fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new("https://www.facebook.com/v10.0/dialog/oauth".to_string()).unwrap(),
            Some(
                TokenUrl::new("https://graph.facebook.com/v10.0/oauth/access_token".to_string())
                    .unwrap(),
            ),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap());

        FacebookOAuthClient {
            client,
            api_client: Client::new(),
        }
    }
}

impl OAuthClient for FacebookOAuthClient {
    async fn authorize_url(&self, _redirect_uri: &str, state: &str) -> Result<String, OAuthError> {
        let (auth_url, _) = self
            .client
            .authorize_url(CsrfToken::new(state.to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("public_profile".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> Result<String, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::TokenExchangeError(e.to_string()))?;

        Ok(token_result.access_token().secret().clone())
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, OAuthError> {
        let user_info_url = "https://graph.facebook.com/v10.0/me";
        let fields = "id,name,email,picture.type(large)";

        let resp = self
            .api_client
            .get(user_info_url)
            .query(&[("fields", fields), ("access_token", access_token)])
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OAuthError::UserInfoError(format!(
                "Failed to get user info, status: {}",
                resp.status()
            )));
        }

        let data: serde_json::Value =
            resp.json().await.map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        let provider_user_id = data["id"]
            .as_str()
            .ok_or_else(|| OAuthError::UserInfoError("Missing 'id' field".to_string()))?
            .to_string();

        let email = data["email"].as_str().map(|s| s.to_string());
        let display_name = data["name"].as_str().map(|s| s.to_string());
        let profile_image = data["picture"]["data"]["url"].as_str().map(|s| s.to_string());

        Ok(OAuthUserInfo {
            provider_user_id,
            provider: OAuthProvider::Facebook,
            email,
            display_name,
            profile_image,
        })
    }
}

struct MicrosoftOAuthClient {
    client: BasicClient,
    api_client: Client,
}

impl MicrosoftOAuthClient {
    fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        let client = BasicClient::new(
            ClientId::new(client_id),
            Some(ClientSecret::new(client_secret)),
            AuthUrl::new(
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
            )
            .unwrap(),
            Some(
                TokenUrl::new(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                )
                .unwrap(),
            ),
        )
        .set_redirect_uri(RedirectUrl::new(redirect_url).unwrap());

        MicrosoftOAuthClient {
            client,
            api_client: Client::new(),
        }
    }
}

impl OAuthClient for MicrosoftOAuthClient {
    async fn authorize_url(&self, _redirect_uri: &str, state: &str) -> Result<String, OAuthError> {
        let (auth_url, _) = self
            .client
            .authorize_url(CsrfToken::new(state.to_string()))
            .add_scope(Scope::new("User.Read".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .add_scope(Scope::new("openid".to_string()))
            .url();

        Ok(auth_url.to_string())
    }

    async fn exchange_code(&self, code: &str, _redirect_uri: &str) -> Result<String, OAuthError> {
        let token_result = self
            .client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| OAuthError::TokenExchangeError(e.to_string()))?;

        Ok(token_result.access_token().secret().clone())
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo, OAuthError> {
        let user_info_url = "https://graph.microsoft.com/v1.0/me";

        let resp = self
            .api_client
            .get(user_info_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(OAuthError::UserInfoError(format!(
                "Failed to get user info, status: {}",
                resp.status()
            )));
        }

        let data: serde_json::Value =
            resp.json().await.map_err(|e| OAuthError::UserInfoError(e.to_string()))?;

        let provider_user_id = data["id"]
            .as_str()
            .ok_or_else(|| OAuthError::UserInfoError("Missing 'id' field".to_string()))?
            .to_string();

        let email = data["mail"]
            .as_str()
            .or_else(|| data["userPrincipalName"].as_str())
            .map(|s| s.to_string());

        let display_name = data["displayName"].as_str().map(|s| s.to_string());

        // Get profile photo separately
        let profile_image_url = "https://graph.microsoft.com/v1.0/me/photo/$value";
        let profile_image = match self
            .api_client
            .get(profile_image_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
        {
            Ok(resp) if resp.status().is_success() => {
                // We would need to convert binary data to a URL or store it
                // This is simplified for the example
                Some(format!(
                    "https://graph.microsoft.com/v1.0/me/photo/$value?token={}",
                    access_token
                ))
            },
            _ => None,
        };

        Ok(OAuthUserInfo {
            provider_user_id,
            provider: OAuthProvider::Microsoft,
            email,
            display_name,
            profile_image,
        })
    }
}

// Implementation of PgPool wrapper for DbClient trait
impl PgPool {
    fn get_client_wrapper() -> impl DbClient {
        PgClientWrapper {}
    }
}

struct PgClientWrapper {}

impl DbClient for PgClientWrapper {
    async fn query_opt<T: FromRow>(
        &self,
        query: &str,
        params: &[&(dyn ToSql + Sync)],
    ) -> Result<Option<T>, Error> {
        let client = PgPool::get_client().await.map_err(|e| Error::Other(e.to_string()))?;
        client.query_opt(query, params).await.map_err(|e| Error::Other(e.to_string()))
    }

    async fn execute(&self, query: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64, Error> {
        let client = PgPool::get_client().await.map_err(|e| Error::Other(e.to_string()))?;
        client.execute(query, params).await.map_err(|e| Error::Other(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Other error: {0}")]
    Other(String),
}

pub trait FromRow: Sized {
    fn from_row(row: tokio_postgres::Row) -> Result<Self, Error>;
}

pub trait ToSql {
    fn to_sql(&self) -> Result<tokio_postgres::types::ToSql, Error>;
}

impl FromRow for User {
    fn from_row(row: tokio_postgres::Row) -> Result<Self, Error> {
        Ok(User {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            password_hash: row.try_get("password_hash").unwrap_or_default(),
            provider: row.try_get("provider").unwrap_or_default(),
            provider_user_id: row.try_get("provider_user_id").unwrap_or_default(),
            display_name: row.try_get("display_name").unwrap_or_default(),
            profile_image: row.try_get("profile_image").unwrap_or_default(),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        })
    }
}

// Routes module for OAuth flows
pub mod routes {
    use super::*;
    use actix_web::{web, HttpRequest, HttpResponse, Responder};
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct AuthorizeQuery {
        redirect_uri: String,
    }

    #[derive(Deserialize)]
    pub struct CallbackQuery {
        code: String,
        state: String,
    }

    pub fn config(cfg: &mut web::ServiceConfig) {
        cfg.service(
            web::scope("/auth/oauth")
                .route("/google", web::get().to(authorize_google))
                .route("/github", web::get().to(authorize_github))
                .route("/facebook", web::get().to(authorize_facebook))
                .route("/microsoft", web::get().to(authorize_microsoft))
                .route("/google/callback", web::get().to(google_callback))
                .route("/github/callback", web::get().to(github_callback))
                .route("/facebook/callback", web::get().to(facebook_callback))
                .route("/microsoft/callback", web::get().to(microsoft_callback)),
        );
    }

    async fn authorize_google(
        query: web::Query<AuthorizeQuery>,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        match oauth_service.authorize(OAuthProvider::Google, &query.redirect_uri).await {
            Ok(url) => HttpResponse::Found().header(header::LOCATION, url).finish(),
            Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
        }
    }

    async fn authorize_github(
        query: web::Query<AuthorizeQuery>,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        match oauth_service.authorize(OAuthProvider::GitHub, &query.redirect_uri).await {
            Ok(url) => HttpResponse::Found().header(header::LOCATION, url).finish(),
            Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
        }
    }

    async fn authorize_facebook(
        query: web::Query<AuthorizeQuery>,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        match oauth_service.authorize(OAuthProvider::Facebook, &query.redirect_uri).await {
            Ok(url) => HttpResponse::Found().header(header::LOCATION, url).finish(),
            Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
        }
    }

    async fn authorize_microsoft(
        query: web::Query<AuthorizeQuery>,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        match oauth_service.authorize(OAuthProvider::Microsoft, &query.redirect_uri).await {
            Ok(url) => HttpResponse::Found().header(header::LOCATION, url).finish(),
            Err(e) => HttpResponse::InternalServerError().json(e.to_string()),
        }
    }

    async fn google_callback(
        query: web::Query<CallbackQuery>,
        req: HttpRequest,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        oauth_service.callback(OAuthProvider::Google, &query.code, &query.state, &req).await
    }

    async fn github_callback(
        query: web::Query<CallbackQuery>,
        req: HttpRequest,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        oauth_service.callback(OAuthProvider::GitHub, &query.code, &query.state, &req).await
    }

    async fn facebook_callback(
        query: web::Query<CallbackQuery>,
        req: HttpRequest,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        oauth_service.callback(OAuthProvider::Facebook, &query.code, &query.state, &req).await
    }

    async fn microsoft_callback(
        query: web::Query<CallbackQuery>,
        req: HttpRequest,
        oauth_service: web::Data<OAuthService>,
    ) -> impl Responder {
        oauth_service.callback(OAuthProvider::Microsoft, &query.code, &query.state, &req).await
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::auth::jwt::JwtService;
        use crate::config::AppConfig;
        use crate::mocks::mock_client::{
            create_mock_row_with_exists, create_mock_user_row, MockClient,
        };
        use crate::mocks::mock_oauth::MockOAuthService;
        use actix_web::{http, test, web, App, HttpRequest, HttpResponse};
        use std::collections::HashMap;
        use std::sync::{Arc, RwLock};
        use tokio_postgres::row::Row;
        use uuid::Uuid;

        // Test for OAuthProvider display formatting
        #[test]
        fn test_oauth_provider_display() {
            assert_eq!(OAuthProvider::Google.to_string(), "google");
            assert_eq!(OAuthProvider::GitHub.to_string(), "github");
            assert_eq!(OAuthProvider::Facebook.to_string(), "facebook");
            assert_eq!(OAuthProvider::Microsoft.to_string(), "microsoft");
        }

        // Test for OAuthProvider from string conversion
        #[test]
        fn test_oauth_provider_from_str() {
            assert_eq!(OAuthProvider::from("google"), OAuthProvider::Google);
            assert_eq!(OAuthProvider::from("GOOGLE"), OAuthProvider::Google);
            assert_eq!(OAuthProvider::from("github"), OAuthProvider::GitHub);
            assert_eq!(OAuthProvider::from("facebook"), OAuthProvider::Facebook);
            assert_eq!(OAuthProvider::from("microsoft"), OAuthProvider::Microsoft);
            assert_eq!(OAuthProvider::from("unknown"), OAuthProvider::Google); // Default is Google
        }

        // Test for OAuthState serialization and deserialization
        #[test]
        fn test_oauth_state_serialization() {
            let state = OAuthState {
                csrf_token: "abc123".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
            };

            let serialized = serde_json::to_string(&state).unwrap();
            let deserialized: OAuthState = serde_json::from_str(&serialized).unwrap();

            assert_eq!(state.csrf_token, deserialized.csrf_token);
            assert_eq!(state.redirect_uri, deserialized.redirect_uri);
        }

        // Test for OAuthUserInfo serialization and deserialization
        #[test]
        fn test_oauth_user_info_serialization() {
            let user_info = OAuthUserInfo {
                provider_user_id: "12345".to_string(),
                provider: OAuthProvider::Google,
                email: Some("user@example.com".to_string()),
                display_name: Some("Test User".to_string()),
                profile_image: Some("https://example.com/image.jpg".to_string()),
            };

            let serialized = serde_json::to_string(&user_info).unwrap();
            let deserialized: OAuthUserInfo = serde_json::from_str(&serialized).unwrap();

            assert_eq!(user_info.provider_user_id, deserialized.provider_user_id);
            assert_eq!(user_info.provider, deserialized.provider);
            assert_eq!(user_info.email, deserialized.email);
            assert_eq!(user_info.display_name, deserialized.display_name);
            assert_eq!(user_info.profile_image, deserialized.profile_image);
        }

        // Test for OAuth login endpoint
        #[actix_web::test]
        async fn test_oauth_login_endpoint() {
            let app_config = AppConfig {
                base_url: "http://localhost:8080".to_string(),
                google_client_id: Some("google_client_id".to_string()),
                google_client_secret: Some("google_client_secret".to_string()),
                ..Default::default()
            };

            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let oauth_service = web::Data::new(OAuthService::new(&app_config, jwt_manager));

            let app = test::init_service(App::new().app_data(oauth_service.clone()).route(
                "/auth/oauth/{provider}/login",
                web::get().to(
                    |provider: web::Path<String>,
                     query: web::Query<HashMap<String, String>>,
                     service: web::Data<OAuthService>| async move {
                        let redirect_uri = query.get("redirect_uri").cloned().unwrap_or_default();
                        let provider = OAuthProvider::from(provider.as_str());
                        match service.authorize(provider, &redirect_uri).await {
                            Ok(url) => HttpResponse::TemporaryRedirect()
                                .append_header(("Location", url))
                                .finish(),
                            Err(e) => HttpResponse::BadRequest().body(e.to_string()),
                        }
                    },
                ),
            ))
            .await;

            let req = test::TestRequest::get()
                .uri("/auth/oauth/google/login?redirect_uri=https://example.com/callback")
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), http::StatusCode::TEMPORARY_REDIRECT);
        }

        // Test for OAuth callback endpoint
        #[actix_web::test]
        async fn test_oauth_callback_endpoint() {
            let app_config = AppConfig {
                base_url: "http://localhost:8080".to_string(),
                google_client_id: Some("google_client_id".to_string()),
                google_client_secret: Some("google_client_secret".to_string()),
                ..Default::default()
            };

            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let mut oauth_service = OAuthService::new(&app_config, jwt_manager);

            // Replace the OAuth client with a mock
            let mock_oauth_client = Arc::new(MockOAuthClient {
                exchange_code_response: Some(Ok("test_access_token".to_string())),
                get_user_info_response: Some(Ok(OAuthUserInfo {
                    provider_user_id: "12345".to_string(),
                    provider: OAuthProvider::Google,
                    email: Some("user@example.com".to_string()),
                    display_name: Some("Test User".to_string()),
                    profile_image: Some("https://example.com/image.jpg".to_string()),
                })),
            });

            oauth_service.clients.insert(OAuthProvider::Google, mock_oauth_client);

            // Mock the database client
            let mock_db_client = MockClient::new()
                .with_query_opt_result(None) // User doesn't exist
                .with_execute_result(1); // User created successfully

            oauth_service.db_client = Arc::new(mock_db_client);

            let oauth_service = web::Data::new(oauth_service);

            // Insert a test state into the state store
            let state_id = Uuid::new_v4().to_string();
            let test_state = OAuthState {
                csrf_token: "test_csrf".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
            };

            oauth_service.state_store.write().unwrap().insert(state_id.clone(), test_state);

            let app = test::init_service(App::new().app_data(oauth_service.clone()).route(
                "/auth/oauth/{provider}/callback",
                web::get().to(
                    |provider: web::Path<String>,
                     query: web::Query<HashMap<String, String>>,
                     req: HttpRequest,
                     service: web::Data<OAuthService>| async move {
                        let provider = OAuthProvider::from(provider.as_str());
                        let code = query.get("code").cloned().unwrap_or_default();
                        let state = query.get("state").cloned().unwrap_or_default();

                        match service.callback(provider, &code, &state, &req).await {
                            Ok(resp) => resp,
                            Err(e) => HttpResponse::BadRequest().body(e.to_string()),
                        }
                    },
                ),
            ))
            .await;

            let req = test::TestRequest::get()
                .uri(&format!("/auth/oauth/google/callback?code=test_code&state={}", state_id))
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), http::StatusCode::TEMPORARY_REDIRECT);
        }

        // Test for OAuthService creation
        #[test]
        fn test_oauth_service_new() {
            let app_config = AppConfig {
                base_url: "http://localhost:8080".to_string(),
                google_client_id: Some("google_client_id".to_string()),
                google_client_secret: Some("google_client_secret".to_string()),
                github_client_id: Some("github_client_id".to_string()),
                github_client_secret: Some("github_client_secret".to_string()),
                facebook_client_id: Some("facebook_client_id".to_string()),
                facebook_client_secret: Some("facebook_client_secret".to_string()),
                microsoft_client_id: Some("microsoft_client_id".to_string()),
                microsoft_client_secret: Some("microsoft_client_secret".to_string()),
                ..Default::default()
            };

            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let oauth_service = OAuthService::new(&app_config, jwt_manager);

            assert!(oauth_service.clients.contains_key(&OAuthProvider::Google));
            assert!(oauth_service.clients.contains_key(&OAuthProvider::GitHub));
            assert!(oauth_service.clients.contains_key(&OAuthProvider::Facebook));
            assert!(oauth_service.clients.contains_key(&OAuthProvider::Microsoft));
        }

        // Test getting user info for providers
        #[tokio::test]
        async fn test_get_user_info_for_providers() {
            let mock_oauth_service = MockOAuthService::new();

            // Create a mock OAuth user info response
            let mock_user_info = OAuthUserInfo {
                provider_user_id: "12345".to_string(),
                provider: OAuthProvider::Google,
                email: Some("user@example.com".to_string()),
                display_name: Some("Test User".to_string()),
                profile_image: Some("https://example.com/image.jpg".to_string()),
            };

            // Add the mock response to the service
            let access_token = "test_token";
            mock_oauth_service
                .add_user_info_response(access_token.to_string(), mock_user_info.clone());

            // Get user info using the mock service
            let result =
                mock_oauth_service.get_user_info(OAuthProvider::Google, access_token).await;

            assert!(result.is_ok());
            let user_info = result.unwrap();
            assert_eq!(user_info.provider_user_id, mock_user_info.provider_user_id);
            assert_eq!(user_info.provider, mock_user_info.provider);
            assert_eq!(user_info.email, mock_user_info.email);
            assert_eq!(user_info.display_name, mock_user_info.display_name);
            assert_eq!(user_info.profile_image, mock_user_info.profile_image);
        }

        // Test finding an existing user
        #[tokio::test]
        async fn test_find_or_create_user_existing() {
            // Create a mock database client
            let user_id = Uuid::new_v4().to_string();
            let provider = OAuthProvider::Google;
            let provider_user_id = "12345".to_string();

            // Create a mock row that would be returned by the database
            let mock_row = create_mock_user_row(&user_id, provider.to_string(), &provider_user_id);

            let mock_client = MockClient::with_query_opt_result(Some(mock_row));

            // Create the OAuthService with the mock client
            let app_config = AppConfig::default();
            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let mut oauth_service = OAuthService::new(&app_config, jwt_manager);
            oauth_service.db_client = Arc::new(mock_client);

            // Create test user info
            let user_info = OAuthUserInfo {
                provider_user_id: provider_user_id.clone(),
                provider,
                email: Some("user@example.com".to_string()),
                display_name: Some("Test User".to_string()),
                profile_image: Some("https://example.com/image.jpg".to_string()),
            };

            // Find or create user
            let result = oauth_service.find_or_create_user(&user_info).await;

            assert!(result.is_ok());
            let found_user_id = result.unwrap();
            assert_eq!(found_user_id, user_id);
        }

        // Test creating a new user
        #[tokio::test]
        async fn test_find_or_create_user_new() {
            // Create a mock database client that indicates no existing user
            let provider = OAuthProvider::Google;
            let provider_user_id = "12345".to_string();

            // First query returns None (user doesn't exist)
            // Second execute returns 1 (user created successfully)
            let mock_client = MockClient::new().with_query_opt_result(None).with_execute_result(1);

            // Create the OAuthService with the mock client
            let app_config = AppConfig::default();
            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let mut oauth_service = OAuthService::new(&app_config, jwt_manager);
            oauth_service.db_client = Arc::new(mock_client);

            // Create test user info
            let user_info = OAuthUserInfo {
                provider_user_id: provider_user_id.clone(),
                provider,
                email: Some("user@example.com".to_string()),
                display_name: Some("Test User".to_string()),
                profile_image: Some("https://example.com/image.jpg".to_string()),
            };

            // Find or create user
            let result = oauth_service.find_or_create_user(&user_info).await;

            assert!(result.is_ok());
            // The user ID will be a new UUID generated during the test
            let new_user_id = result.unwrap();
            assert!(!new_user_id.is_empty());
        }

        // Test saving a session
        #[tokio::test]
        async fn test_save_session() {
            // Create a mock session
            let user_id = "test_user_id";
            let session = SessionTokens::new(user_id);

            // Create a mock client that returns success for execute
            let mock_client = MockClient::with_execute_result(1);

            // Create the OAuthService with the mock client
            let app_config = AppConfig::default();
            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let mut oauth_service = OAuthService::new(&app_config, jwt_manager);
            oauth_service.db_client = Arc::new(mock_client);

            // Save the session
            let result = oauth_service.save_session(&session).await;

            assert!(result.is_ok());
        }

        // Test OAuthProvider equality
        #[test]
        fn test_oauth_provider_equality() {
            assert_eq!(OAuthProvider::Google, OAuthProvider::Google);
            assert_ne!(OAuthProvider::Google, OAuthProvider::GitHub);
            assert_ne!(OAuthProvider::Google, OAuthProvider::Facebook);
            assert_ne!(OAuthProvider::Google, OAuthProvider::Microsoft);
        }

        // Test state store functionality
        #[test]
        fn test_state_store() {
            // Create a new state store
            let state_store: StateStore = Arc::new(RwLock::new(HashMap::new()));

            // Create a test state
            let state_id = Uuid::new_v4().to_string();
            let test_state = OAuthState {
                csrf_token: "test_csrf".to_string(),
                redirect_uri: "https://example.com/callback".to_string(),
            };

            // Insert the state
            state_store.write().unwrap().insert(state_id.clone(), test_state.clone());

            // Retrieve the state
            let retrieved_state = state_store.read().unwrap().get(&state_id).cloned();
            assert!(retrieved_state.is_some());
            let retrieved_state = retrieved_state.unwrap();
            assert_eq!(retrieved_state.csrf_token, test_state.csrf_token);
            assert_eq!(retrieved_state.redirect_uri, test_state.redirect_uri);

            // Remove the state
            let removed_state = state_store.write().unwrap().remove(&state_id);
            assert!(removed_state.is_some());
            let removed_state = removed_state.unwrap();
            assert_eq!(removed_state.csrf_token, test_state.csrf_token);
            assert_eq!(removed_state.redirect_uri, test_state.redirect_uri);

            // Verify the state is no longer in the store
            assert!(!state_store.read().unwrap().contains_key(&state_id));
        }

        // Test authorize method
        #[tokio::test]
        async fn test_authorize() {
            let app_config = AppConfig {
                base_url: "http://localhost:8080".to_string(),
                google_client_id: Some("google_client_id".to_string()),
                google_client_secret: Some("google_client_secret".to_string()),
                ..Default::default()
            };

            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let oauth_service = OAuthService::new(&app_config, jwt_manager);

            let redirect_uri = "https://example.com/callback";
            let result = oauth_service.authorize(OAuthProvider::Google, redirect_uri).await;

            assert!(result.is_ok());
            let url = result.unwrap();

            // Verify URL contains expected parameters
            assert!(url.contains("client_id=google_client_id"));
            assert!(url.contains("redirect_uri="));
            assert!(url.contains("state="));
            assert!(url.contains("response_type=code"));
        }

        // Test callback method with invalid state
        #[tokio::test]
        async fn test_callback_invalid_state() {
            let app_config = AppConfig::default();
            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let oauth_service = OAuthService::new(&app_config, jwt_manager);

            let provider = OAuthProvider::Google;
            let code = "test_code";
            let state = "invalid_state_id";
            let req = test::TestRequest::get().to_http_request();

            let result = oauth_service.callback(provider, code, state, &req).await;

            assert!(result.is_err());
            let error = result.unwrap_err();
            assert!(error.to_string().contains("Invalid state"));
        }

        // Test exchange token method
        #[tokio::test]
        async fn test_exchange_token() {
            let app_config = AppConfig {
                base_url: "http://localhost:8080".to_string(),
                google_client_id: Some("google_client_id".to_string()),
                google_client_secret: Some("google_client_secret".to_string()),
                ..Default::default()
            };

            let jwt_manager = JwtService::new("test_secret", 60 * 24 * 7);
            let mut oauth_service = OAuthService::new(&app_config, jwt_manager);

            // Replace the OAuth client with a mock
            let mock_oauth_client = Arc::new(MockOAuthClient {
                exchange_code_response: Some(Ok("test_access_token".to_string())),
                get_user_info_response: None,
            });

            oauth_service.clients.insert(OAuthProvider::Google, mock_oauth_client);

            let result = oauth_service
                .exchange_token(
                    OAuthProvider::Google,
                    "test_code",
                    "http://localhost:8080/callback",
                )
                .await;

            assert!(result.is_ok());
            assert_eq!(result.unwrap(), "test_access_token");
        }

        // Mock OAuth client for testing
        struct MockOAuthClient {
            exchange_code_response: Option<Result<String, OAuthError>>,
            get_user_info_response: Option<Result<OAuthUserInfo, OAuthError>>,
        }

        impl OAuthClient for MockOAuthClient {
            async fn authorize_url(
                &self,
                _redirect_uri: &str,
                _state: &str,
            ) -> Result<String, OAuthError> {
                Ok(format!("https://example.com/auth?client_id=test&redirect_uri={}&state={}&response_type=code",
						   _redirect_uri, _state))
            }

            async fn exchange_code(
                &self,
                _code: &str,
                _redirect_uri: &str,
            ) -> Result<String, OAuthError> {
                match &self.exchange_code_response {
                    Some(response) => response.clone(),
                    None => Err(OAuthError::ClientError("No mock response configured".to_string())),
                }
            }

            async fn get_user_info(
                &self,
                _access_token: &str,
            ) -> Result<OAuthUserInfo, OAuthError> {
                match &self.get_user_info_response {
                    Some(response) => response.clone(),
                    None => Err(OAuthError::ClientError("No mock response configured".to_string())),
                }
            }
        }
    }
}
