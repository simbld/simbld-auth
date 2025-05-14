use crate::auth::jwt::JwtManager;
use crate::auth::oauth::{OAuthProvider, OAuthService};
use crate::config::AppConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Mock response for user info
pub struct MockUserInfoResponse {
    pub provider: OAuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub profile_image: Option<String>,
}

pub struct MockOAuthService {
    pub authorize_responses: Arc<RwLock<HashMap<OAuthProvider, Result<String, String>>>>,
    pub user_info_responses: Arc<RwLock<HashMap<String, MockUserInfoResponse>>>,
    pub jwt_manager: JwtManager,
}

impl MockOAuthService {
    pub fn new() -> Self {
        MockOAuthService {
            authorize_responses: Arc::new(RwLock::new(HashMap::new())),
            user_info_responses: Arc::new(RwLock::new(HashMap::new())),
            jwt_manager: JwtManager::new("test_secret", 60 * 24 * 7), // 7 days
        }
    }

    pub fn add_authorize_response(&self, provider: OAuthProvider, response: Result<String, String>) {
        self.authorize_responses.write().unwrap().insert(provider, response);
    }

    pub fn add_user_info_response(&self, access_token: String, response: MockUserInfoResponse) {
        self.user_info_responses.write().unwrap().insert(access_token, response);
    }

    // Create a real OAuthService with test configuration
    pub fn create_real_service() -> OAuthService {
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

        let jwt_manager = JwtManager::new("test_secret", 60 * 24 * 7); // 7 days
        OAuthService::new(&app_config, jwt_manager)
    }
}

// Helper function to create OAuthService for testing
pub fn create_test_oauth_service_with_client(mock_client: crate::mocks::mock_client::MockClient) -> OAuthService {
    // In a real implementation, this would create an OAuthService instance with the mock client
    todo!("Implement create_test_oauth_service_with_client to return a valid OAuthService that uses the provided mock client")
}