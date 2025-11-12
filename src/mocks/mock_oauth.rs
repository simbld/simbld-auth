use crate::auth::jwt::JwtService;
use crate::auth::oauth::{OAuthProvider, OAuthService};
use crate::types::AppConfig;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// Mock response for user information
pub struct MockUserInfoResponse {
    pub provider_name: OAuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub profile_image: Option<String>,
}

pub struct MockOAuthService {
    pub authorize_responses: Arc<RwLock<HashMap<OAuthProvider, Result<String, String>>>>,
    pub user_info_responses: Arc<RwLock<HashMap<String, MockUserInfoResponse>>>,
    pub jwt_manager: JwtService,
}

impl MockOAuthService {
    pub fn new() -> Self {
        MockOAuthService {
            authorize_responses: Arc::new(RwLock::new(HashMap::new())),
            user_info_responses: Arc::new(RwLock::new(HashMap::new())),
            jwt_manager: JwtService::new("test_secret"),
        }
    }

    pub fn add_authorize_response(
        &self,
        provider: OAuthProvider,
        response: Result<String, String>,
    ) {
        self.authorize_responses.write().unwrap().insert(provider, response);
    }

    pub fn add_user_info_response(&self, access_token: String, response: MockUserInfoResponse) {
        self.user_info_responses.write().unwrap().insert(access_token, response);
    }

    // Create a real OAuthService with test configuration
    pub fn create_real_service() -> OAuthService {
        let app_config = AppConfig {
            database_url: "postgresql://localhost/simbld_auth".to_string(),
            server: Default::default(),
            mfa: Default::default(),
            jwt_secret: "test_secret".to_string(),
            cors_origins: vec!["*".to_string()],
            rate_limit: 100,
            log_level: "info".to_string(),
        };

        let jwt_manager = JwtService::new("test_secret");
        OAuthService::new(&app_config, jwt_manager)
    }
}

// Helper function to create OAuthService for testing
pub fn create_test_oauth_service_with_client(
    _mock_client: crate::mocks::mock_client::MockClient,
) -> OAuthService {
    // TODO: Inject mock_client when OAuthService will support dependency injection

    let app_config = AppConfig {
        database_url: "postgresql://localhost/test_db".to_string(),
        server: Default::default(),
        mfa: Default::default(),
        jwt_secret: "test_secret_key".to_string(),
        cors_origins: vec!["http://localhost:3000".to_string()],
        rate_limit: 100,
        log_level: "debug".to_string(),
    };

    let jwt_service = JwtService::new("test_secret_key");
    OAuthService::new(&app_config, jwt_service)
}
