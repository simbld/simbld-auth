//! # Authentication Handlers
//!
//! This module contains all the HTTP handlers for authentication-related endpoints.
//! It implements the RESTful API endpoints for user registration, login, MFA operations,
//! session management, and password operations.

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

use crate::auth::jwt::Claims;
use crate::auth::service::AuthService;
use crate::errors::ApiError;

/// User registration request data structure
#[derive(Debug, Deserialize, Validate)]
pub struct RegisterRequest {
    /// Username must be between 3 and 50 characters
    #[validate(length(min = 3, max = 50))]
    pub username: String,

    /// Email must be a valid email format
    #[validate(email)]
    pub email: String,

    /// Password must be at least 8 characters
    #[validate(length(min = 8))]
    pub password: String,
}

/// User login request data structure
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    /// User email address
    pub email: String,

    /// User password
    pub password: String,
}

/// MFA verification request data structure
#[derive(Debug, Deserialize)]
pub struct MfaVerifyRequest {
    /// ID of the user attempting to verify MFA
    pub user_id: Uuid,

    /// OTP code provided by user
    pub code: String,
}

/// Refresh token request data structure
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    /// Refresh token value
    pub refresh_token: String,
}

/// Password change request data structure
#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    /// Current password for verification
    pub current_password: String,

    /// New password to set
    pub new_password: String,
}

/// MFA setup request data structure
#[derive(Debug, Deserialize)]
pub struct SetupMfaRequest {
    /// Password for verification before setup
    pub password: String,
}

/// MFA setup verification request
#[derive(Debug, Deserialize)]
pub struct VerifyMfaSetupRequest {
    /// OTP code to verify MFA setup
    pub code: String,
}

/// Authentication token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// JWT access token
    pub access_token: String,

    /// Refresh token for obtaining new access tokens
    pub refresh_token: String,

    /// Token type (typically "Bearer")
    pub token_type: String,

    /// Token expiration time in seconds
    pub expires_in: i64,
}

/// Response indicating MFA is required
#[derive(Debug, Serialize)]
pub struct MfaRequiredResponse {
    /// Flag indicating MFA is required
    pub mfa_required: bool,

    /// User ID to use in MFA verification
    pub user_id: Uuid,
}

/// Response for MFA setup
#[derive(Debug, Serialize)]
pub struct MfaSetupResponse {
    /// TOTP secret
    pub secret: String,

    /// URI for QR code generation
    pub provisioning_uri: String,
}

/// Register a new user
///
/// Validates the registration data and creates a new user account.
/// Returns the newly created user or an error.
pub async fn register(
    req: web::Json<RegisterRequest>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Validate the registration input
    req.validate()?;

    // Create the user in the database
    let user = auth_service.register_user(&req, &db_pool).await?;

    // Return the created user
    Ok(HttpResponse::Created().json(user))
}

/// Login a user
///
/// Authenticates a user with email and password.
/// Returns JWT tokens or indicates MFA is required.
pub async fn login(
    req: web::Json<LoginRequest>,
    http_req: HttpRequest,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Get client information for session tracking
    let user_agent = http_req
        .headers()
        .get("User-Agent")
        .map(|h| h.to_str().unwrap_or("unknown"))
        .unwrap_or("unknown");
    let ip_address =
        http_req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();

    // Authenticate the user
    let auth_result = auth_service.authenticate_user(&req.email, &req.password, &db_pool).await?;

    // Check if MFA is required
    if auth_result.mfa_required {
        return Ok(HttpResponse::Ok().json(MfaRequiredResponse {
            mfa_required: true,
            user_id: auth_result.user_id,
        }));
    }

    // Generate tokens
    let tokens = auth_service
        .generate_tokens(auth_result.user_id, &db_pool, ip_address, user_agent.to_string())
        .await?;

    // Return the token response
    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
    }))
}

/// Verify MFA code
///
/// Verifies the MFA code provided by user during login.
/// Returns JWT tokens if verification is successful.
pub async fn verify_mfa(
    req: web::Json<MfaVerifyRequest>,
    http_req: HttpRequest,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Get client information for session tracking
    let user_agent = http_req
        .headers()
        .get("User-Agent")
        .map(|h| h.to_str().unwrap_or("unknown"))
        .unwrap_or("unknown");
    let ip_address =
        http_req.connection_info().realip_remote_addr().unwrap_or("unknown").to_string();

    // Verify MFA code
    auth_service.verify_mfa_code(req.user_id, &req.code, &db_pool).await?;

    // Generate tokens
    let tokens = auth_service
        .generate_tokens(req.user_id, &db_pool, ip_address, user_agent.to_string())
        .await?;

    // Return the token response
    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
    }))
}

/// Refresh authentication token
///
/// Uses a refresh token to generate a new access token.
pub async fn refresh_token(
    req: web::Json<RefreshTokenRequest>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Refresh the token
    let tokens = auth_service.refresh_token(&req.refresh_token, &db_pool).await?;

    // Return the new tokens
    Ok(HttpResponse::Ok().json(TokenResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: 3600, // 1 hour
    }))
}

/// Logout a user
///
/// Invalidates the refresh token, effectively logging the user out.
pub async fn logout(
    req: web::Json<RefreshTokenRequest>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Invalidate the refresh token
    auth_service.invalidate_token(&req.refresh_token, &db_pool).await?;

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Successfully logged out"
    })))
}

/// Setup MFA for a user
///
/// Generates and returns TOTP secret and provisioning URI for MFA setup.
pub async fn setup_mfa(
    req: web::Json<SetupMfaRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Verify password before allowing MFA setup
    auth_service.verify_password(claims.sub, &req.password, &db_pool).await?;

    // Generate MFA setup
    let setup = auth_service.generate_mfa_setup(claims.sub, &db_pool).await?;

    // Return setup information
    Ok(HttpResponse::Ok().json(MfaSetupResponse {
        secret: setup.secret,
        provisioning_uri: setup.provisioning_uri,
    }))
}

/// Verify MFA setup
///
/// Verifies the MFA setup by checking the provided OTP code.
pub async fn verify_mfa_setup(
    req: web::Json<VerifyMfaSetupRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Verify and activate MFA
    auth_service.verify_and_activate_mfa(claims.sub, &req.code, &db_pool).await?;

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "MFA setup successful"
    })))
}

/// Disable MFA for a user
///
/// Disables MFA after password verification.
pub async fn disable_mfa(
    req: web::Json<SetupMfaRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Verify password before allowing MFA disabling
    auth_service.verify_password(claims.sub, &req.password, &db_pool).await?;

    // Disable MFA
    auth_service.disable_mfa(claims.sub, &db_pool).await?;

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "MFA disabled successfully"
    })))
}

/// Change user password
///
/// Allows an authenticated user to change their password.
pub async fn change_password(
    req: web::Json<ChangePasswordRequest>,
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Change the password
    auth_service
        .change_password(claims.sub, &req.current_password, &req.new_password, &db_pool)
        .await?;

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Password changed successfully"
    })))
}

/// Get current user information
///
/// Returns information about the currently authenticated user.
pub async fn get_me(
    claims: web::ReqData<Claims>,
    auth_service: web::Data<AuthService>,
    db_pool: web::Data<deadpool_postgres::Pool>,
) -> Result<HttpResponse, ApiError> {
    // Get user information
    let user = auth_service.get_user_by_id(claims.sub, &db_pool).await?;

    // Return user information
    Ok(HttpResponse::Ok().json(user))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test, web, App};
    use deadpool_postgres::{Config, Pool};
    use mockall::mock;
    use mockall::predicate::*;
    use tokio_postgres::NoTls;
    use uuid::Uuid;

    // Mock the AuthService for testing
    mock! {
        AuthService {}

        impl AuthService {
            pub async fn register_user(&self, username: &str, email: &str, password: &str) -> Result<Uuid, ApiError>;
            pub async fn login_user(&self, email: &str, password: &str, ip_address: Option<String>) -> Result<(Uuid, bool), ApiError>;
            pub async fn verify_mfa(&self, user_id: Uuid, code: &str) -> Result<TokenResponse, ApiError>;
            pub async fn refresh_token(&self, refresh_token: &str) -> Result<TokenResponse, ApiError>;
            pub async fn logout(&self, refresh_token: &str) -> Result<(), ApiError>;
            pub async fn setup_mfa(&self, user_id: Uuid, password: &str) -> Result<MfaSetupResponse, ApiError>;
            pub async fn verify_mfa_setup(&self, user_id: Uuid, code: &str) -> Result<(), ApiError>;
            pub async fn disable_mfa(&self, user_id: Uuid, password: &str) -> Result<(), ApiError>;
            pub async fn change_password(&self, user_id: Uuid, current_password: &str, new_password: &str) -> Result<(), ApiError>;
            pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User, ApiError>;
        }
    }

    // Helper function to create a mock DB pool
    fn create_mock_pool() -> Pool {
        let cfg = Config::new();
        Pool::new(cfg, NoTls)
    }

    // Test validation of register request
    #[test]
    fn test_register_request_validation() {
        // Valid request
        let valid_req = RegisterRequest {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };
        assert!(valid_req.validate().is_ok());

        // Invalid username (too short)
        let invalid_username = RegisterRequest {
            username: "ab".to_string(),
            email: "test@example.com".to_string(),
            password: "password123".to_string(),
        };
        assert!(invalid_username.validate().is_err());

        // Invalid email
        let invalid_email = RegisterRequest {
            username: "testuser".to_string(),
            email: "not_an_email".to_string(),
            password: "password123".to_string(),
        };
        assert!(invalid_email.validate().is_err());

        // Invalid password (too short)
        let invalid_password = RegisterRequest {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password: "pass".to_string(),
        };
        assert!(invalid_password.validate().is_err());
    }

    // Test register endpoint
    #[actix_web::test]
    async fn test_register_endpoint() {
        // Create mock AuthService
        let mut mock_auth_service = MockAuthService::new();

        // Set up expectations
        mock_auth_service
            .expect_register_user()
            .with(eq("testuser"), eq("test@example.com"), eq("password123"))
            .returning(|_, _, _| Ok(Uuid::new_v4()));

        // Create test app with routes
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_auth_service))
                .app_data(web::Data::new(create_mock_pool()))
                .route("/register", web::post().to(register)),
        )
        .await;

        // Create test request
        let req = test::TestRequest::post()
            .uri("/register")
            .set_json(&RegisterRequest {
                username: "testuser".to_string(),
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        // Send request and check response
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Test login endpoint
    #[actix_web::test]
    async fn test_login_endpoint() {
        // Create mock AuthService
        let mut mock_auth_service = MockAuthService::new();
        let user_id = Uuid::new_v4();

        // Set up expectations for successful login without MFA
        mock_auth_service
            .expect_login_user()
            .with(eq("test@example.com"), eq("password123"), any())
            .returning(move |_, _, _| Ok((user_id, false)));

        // When MFA is not required, login should return tokens
        mock_auth_service.expect_verify_mfa().never();

        // Create test app with routes
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_auth_service))
                .app_data(web::Data::new(create_mock_pool()))
                .route("/login", web::post().to(login)),
        )
        .await;

        // Create test request
        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        // Send request and check response
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Test login with MFA required
    #[actix_web::test]
    async fn test_login_with_mfa_required() {
        // Create mock AuthService
        let mut mock_auth_service = MockAuthService::new();
        let user_id = Uuid::new_v4();

        // Set up expectations for login with MFA required
        mock_auth_service
            .expect_login_user()
            .with(eq("test@example.com"), eq("password123"), any())
            .returning(move |_, _, _| Ok((user_id, true)));

        // Create test app with routes
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_auth_service))
                .app_data(web::Data::new(create_mock_pool()))
                .route("/login", web::post().to(login)),
        )
        .await;

        // Create test request
        let req = test::TestRequest::post()
            .uri("/login")
            .set_json(&LoginRequest {
                email: "test@example.com".to_string(),
                password: "password123".to_string(),
            })
            .to_request();

        // Send request and check response
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Parse response body and check it contains MFA information
        let body = test::read_body(resp).await;
        let mfa_response: MfaRequiredResponse = serde_json::from_slice(&body).unwrap();
        assert!(mfa_response.mfa_required);
        assert_eq!(mfa_response.user_id, user_id);
    }

    // Test MFA verification
    #[actix_web::test]
    async fn test_verify_mfa_endpoint() {
        // Create mock AuthService
        let mut mock_auth_service = MockAuthService::new();
        let user_id = Uuid::new_v4();

        // Set up expectations
        mock_auth_service.expect_verify_mfa().with(eq(user_id), eq("123456")).returning(|_, _| {
            Ok(TokenResponse {
                access_token: "access_token".to_string(),
                refresh_token: "refresh_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            })
        });

        // Create test app with routes
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_auth_service))
                .app_data(web::Data::new(create_mock_pool()))
                .route("/verify-mfa", web::post().to(verify_mfa)),
        )
        .await;

        // Create test request
        let req = test::TestRequest::post()
            .uri("/verify-mfa")
            .set_json(&MfaVerifyRequest {
                user_id,
                code: "123456".to_string(),
            })
            .to_request();

        // Send request and check response
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Parse response body and check it contains token information
        let body = test::read_body(resp).await;
        let token_response: TokenResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(token_response.token_type, "Bearer");
        assert_eq!(token_response.expires_in, 3600);
    }

    // Test refresh token
    #[actix_web::test]
    async fn test_refresh_token_endpoint() {
        // Create mock AuthService
        let mut mock_auth_service = MockAuthService::new();

        // Set up expectations
        mock_auth_service.expect_refresh_token().with(eq("old_refresh_token")).returning(|_| {
            Ok(TokenResponse {
                access_token: "new_access_token".to_string(),
                refresh_token: "new_refresh_token".to_string(),
                token_type: "Bearer".to_string(),
                expires_in: 3600,
            })
        });

        // Create test app with routes
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_auth_service))
                .app_data(web::Data::new(create_mock_pool()))
                .route("/refresh", web::post().to(refresh_token)),
        )
        .await;

        // Create test request
        let req = test::TestRequest::post()
            .uri("/refresh")
            .set_json(&RefreshTokenRequest {
                refresh_token: "old_refresh_token".to_string(),
            })
            .to_request();

        // Send request and check response
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Test logout
    #[actix_web::test]
    async fn test_logout_endpoint() {
        // Create mock AuthService
        let mut mock_auth_service = MockAuthService::new();

        // Set up expectations
        mock_auth_service.expect_logout().with(eq("refresh_token")).returning(|_| Ok(()));

        // Create test app with routes
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(mock_auth_service))
                .app_data(web::Data::new(create_mock_pool()))
                .route("/logout", web::post().to(logout)),
        )
        .await;

        // Create test request
        let req = test::TestRequest::post()
            .uri("/logout")
            .set_json(&RefreshTokenRequest {
                refresh_token: "refresh_token".to_string(),
            })
            .to_request();

        // Send request and check response
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Test serialization of responses
    #[test]
    fn test_response_serialization() {
        // Create a token response
        let token_response = TokenResponse {
            access_token: "access_token".to_string(),
            refresh_token: "refresh_token".to_string(),
            token_type: "Bearer".to_string(),
            expires_in: 3600,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&token_response).unwrap();

        // Verify serialization
        assert!(json.contains("access_token"));
        assert!(json.contains("refresh_token"));
        assert!(json.contains("Bearer"));
        assert!(json.contains("3600"));

        // Create an MFA required response
        let user_id = Uuid::new_v4();
        let mfa_response = MfaRequiredResponse {
            mfa_required: true,
            user_id,
        };

        // Serialize to JSON
        let json = serde_json::to_string(&mfa_response).unwrap();

        // Verify serialization
        assert!(json.contains("true"));
        assert!(json.contains(&user_id.to_string()));
    }
}
