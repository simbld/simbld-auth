//! User API handlers
//!
//! This module contains the HTTP handler functions for the user API endpoints.
//! These handlers process incoming HTTP requests, interact with the user service layer,
//! and format appropriate HTTP responses.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use axum_extra::extract::WithRejection;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    auth::Claims,
    common::{api_response::ApiResponse, error::AppError},
    user::{
        dto::{
            AssignRoleDto, ChangePasswordDto, DetailedUserResponseDto, ListUsersQuery,
            LoginUserDto, OAuthUserDto, PasswordResetDto, PasswordResetRequestDto, RegisterUserDto,
            TokenResponseDto, UpdateProfileDto, UserResponseDto, UserStatsDto, VerifyEmailDto,
        },
        service::UserService,
    },
};

use super::AppState;

/// Handle user registration
///
/// Processes a user registration request by validating the input data
/// and creating a new user account.
pub async fn register_user(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<RegisterUserDto>, AppError>,
) -> Result<ApiResponse<UserResponseDto>, AppError> {
    let user = state.user_service.register_user(&payload).await?;
    Ok(ApiResponse::created(user.into()))
}

/// Handle user login
///
/// Authenticates a user based on username/email and password,
/// returning a JWT token upon successful authentication.
pub async fn login_user(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<LoginUserDto>, AppError>,
) -> Result<ApiResponse<TokenResponseDto>, AppError> {
    let token_response = state.user_service.login_user(&payload).await?;
    Ok(ApiResponse::ok(token_response))
}

/// Get the current user's profile
///
/// Retrieves the profile information for the authenticated user.
pub async fn get_profile(
    State(state): State<Arc<AppState>>,
    claims: Claims,
) -> Result<ApiResponse<UserResponseDto>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::invalid_request("Invalid user ID in token"))?;

    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(ApiResponse::ok(user.into()))
}

/// Update the current user's profile
///
/// Updates profile information such as display name and profile image.
pub async fn update_profile(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    WithRejection(Json(payload), _): WithRejection<Json<UpdateProfileDto>, AppError>,
) -> Result<ApiResponse<UserResponseDto>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::invalid_request("Invalid user ID in token"))?;

    let updated_user = state.user_service.update_profile(user_id, &payload).await?;
    Ok(ApiResponse::ok(updated_user.into()))
}

/// Change the current user's password
///
/// Validates the current password and updates it with a new one.
pub async fn change_password(
    State(state): State<Arc<AppState>>,
    claims: Claims,
    WithRejection(Json(payload), _): WithRejection<Json<ChangePasswordDto>, AppError>,
) -> Result<ApiResponse<()>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::invalid_request("Invalid user ID in token"))?;

    state.user_service.change_password(user_id, &payload).await?;
    Ok(ApiResponse::ok(()))
}

/// Get a user by ID
///
/// Retrieves a user's profile information by their unique ID.
/// This endpoint is typically restricted to administrators.
pub async fn get_user_by_id(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<ApiResponse<DetailedUserResponseDto>, AppError> {
    let user_id =
        Uuid::parse_str(&id).map_err(|_| AppError::invalid_request("Invalid user ID format"))?;

    let user = state.user_service.get_user_by_id(user_id).await?;
    Ok(ApiResponse::ok(user.into()))
}

/// Delete a user
///
/// Permanently removes a user account from the system.
/// This endpoint is typically restricted to administrators.
pub async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<ApiResponse<()>, AppError> {
    let user_id =
        Uuid::parse_str(&id).map_err(|_| AppError::invalid_request("Invalid user ID format"))?;

    state.user_service.delete_user(user_id).await?;
    Ok(ApiResponse::ok(()))
}

/// List users
///
/// Retrieves a paginated list of users in the system.
/// This endpoint is typically restricted to administrators.
pub async fn list_users(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ListUsersQuery>,
) -> Result<ApiResponse<Vec<UserResponseDto>>, AppError> {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(10);

    if page < 1 || limit < 1 || limit > 100 {
        return Err(AppError::invalid_request("Invalid pagination parameters"));
    }

    let users = state.user_service.list_users(page, limit).await?;
    let response: Vec<UserResponseDto> = users.into_iter().map(UserResponseDto::from).collect();

    Ok(ApiResponse::ok(response))
}

/// Assign a role to a user
///
/// Updates the roles assigned to a user.
/// This endpoint is typically restricted to administrators.
pub async fn assign_role(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    WithRejection(Json(payload), _): WithRejection<Json<AssignRoleDto>, AppError>,
) -> Result<ApiResponse<()>, AppError> {
    let user_id =
        Uuid::parse_str(&id).map_err(|_| AppError::invalid_request("Invalid user ID format"))?;

    state.user_service.assign_role(user_id, &payload.role).await?;
    Ok(ApiResponse::ok(()))
}

/// Get user roles
///
/// Retrieves the list of roles assigned to a user.
pub async fn get_user_roles(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<ApiResponse<Vec<String>>, AppError> {
    let user_id =
        Uuid::parse_str(&id).map_err(|_| AppError::invalid_request("Invalid user ID format"))?;

    let roles = state.user_service.get_user_roles(user_id).await?;
    Ok(ApiResponse::ok(roles))
}

/// Handle OAuth callback
///
/// Processes OAuth authentication callback from providers like Google, GitHub, etc.
pub async fn oauth_callback(
    State(state): State<Arc<AppState>>,
    Path(provider): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Result<ApiResponse<TokenResponseDto>, AppError> {
    // Extract the authorization code from query parameters
    let code = params
        .get("code")
        .ok_or_else(|| AppError::invalid_request("Missing authorization code"))?;

    // Process OAuth login
    let token_response = state.user_service.process_oauth_login(&provider, code).await?;
    Ok(ApiResponse::ok(token_response))
}

/// Create user account from OAuth data
///
/// Creates or updates user account with data from OAuth providers.
/// This is typically an internal endpoint called by the OAuth service.
pub async fn create_oauth_user(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<OAuthUserDto>, AppError>,
) -> Result<ApiResponse<UserResponseDto>, AppError> {
    let user = state.user_service.create_oauth_user(&payload).await?;
    Ok(ApiResponse::ok(user.into()))
}

/// Request email verification
///
/// Sends an email verification link to the current user.
pub async fn request_email_verification(
    State(state): State<Arc<AppState>>,
    claims: Claims,
) -> Result<ApiResponse<()>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::invalid_request("Invalid user ID in token"))?;

    state.user_service.request_email_verification(user_id).await?;
    Ok(ApiResponse::ok(()))
}

/// Verify email address
///
/// Verifies a user's email address using a token sent via email.
pub async fn verify_email(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<VerifyEmailDto>, AppError>,
) -> Result<ApiResponse<()>, AppError> {
    state.user_service.verify_email(&payload.token).await?;
    Ok(ApiResponse::ok(()))
}

/// Request password reset
///
/// Initiates a password reset process by sending a reset token to the user's email.
pub async fn request_password_reset(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<PasswordResetRequestDto>, AppError>,
) -> Result<ApiResponse<()>, AppError> {
    state.user_service.request_password_reset(&payload.email).await?;
    Ok(ApiResponse::ok(()))
}

/// Reset password
///
/// Completes the password reset process using the token received via email.
pub async fn reset_password(
    State(state): State<Arc<AppState>>,
    WithRejection(Json(payload), _): WithRejection<Json<PasswordResetDto>, AppError>,
) -> Result<ApiResponse<()>, AppError> {
    state.user_service.reset_password(&payload.token, &payload.new_password).await?;
    Ok(ApiResponse::ok(()))
}

/// Get user statistics
///
/// Retrieves summary statistics about users in the system.
/// This endpoint is typically restricted to administrators.
pub async fn get_user_stats(
    State(state): State<Arc<AppState>>,
) -> Result<ApiResponse<UserStatsDto>, AppError> {
    let stats = state.user_service.get_user_stats().await?;
    Ok(ApiResponse::ok(stats))
}

/// Handler for revoking a user token
///
/// Invalidates the current user's authentication token.
pub async fn logout(
    State(state): State<Arc<AppState>>,
    claims: Claims,
) -> Result<ApiResponse<()>, AppError> {
    state.user_service.revoke_token(&claims.jti).await?;
    Ok(ApiResponse::ok(()))
}

/// Handler for refreshing an authentication token
///
/// Issues a new token with a refreshed expiration time.
pub async fn refresh_token(
    State(state): State<Arc<AppState>>,
    claims: Claims,
) -> Result<ApiResponse<TokenResponseDto>, AppError> {
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::invalid_request("Invalid user ID in token"))?;

    let token_response = state.user_service.refresh_token(user_id, &claims.jti).await?;
    Ok(ApiResponse::ok(token_response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{jwt::JwtManager, role::UserRole},
        user::{repository::MockUserRepository, service::UserServiceImpl},
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post, put},
        Router,
    };
    use chrono::Utc;
    use serde_json::json;
    use tower::ServiceExt;

    // Helper function to create a test app state
    async fn create_test_state() -> Arc<AppState> {
        let repo = MockUserRepository::new();
        let password_hasher = MockPasswordHasher::new();
        let jwt_manager = JwtManager::new("test_secret", "user_api", 60);

        let user_service = UserServiceImpl::new(
            Arc::new(repo),
            Arc::new(password_hasher),
            Arc::new(jwt_manager),
            None, // No email service in tests
        );

        Arc::new(AppState {
            user_service: Arc::new(user_service),
            jwt_manager: Arc::new(jwt_manager),
        })
    }

    // Utility to create a test router with the handlers
    fn create_test_router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/register", post(register_user))
            .route("/login", post(login_user))
            .route("/profile", get(get_profile).put(update_profile))
            .route("/profile/password", post(change_password))
            .route("/users/:id", get(get_user_by_id).delete(delete_user))
            .route("/users", get(list_users))
            .route("/users/:id/roles", get(get_user_roles).post(assign_role))
            .with_state(state)
    }

    // Mock password hasher implementation
    struct MockPasswordHasher;

    impl MockPasswordHasher {
        fn new() -> Self {
            Self
        }

        fn hash_password(&self, password: &str) -> Result<String, AppError> {
            // Simple mock - just add a prefix
            Ok(format!("hashed_{}", password))
        }

        fn verify_password(&self, hash: &str, password: &str) -> Result<bool, AppError> {
            // Simple mock verification
            Ok(hash == format!("hashed_{}", password))
        }
    }

    #[tokio::test]
    async fn test_register_user() {
        let state = create_test_state().await;
        let app = create_test_router(state.clone());

        let request = Request::builder()
            .uri("/register")
            .method("POST")
            .header("Content-Type", "application/json")
            .body(Body::from(
                json!({
                    "username": "testuser",
                    "email": "test@example.com",
                    "password": "password123"
                })
                .to_string(),
            ))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::CREATED);

        // Add more assertions about the response body if needed
    }

    #[tokio::test]
    async fn test_get_profile() {
        let state = create_test_state().await;

        // Add a test user
        let user_id = Uuid::new_v4();
        let user = super::super::model::User {
            id: user_id,
            username: "profileuser".to_string(),
            email: "profile@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            display_name: Some("Profile User".to_string()),
            profile_image: None,
            provider: "local".to_string(),
            provider_id: None,
            is_active: true,
            is_verified: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_login: None,
        };

        if let Some(repo) = state.user_service.repo.as_any().downcast_ref::<MockUserRepository>() {
            repo.add_user(user.clone());
        }

        // Create a JWT token for the user
        let token = state
            .jwt_manager
            .create_token(user_id, &user.username, &user.email, vec![UserRole::User])
            .unwrap();

        let app = create_test_router(state);

        let request = Request::builder()
            .uri("/profile")
            .method("GET")
            .header("Authorization", format!("Bearer {}", token))
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Verify response body contains expected user data
        let body = hyper::body::to_bytes(response.into_body()).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["data"]["username"], "profileuser");
        assert_eq!(json["data"]["email"], "profile@example.com");
        assert_eq!(json["data"]["display_name"], "Profile User");
    }

    // Additional tests can be added for other handlers
}
