//! Handler functions for authentication and user management
//!
//! This module contains the handler functions that implement the actual
//! business logic for the API endpoints related to authentication, user
//! management, and authorization.

use actix_web::web::{Json, Path, Query};
use actix_web::{web, HttpResponse, Responder};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Claims;
use crate::errors::AppError;
use crate::models::{
    ApiResponse, AssignRoleDto, ChangePasswordDto, DetailedUserResponseDto, ListUsersQuery,
    LoginUserDto, OAuthUserDto, PasswordResetDto, PasswordResetRequestDto, RegisterUserDto,
    TokenResponseDto, UpdateProfileDto, UserResponseDto, UserStatsDto, VerifyEmailDto,
};
use crate::state::AppState;

/// Register a new user
///
/// Takes registration information and creates a new user account.
/// Returns the created user with authentication token.
pub async fn register_user(
    state: web::Data<Arc<AppState>>,
    payload: Json<RegisterUserDto>,
) -> Result<HttpResponse, AppError> {
    let result = state.user_service.register_user(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(result)))
}

/// Login a user
///
/// Takes login credentials and returns an authentication token.
pub async fn login_user(
    state: web::Data<Arc<AppState>>,
    payload: Json<LoginUserDto>,
) -> Result<HttpResponse, AppError> {
    let result = state.auth_service.login(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(result)))
}

/// Get the current user's profile
///
/// Uses the JWT token to identify the user and return their profile information.
pub async fn get_profile(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
) -> Result<HttpResponse, AppError> {
    let user = state.user_service.get_user_by_id(claims.sub).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(user)))
}

/// Update the current user's profile
///
/// Takes profile update information and updates the authenticated user's profile.
pub async fn update_profile(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
    payload: Json<UpdateProfileDto>,
) -> Result<HttpResponse, AppError> {
    let result = state.user_service.update_profile(claims.sub, payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(result)))
}

/// Change the current user's password
///
/// Takes old and new password and updates the authenticated user's password.
pub async fn change_password(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
    payload: Json<ChangePasswordDto>,
) -> Result<HttpResponse, AppError> {
    state.auth_service.change_password(claims.sub, payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Get a user by ID
///
/// Admin only. Takes a user ID and returns detailed user information.
pub async fn get_user_by_id(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    let user = state.user_service.get_detailed_user(id).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(user)))
}

/// Delete a user
///
/// Admin only. Takes a user ID and permanently deletes the user.
pub async fn delete_user(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    state.user_service.delete_user(id).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// List all users with pagination
///
/// Admin only. Takes pagination parameters and returns a list of users.
pub async fn list_users(
    state: web::Data<Arc<AppState>>,
    query: Query<ListUsersQuery>,
) -> Result<HttpResponse, AppError> {
    let users = state.user_service.list_users(query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(users)))
}

/// Assign a role to a user
///
/// Admin only. Takes a user ID and role information and assigns the role to the user.
pub async fn assign_role(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
    payload: Json<AssignRoleDto>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    state.role_service.assign_role(id, payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Get all roles assigned to a user
///
/// Admin only. Takes a user ID and returns a list of assigned roles.
pub async fn get_user_roles(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    let roles = state.role_service.get_user_roles(id).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(roles)))
}

/// OAuth callback handler
///
/// Processes OAuth callback from providers like Google, Facebook, etc.
/// Returns authentication token upon successful OAuth flow.
pub async fn oauth_callback(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse, AppError> {
    let provider_name = path.into_inner();
    let result = state.oauth_service.handle_callback(&provider_name, &query).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(result)))
}

/// Create a user account from OAuth data
///
/// Internal use only. Creates a new user from OAuth provider data.
pub async fn create_oauth_user(
    state: web::Data<Arc<AppState>>,
    payload: Json<OAuthUserDto>,
) -> Result<HttpResponse, AppError> {
    let user = state.oauth_service.create_oauth_user(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(user)))
}

/// Request email verification
///
/// Sends an email verification link to the authenticated user's email.
pub async fn request_email_verification(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
) -> Result<HttpResponse, AppError> {
    state.notification_service.send_verification_email(claims.sub).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Verify email address
///
/// Takes a verification token and marks the user's email as verified.
pub async fn verify_email(
    state: web::Data<Arc<AppState>>,
    payload: Json<VerifyEmailDto>,
) -> Result<HttpResponse, AppError> {
    state.user_service.verify_email(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Request password reset
///
/// Takes an email address and sends a password reset link if the user exists.
pub async fn request_password_reset(
    state: web::Data<Arc<AppState>>,
    payload: Json<PasswordResetRequestDto>,
) -> Result<HttpResponse, AppError> {
    state.notification_service.send_password_reset(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Reset password
///
/// Takes a password reset token and new password, then updates the user's password.
pub async fn reset_password(
    state: web::Data<Arc<AppState>>,
    payload: Json<PasswordResetDto>,
) -> Result<HttpResponse, AppError> {
    state.auth_service.reset_password(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Get user statistics
///
/// Admin only. Returns statistics about user accounts.
pub async fn get_user_stats(state: web::Data<Arc<AppState>>) -> Result<HttpResponse, AppError> {
    let stats = state.user_service.get_stats().await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(stats)))
}

/// Logout current user
///
/// Invalidates the current authentication token.
pub async fn logout(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
) -> Result<HttpResponse, AppError> {
    state.auth_service.logout(claims).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Refresh authentication token
///
/// Issues a new authentication token for the current user.
pub async fn refresh_token(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
) -> Result<HttpResponse, AppError> {
    let token = state.auth_service.refresh_token(claims).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(token)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{MockAuthService, MockRoleService, MockUserService};
    use actix_web::{test, web, App};
    use std::sync::Arc;

    /// Create a test application state with mock services
    async fn create_test_state() -> Arc<AppState> {
        // Create mock services
        let user_service = MockUserService::new();
        let auth_service = MockAuthService::new();
        let role_service = MockRoleService::new();

        // Create and return app state
        Arc::new(AppState {
            user_service: Arc::new(user_service),
            auth_service: Arc::new(auth_service),
            role_service: Arc::new(role_service),
            // Add other required mock services
        })
    }

    /// Create a test application with all routes configured
    fn create_test_app(state: Arc<AppState>) -> actix_web::App {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/api/auth/register", web::post().to(register_user))
            .route("/api/auth/login", web::post().to(login_user))
            .route("/api/auth/profile", web::get().to(get_profile))
            .route("/api/auth/profile", web::put().to(update_profile))
            .route("/api/auth/password", web::put().to(change_password))
            .route("/api/users/{id}", web::get().to(get_user_by_id))
            .route("/api/users/{id}", web::delete().to(delete_user))
            .route("/api/users", web::get().to(list_users))
            .route("/api/users/{id}/roles", web::post().to(assign_role))
            .route("/api/users/{id}/roles", web::get().to(get_user_roles))
        // Add other routes as needed
    }

    /// Mock password hasher for testing
    struct MockPasswordHasher;

    // Tests for register_user
    #[actix_web::test]
    async fn test_register_user_success() {
        // Implement test for successful user registration
    }

    #[actix_web::test]
    async fn test_register_user_existing_email() {
        // Implement test for registration with existing email
    }

    // Tests for login_user
    #[actix_web::test]
    async fn test_login_user_success() {
        // Implement test for successful login
    }

    #[actix_web::test]
    async fn test_login_user_invalid_credentials() {
        // Implement test for login with invalid credentials
    }

    // Add more tests for other handlers
}
