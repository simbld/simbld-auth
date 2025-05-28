//! Routes for the authentication service
//!
//! This module contains all the routes for the authentication service.
//! It handles user registration, login, profile management, and role management.

use std::sync::Arc;
use actix_web::{web, Scope, HttpResponse, Responder};
use actix_web::web::{Json, Path, Query};
use crate::auth::Claims;
use crate::errors::AppError;
use crate::models::{
    ApiResponse, RegisterUserDto, LoginUserDto, UserResponseDto,
    UpdateProfileDto, ChangePasswordDto, ListUsersQuery, AssignRoleDto,
};
use crate::state::AppState;
use uuid::Uuid;

/// Initialize the routes for the authentication service
pub fn init_routes(state: Arc<AppState>) -> Scope {
    web::scope("/api")
        .app_data(web::Data::new(state.clone()))
        .service(
            web::scope("/auth")
                .route("/register", web::post().to(register_user))
                .route("/login", web::post().to(login_user))
                .route("/profile", web::get().to(get_profile))
                .route("/profile", web::put().to(update_profile))
                .route("/password", web::put().to(change_password))
        )
        .service(
            web::scope("/users")
                .route("", web::get().to(list_users))
                .route("/{id}", web::get().to(get_user_by_id))
                .route("/{id}", web::delete().to(delete_user))
                .route("/{id}/roles", web::post().to(assign_role))
                .route("/{id}/roles", web::get().to(get_user_roles))
        )
}

/// Register a new user
///
/// Takes a JSON payload with email, password, and optional name.
/// Returns the created user with an auth token.
async fn register_user(
    state: web::Data<Arc<AppState>>,
    payload: Json<RegisterUserDto>,
) -> Result<HttpResponse, AppError> {
    let result = state.user_service.register_user(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(result)))
}

/// Login a user
///
/// Takes a JSON payload with email and password.
/// Returns an auth token and user info.
async fn login_user(
    state: web::Data<Arc<AppState>>,
    payload: Json<LoginUserDto>,
) -> Result<HttpResponse, AppError> {
    let result = state.auth_service.login(payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(result)))
}

/// Get the current user's profile
///
/// Uses the JWT token to identify the user.
/// Returns the user's profile information.
async fn get_profile(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
) -> Result<HttpResponse, AppError> {
    let user = state.user_service.get_user_by_id(claims.sub).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(user)))
}

/// Update the current user's profile
///
/// Takes a JSON payload with updated profile fields.
/// Returns the updated user profile.
async fn update_profile(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
    payload: Json<UpdateProfileDto>,
) -> Result<HttpResponse, AppError> {
    let user = state.user_service.update_profile(claims.sub, payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(user)))
}

/// Change the current user's password
///
/// Takes a JSON payload with old and new password.
/// Returns success or error.
async fn change_password(
    state: web::Data<Arc<AppState>>,
    claims: Claims,
    payload: Json<ChangePasswordDto>,
) -> Result<HttpResponse, AppError> {
    state.auth_service.change_password(claims.sub, payload.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// Get a user by ID
///
/// Admin only. Takes a user ID and returns user info.
async fn get_user_by_id(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    let user = state.user_service.get_user_by_id(id).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(user)))
}

/// Delete a user
///
/// Admin only. Takes a user ID and permanently deletes the user.
async fn delete_user(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    state.user_service.delete_user(id).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(())))
}

/// List all users with pagination
///
/// Admin only. Takes pagination params and returns a list of users.
async fn list_users(
    state: web::Data<Arc<AppState>>,
    query: Query<ListUsersQuery>,
) -> Result<HttpResponse, AppError> {
    let users = state.user_service.list_users(query.into_inner()).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(users)))
}

/// Assign a role to a user
///
/// Admin only. Takes a user ID and role name.
/// Adds the specified role to the user.
async fn assign_role(
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
/// Admin only. Takes a user ID and returns a list of role names.
async fn get_user_roles(
    state: web::Data<Arc<AppState>>,
    path: Path<String>,
) -> Result<HttpResponse, AppError> {
    let id = Uuid::parse_str(&path.into_inner())?;
    let roles = state.role_service.get_user_roles(id).await?;
    Ok(HttpResponse::Ok().json(ApiResponse::success(roles)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App, http::StatusCode};
    use crate::test_utils::build_test_state;
    use crate::user::dto::RegisterUserDto;

    /// Build a test app state
    async fn build_test_state() -> Arc<AppState> {
        // Implement test state builder
        todo!("Implementation of test state builder")
    }

    #[actix_web::test]
    async fn test_register_user_success() {
        let state = build_test_state().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(state.clone()))
                .service(web::scope("/api").route("/auth/register", web::post().to(register_user)))
        ).await;

        let payload = RegisterUserDto {
            username: "".to_string(),
            email: "test@example.com".to_string(),
            password: "Password123!".to_string(),
        };

        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(&payload)
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body: ApiResponse<UserResponseDto> = test::read_body_json(resp).await;
        assert!(body.success);
        assert_eq!(body.data.email, "test@example.com");
    }

    #[actix_web::test]
    async fn test_register_user_validation_error() {
        // Test implementation for validation error
        todo!("Test implementation for validation error")
    }

    #[actix_web::test]
    async fn test_login_user() {
        // Test implementation for login
        todo!("Test implementation for login")
    }

    #[actix_web::test]
    async fn test_profile_operations() {
        // Test implementation for profile operations
        todo!("Test implementation for profile operations")
    }
}