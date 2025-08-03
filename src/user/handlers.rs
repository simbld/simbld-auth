//! User management HTTP handlers
//!
//! This module contains the HTTP request handlers for user-related operations.

use crate::user::{dto::*, error::UserError, service::UserService};
use actix_web::{web, HttpResponse, Result as ActixResult};
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

/// Helper function to parse user ID from a path
fn parse_user_id(path: &str) -> Result<Uuid, actix_web::Error> {
    Uuid::parse_str(path).map_err(|_| actix_web::error::ErrorBadRequest("Invalid user ID format"))
}

/// Helper function to handle validation errors
fn handle_validation_error(validation_errors: validator::ValidationErrors) -> HttpResponse {
    HttpResponse::BadRequest().json(serde_json::json!({
        "error": "Validation failed",
        "details": validation_errors
    }))
}

/// Helper function to handle user errors
fn handle_user_error(error: UserError) -> HttpResponse {
    match error {
        UserError::UserNotFound => HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        })),
        UserError::UsernameTaken => HttpResponse::Conflict().json(serde_json::json!({
            "error": "Username already took"
        })),
        UserError::ValidationError(e) => HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Validation failed",
            "details": e.to_string()
        })),
        _ => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": error.to_string()
        })),
    }
}

/// Helper function to handle user lookup operations (by ID, email, username)
async fn handle_user_lookup<F>(service: &UserService, lookup_fn: F) -> ActixResult<HttpResponse>
where
    F: std::future::Future<Output = Result<Option<crate::user::models::User>, UserError>>,
{
    match lookup_fn.await {
        Ok(Some(user)) => {
            let response = service.user_to_response(user);
            Ok(HttpResponse::Ok().json(response))
        },
        Ok(None) => Ok(HttpResponse::NotFound().json(serde_json::json!({
            "error": "User not found"
        }))),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Get user by ID
pub async fn get_user(
    service: web::Data<Arc<UserService>>,
    path: web::Path<String>,
) -> ActixResult<HttpResponse> {
    let user_id = parse_user_id(&path.into_inner())?;

    handle_user_lookup(&**service, service.get_user_by_id(user_id)).await
}

/// Update user profile
pub async fn update_profile(
    service: web::Data<Arc<UserService>>,
    path: web::Path<String>,
    payload: web::Json<UpdateProfileRequest>,
) -> ActixResult<HttpResponse> {
    let user_id = parse_user_id(&path.into_inner())?;

    // Validation
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    match service.update_profile(user_id, payload.into_inner()).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Profile updated successfully"
        }))),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Change user password
pub async fn change_password(
    service: web::Data<Arc<UserService>>,
    path: web::Path<String>,
    payload: web::Json<ChangePasswordRequest>,
) -> ActixResult<HttpResponse> {
    let user_id = parse_user_id(&path.into_inner())?;

    // Validation
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    match service.change_password(user_id, payload.into_inner()).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Password changed successfully"
        }))),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Update user status (Admin only)
pub async fn update_user_status(
    service: web::Data<Arc<UserService>>,
    path: web::Path<String>,
    payload: web::Json<UpdateUserStatusRequest>,
) -> ActixResult<HttpResponse> {
    let user_id = parse_user_id(&path.into_inner())?;

    // Validation
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    match service.update_user_status(user_id, payload.into_inner()).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "User status updated successfully"
        }))),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// List users with pagination and filters
pub async fn list_users(
    service: web::Data<Arc<UserService>>,
    query: web::Query<ListUsersQuery>,
) -> ActixResult<HttpResponse> {
    // Validation
    if let Err(validation_errors) = query.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    match service.list_users(query.into_inner()).await {
        Ok(response) => Ok(HttpResponse::Ok().json(response)),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Assign a role to a user (Admin only)
pub async fn assign_role(
    service: web::Data<Arc<UserService>>,
    path: web::Path<String>,
    payload: web::Json<AssignRoleRequest>,
) -> ActixResult<HttpResponse> {
    let user_id = parse_user_id(&path.into_inner())?;

    // Validation
    if let Err(validation_errors) = payload.validate() {
        return Ok(handle_validation_error(validation_errors));
    }

    match service.assign_role(user_id, payload.into_inner()).await {
        Ok(_) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "message": "Role assigned successfully"
        }))),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Get user roles
pub async fn get_user_roles(
    service: web::Data<Arc<UserService>>,
    path: web::Path<String>,
) -> ActixResult<HttpResponse> {
    let user_id = parse_user_id(&path.into_inner())?;

    match service.get_user_roles(user_id).await {
        Ok(roles) => Ok(HttpResponse::Ok().json(serde_json::json!({
            "roles": roles
        }))),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Get user statistics (Admin only)
pub async fn get_user_stats(service: web::Data<Arc<UserService>>) -> ActixResult<HttpResponse> {
    match service.get_user_stats().await {
        Ok(stats) => Ok(HttpResponse::Ok().json(stats)),
        Err(e) => Ok(handle_user_error(e)),
    }
}

/// Get user by email (Admin only)
pub async fn get_user_by_email(
    service: web::Data<Arc<UserService>>,
    query: web::Query<serde_json::Value>,
) -> ActixResult<HttpResponse> {
    let email = query
        .get("email")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing email parameter"))?;

    handle_user_lookup(&**service, service.get_user_by_email(email)).await
}

/// Get user by username (Admin only)
pub async fn get_user_by_username(
    service: web::Data<Arc<UserService>>,
    query: web::Query<serde_json::Value>,
) -> ActixResult<HttpResponse> {
    let username = query
        .get("username")
        .and_then(|v| v.as_str())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("Missing username parameter"))?;

    handle_user_lookup(&**service, service.get_user_by_username(username)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_uuid() {
        let valid_uuid = "550e8400-e29b-41d4-a716-446655440000";
        let result = parse_user_id(valid_uuid);
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_invalid_uuid() {
        let invalid_uuid = "invalid-uuid";
        let result = parse_user_id(invalid_uuid);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_handlers_compile() {
        assert!(true);
    }
}
