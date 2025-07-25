//! Protected routes module
//!
//! This module defines routes that require authentication to access.
//! It handles token validation and provides proper error responses.

use crate::auth::service::AuthService;
use actix_web::{http::StatusCode, web, HttpRequest, HttpResponse, Responder};
use serde_json::json;

/// Middleware extractor for authenticated user information
pub struct AuthenticatedUser {
    pub user_id: uuid::Uuid,
    pub email: String,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub profile_picture: Option<String>,
    pub email_verified: bool,
    pub mfa_enabled: bool,
    pub last_login: Option<chrono::NaiveDateTime>,
    pub account_locked: bool,
    pub failed_login_attempts: i32,
    pub status: String,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: Option<chrono::NaiveDateTime>,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub scopes: Vec<String>,
    pub token: String,
}

/// Extract and validate an authentication token from the request
///
/// Returns the authenticated user information if valid, or an error response
async fn extract_auth_user(
    req: &HttpRequest,
    auth_service: &AuthService,
) -> Result<AuthenticatedUser, HttpResponse> {
    // Extract authorization header
    let auth_header =
        req.headers().get("Authorization").and_then(|h| h.to_str().ok()).ok_or_else(|| {
            HttpResponse::build(StatusCode::UNAUTHORIZED).json(json!({
                "error": "Missing token",
                "code": 401
            }))
        })?;

    // Validate header format
    if !auth_header.starts_with("Bearer ") {
        return Err(HttpResponse::build(StatusCode::UNAUTHORIZED).json(json!({
            "error": "Unauthorized",
            "code": 401
        })));
    }

    // Extract token
    let token = &auth_header["Bearer ".len()..];

    // Validate token using AuthService
    let claims = auth_service.validate_token(token).await.map_err(|_| {
        HttpResponse::build(StatusCode::UNAUTHORIZED).json(json!({
            "error": "Invalid or expired token",
            "code": 401
        }))
    })?;

    Ok(AuthenticatedUser {
        user_id: claims.user_id,
        email: format!("user-{}", claims.user_id), // Temporary - should get actual email from the user profile
        name: None,
        display_name: None,
        profile_picture: None,
        email_verified: false,
        mfa_enabled: false,
        last_login: None,
        account_locked: false,
        failed_login_attempts: 0,
        status: "active".to_string(),
        created_at: chrono::Utc::now().naive_utc(),
        updated_at: None,
        roles: vec!["user".to_string()],
        permissions: vec!["read".to_string()],
        scopes: vec!["profile".to_string()],
        token: token.to_string(),
    })
}

/// Handler for the basic protected route
///
/// Returns a success response with the user's email if authentication is valid
async fn protected_route(req: HttpRequest, auth_service: web::Data<AuthService>) -> impl Responder {
    // Remove and validate authentication
    let user = match extract_auth_user(&req, &auth_service).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Prepare success response
    HttpResponse::Ok().json(json!({
        "code": 200,
        "desc": "Authentication successful",
        "data": {
            "message": "Access Granted",
            "user_id": user.user_id,
            "email": user.email
        }
    }))
}

/// Handler for a resource endpoint that requires authentication
async fn get_user_profile(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
) -> impl Responder {
    // Extract and validate authentication
    let user = match extract_auth_user(&req, &auth_service).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Temp mock data
    HttpResponse::Ok().json(json!({
        "code": 200,
        "desc": "Profile retrieved successfully",
        "data": {
            "user_id": user.user_id,
            "email": user.email,
            "name": "Example User",
            "joined": "2023-01-01"
        }
    }))
}

/// Configures all protected routes
pub fn configure_protected_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/protected")
            .route("", web::get().to(protected_route))
            .route("/profile", web::get().to(get_user_profile)),
        // Additional protected routes can be added here
    );
}

/// Extension trait for ServiceConfig to easily add protected routes
pub trait ProtectedRoutes {
    fn configure_protected_api(&mut self) -> &mut Self;
}

impl ProtectedRoutes for web::ServiceConfig {
    fn configure_protected_api(&mut self) -> &mut Self {
        self.configure(configure_protected_routes);
        self
    }
}
