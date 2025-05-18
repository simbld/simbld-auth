//! Protected routes module
//!
//! This module defines routes that require authentication to access.
//! It handles token validation and provides proper error responses.

use crate::auth::service::AuthService;
use actix_web::{web, HttpRequest, HttpResponse, Responder, http::StatusCode};
use serde_json::json;
use simbld_http::responses::client::unauthorized;
use simbld_http::responses::local::missing_token;
use simbld_http::responses::success::{ok, authentication_successful};

/// Middleware extractor for authenticated user information
pub struct AuthenticatedUser {
    pub email: String,
    // Additional user info could be added here (e.g., user_id, roles, etc.)
}

/// Extract and validate authentication token from the request
///
/// Returns the authenticated user info if valid, or an error response
async fn extract_auth_user(req: &HttpRequest) -> Result<AuthenticatedUser, HttpResponse> {
    // Extract authorization header
    let auth_header = req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            let (code, description) = missing_token();
            HttpResponse::build(StatusCode::from_u16(code).unwrap())
                .body(description)
        })?;

    // Validate header format
    if !auth_header.starts_with("Bearer ") {
        let (code, description) = unauthorized();
        return Err(HttpResponse::build(StatusCode::from_u16(code).unwrap())
            .body(description));
    }

    // Extract token
    let token = &auth_header["Bearer ".len()..];

    // Validate token
    let email = AuthService::validate_token(token).await
        .map_err(|(code, desc)| {
            HttpResponse::build(StatusCode::from_u16(code).unwrap())
                .body(desc)
        })?;

    Ok(AuthenticatedUser { email })
}

/// Handler for the basic protected route
///
/// Returns a success response with the user's email if authentication is valid
async fn protected_route(req: HttpRequest) -> impl Responder {
    // Extract and validate authentication
    let user = match extract_auth_user(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Prepare success response
    let (code, description) = authentication_successful();
    HttpResponse::build(StatusCode::from_u16(code).unwrap())
        .json(json!({
            "code": code,
            "desc": description,
            "data": {
                "message": "Access Granted",
                "email": user.email
            }
        }))
}

/// Handler for a resource endpoint that requires authentication
async fn get_user_profile(req: HttpRequest) -> impl Responder {
    // Extract and validate authentication
    let user = match extract_auth_user(&req).await {
        Ok(user) => user,
        Err(response) => return response,
    };

    // Here you would typically fetch the user's profile from a database
    // For demonstration, we're returning a mock profile

    // Prepare success response
    let (code, _) = ok();
    HttpResponse::build(StatusCode::from_u16(code).unwrap())
        .json(json!({
            "code": code,
            "desc": "Profile retrieved successfully",
            "data": {
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
            .route("/profile", web::get().to(get_user_profile))
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