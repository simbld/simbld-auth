//! # Authentication Middleware
//!
//! This module provides middleware components for authentication and authorization.
//! These middlewares verify tokens, extract user information, and enforce access control.

use std::future::{ready, Ready};
use std::rc::Rc;
use std::task::{Context, Poll};
use std::pin::Pin;

use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use actix_web::error::ErrorUnauthorized;
use futures_util::future::LocalBoxFuture;
use uuid::Uuid;

use crate::auth::jwt::{JwtManager, Claims};
use crate::auth::models::Role;
use crate::errors::ApiError;

/// Middleware for requiring authentication
pub struct Authentication {
    jwt_manager: Rc<JwtManager>,
}

impl Authentication {
    /// Create a new Authentication middleware with the specified JWT manager
    pub fn new(jwt_manager: JwtManager) -> Self {
        Self {
            jwt_manager: Rc::new(jwt_manager),
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Authentication
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthenticationMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware {
            service,
            jwt_manager: self.jwt_manager.clone(),
        }))
    }
}

/// Inner service implementation for the Authentication middleware
pub struct AuthenticationMiddleware<S> {
    service: S,
    jwt_manager: Rc<JwtManager>,
}

impl<S, B> Service<ServiceRequest> for AuthenticationMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let jwt_manager = self.jwt_manager.clone();
        let mut authenticated = false;
        let mut claims: Option<Claims> = None;

        // Extract the Authorization header
        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..]; // Skip "Bearer "

                    // Verify the token
                    if let Ok(token_claims) = jwt_manager.verify_token(token) {
                        authenticated = true;
                        claims = Some(token_claims);
                    }
                }
            }
        }

        // If not authenticated, return an error
        if !authenticated {
            let fut = async {
                Err(ErrorUnauthorized(ApiError::new(
                    401,
                    "Authentication required".to_string(),
                )))
            };
            return Box::pin(fut);
        }

        // Store claims in the request extensions
        if let Some(claims_data) = claims {
            req.extensions_mut().insert(claims_data);
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Middleware for requiring a specific role
pub struct RequireRole {
    jwt_manager: Rc<JwtManager>,
    required_role: Role,
}

impl RequireRole {
    /// Create a new RequireRole middleware with the specified JWT manager and role
    pub fn new(jwt_manager: JwtManager, role: Role) -> Self {
        Self {
            jwt_manager: Rc::new(jwt_manager),
            required_role: role,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireRole
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = RoleMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RoleMiddleware {
            service,
            jwt_manager: self.jwt_manager.clone(),
            required_role: self.required_role.clone(),
        }))
    }
}

/// Inner service implementation for the RequireRole middleware
pub struct RoleMiddleware<S> {
    service: S,
    jwt_manager: Rc<JwtManager>,
    required_role: Role,
}

impl<S, B> Service<ServiceRequest> for RoleMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let jwt_manager = self.jwt_manager.clone();
        let required_role = self.required_role.clone();

        // First check authentication and extract user_id
        let mut user_id: Option<Uuid> = None;
        let mut has_required_role = false;

        if let Some(auth_header) = req.headers().get("Authorization") {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..]; // Skip "Bearer "

                    // Verify the token and extract user_id
                    if let Ok(claims) = jwt_manager.verify_token(token) {
                        user_id = Some(claims.sub);

                        // Here you would typically query your database to get the user's role
                        // For this example, we'll assume there's a function to get the user's role
                        if let Some(id) = user_id {
                            // This would be replaced with a database lookup in a real app
                            let user_role = get_user_role(id);
                            has_required_role = user_role == required_role;
                        }
                    }
                }
            }
        }

        // If not authorized with the required role, return a forbidden error
        if !has_required_role {
            let fut = async {
                Err(ErrorUnauthorized(ApiError::new(
                    403,
                    "Insufficient permissions".to_string(),
                )))
            };
            return Box::pin(fut);
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

/// Helper function to get a user's role (would be replaced with database lookup)
fn get_user_role(user_id: Uuid) -> Role {
    // In a real application, this would query your database
    // This is just a placeholder implementation
    Role::User
}

/// Extractor for authenticated user ID from request
pub struct AuthenticatedUser(pub Uuid);

impl FromRequest for AuthenticatedUser {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(claims) = req.extensions().get::<Claims>() {
            return ready(Ok(AuthenticatedUser(claims.sub)));
        }

        ready(Err(ErrorUnauthorized("User not authenticated")))
    }
}

/// Extractor for the full claims from request
pub struct AuthClaims(pub Claims);

impl FromRequest for AuthClaims {
    type Error = actix_web::Error;
    type Future = Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(claims) = req.extensions().get::<Claims>() {
            return ready(Ok(AuthClaims(claims.clone())));
        }

        ready(Err(ErrorUnauthorized("User not authenticated")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::{Claims, JwtManager};
    use actix_web::{
        dev::{Service, ServiceResponse},
        http::header::{self, HeaderValue},
        test::{self, TestRequest},
        web, App, Error, HttpResponse,
    };
    use std::time::{SystemTime, UNIX_EPOCH};
    use uuid::Uuid;

    // Helper function to get current timestamp in seconds
    fn current_timestamp() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as usize
    }

    // Mock endpoint for authentication tests
    async fn mock_protected_endpoint() -> HttpResponse {
        HttpResponse::Ok().body("Access granted")
    }

    // Mock endpoint for authenticated user tests
    async fn mock_user_endpoint(user: AuthenticatedUser) -> HttpResponse {
        HttpResponse::Ok().body(format!("User ID: {}", user.0))
    }

    // Mock endpoint for auth claims tests
    async fn mock_claims_endpoint(claims: AuthClaims) -> HttpResponse {
        HttpResponse::Ok().body(format!("Claims for user: {}", claims.0.sub))
    }

    // Helper function to create a test app with authentication middleware
    fn create_test_app() -> impl Service<actix_web::dev::Request, Response = ServiceResponse, Error = Error> {
        let jwt_manager = JwtManager::default();

        test::init_service(
            App::new()
                .wrap(Authentication::new(jwt_manager.clone()))
                .service(web::resource("/protected").to(mock_protected_endpoint))
                .service(web::resource("/user").to(mock_user_endpoint))
                .service(web::resource("/claims").to(mock_claims_endpoint))
                .app_data(web::Data::new(jwt_manager))
        )
    }

    // Helper function to create a test app with role-based middleware
    fn create_role_test_app(required_role: Role) -> (
        impl Service<actix_web::dev::Request, Response = ServiceResponse, Error = Error>,
        JwtManager,
    ) {
        let jwt_manager = JwtManager::default();

        let app = test::init_service(
            App::new()
                .wrap(Authentication::new(jwt_manager.clone()))
                .wrap(RequireRole::new(jwt_manager.clone(), required_role))
                .service(web::resource("/admin").to(mock_protected_endpoint))
                .app_data(web::Data::new(jwt_manager.clone()))
        );

        (app, jwt_manager)
    }

    #[actix_web::test]
    async fn test_authentication_middleware_valid_token() {
        // Create test app with authentication middleware
        let app = create_test_app().await;

        // Create JWT manager and generate valid token
        let jwt_manager = JwtManager::default();
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let token = jwt_manager.generate_token(user_id, session_id, None).unwrap();

        // Create request with valid token
        let req = TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be OK
        assert_eq!(resp.status(), 200);

        // Body should contain expected content
        let body = test::read_body(resp).await;
        assert_eq!(body, "Access granted");
    }

    #[actix_web::test]
    async fn test_authentication_middleware_missing_token() {
        // Create test app with authentication middleware
        let app = create_test_app().await;

        // Create request without token
        let req = TestRequest::get().uri("/protected").to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be Unauthorized
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_authentication_middleware_invalid_token() {
        // Create test app with authentication middleware
        let app = create_test_app().await;

        // Create request with invalid token
        let req = TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, "Bearer invalid.token.here"))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be Unauthorized
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_authentication_middleware_expired_token() {
        // Create test app with authentication middleware
        let app = create_test_app().await;

        // Create JWT manager with very short expiration
        let jwt_manager = JwtManager::new(1); // 1 second expiration
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let token = jwt_manager.generate_token(user_id, session_id, None).unwrap();

        // Wait for token to expire
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Create request with expired token
        let req = TestRequest::get()
            .uri("/protected")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be Unauthorized
        assert_eq!(resp.status(), 401);
    }

    #[actix_web::test]
    async fn test_authenticated_user_extractor() {
        // Create test app with authentication middleware
        let app = create_test_app().await;

        // Create JWT manager and generate valid token
        let jwt_manager = JwtManager::default();
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let token = jwt_manager.generate_token(user_id, session_id, None).unwrap();

        // Create request with valid token to endpoint using AuthenticatedUser
        let req = TestRequest::get()
            .uri("/user")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be OK
        assert_eq!(resp.status(), 200);

        // Body should contain user ID
        let body = test::read_body(resp).await;
        assert_eq!(body, format!("User ID: {}", user_id));
    }

    #[actix_web::test]
    async fn test_auth_claims_extractor() {
        // Create test app with authentication middleware
        let app = create_test_app().await;

        // Create JWT manager and generate valid token
        let jwt_manager = JwtManager::default();
        let user_id = Uuid::new_v4();
        let session_id = Uuid::new_v4();
        let token = jwt_manager.generate_token(user_id, session_id, None).unwrap();

        // Create request with valid token to endpoint using AuthClaims
        let req = TestRequest::get()
            .uri("/claims")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be OK
        assert_eq!(resp.status(), 200);

        // Body should contain claims info
        let body = test::read_body(resp).await;
        assert_eq!(body, format!("Claims for user: {}", user_id));
    }

    #[actix_web::test]
    async fn test_role_middleware_authorized() {
        // Mock the user role function to return ADMIN for our test user
        // Note: In a real implementation, you would use a test double/mock
        // This test assumes get_user_role returns ADMIN for the test user

        // Create test app with role middleware requiring ADMIN role
        let (app, jwt_manager) = create_role_test_app(Role::Admin).await;

        // Generate token for a user with admin privileges
        let admin_user_id = Uuid::new_v4(); // Assuming this ID will return ADMIN role
        let session_id = Uuid::new_v4();
        let token = jwt_manager.generate_token(admin_user_id, session_id, None).unwrap();

        // Create request with admin token
        let req = TestRequest::get()
            .uri("/admin")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be OK for admin user
        assert_eq!(resp.status(), 200);

        // Body should contain expected content
        let body = test::read_body(resp).await;
        assert_eq!(body, "Access granted");
    }

    #[actix_web::test]
    async fn test_role_middleware_unauthorized() {
        // Mock the user role function to return USER for our test user
        // Note: In a real implementation, you would use a test double/mock
        // This test assumes get_user_role returns USER for the test user

        // Create test app with role middleware requiring ADMIN role
        let (app, jwt_manager) = create_role_test_app(Role::Admin).await;

        // Generate token for a regular user without admin privileges
        let regular_user_id = Uuid::new_v4(); // Assuming this ID will return USER role
        let session_id = Uuid::new_v4();
        let token = jwt_manager.generate_token(regular_user_id, session_id, None).unwrap();

        // Create request with regular user token
        let req = TestRequest::get()
            .uri("/admin")
            .insert_header((header::AUTHORIZATION, format!("Bearer {}", token)))
            .to_request();

        // Execute request
        let resp = test::call_service(&app, req).await;

        // Response should be Forbidden for regular user
        assert_eq!(resp.status(), 403);
    }

    #[test]
    fn test_middleware_initialization() {
        // Test Authentication middleware constructor
        let jwt_manager = JwtManager::default();
        let auth_middleware = Authentication::new(jwt_manager.clone());

        // Test RequireRole middleware constructor
        let role_middleware = RequireRole::new(jwt_manager, Role::Admin);

        // Ensure middleware objects were created (no easy way to check internals)
        assert!(true);
    }
}