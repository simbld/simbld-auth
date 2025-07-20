//! Authentication middleware for Actix Web
//!
//! Provides JWT token validation middleware and role-based access control.

use crate::auth::jwt::{Claims, JwtService};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error::ErrorUnauthorized,
    Error, FromRequest, HttpMessage, HttpRequest,
};
use futures_util::{future::LocalBoxFuture, FutureExt};
use std::future::{ready, Ready};
use std::rc::Rc;
use uuid::Uuid;

/// Authentication middleware factory
pub struct Authentication {
    jwt_service: Rc<JwtService>,
}

impl Authentication {
    pub fn new(jwt_service: JwtService) -> Self {
        Self {
            jwt_service: Rc::new(jwt_service),
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
    type Transform = AuthenticationMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthenticationMiddleware {
            service,
            jwt_service: Rc::clone(&self.jwt_service),
        }))
    }
}

/// Authentication middleware implementation
pub struct AuthenticationMiddleware<S> {
    service: S,
    jwt_service: Rc<JwtService>,
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

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let jwt_service = Rc::clone(&self.jwt_service);

        async move {
            // Remove Authorization header
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .ok_or_else(|| ErrorUnauthorized("Missing Authorization header"))?;

            // Validate Bearer token format
            if !auth_header.starts_with("Bearer ") {
                return Err(ErrorUnauthorized("Invalid Authorization header format"));
            }

            // Remove token
            let token = &auth_header[7..]; // Skip "Bearer "

            // Validate token
            let claims = jwt_service
                .validate_access_token(token)
                .map_err(|_| ErrorUnauthorized("Invalid or expired token"))?;

            // Insert claims into request extensions for later use
            req.extensions_mut().insert(claims);

            // Continue to the next service
            let service_response = self.service.call(req).await?;
            Ok(service_response)
        }
        .boxed_local()
    }
}

/// Role-based authorization middleware (simplified version)
pub struct RequireAuth;

impl RequireAuth {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RequireAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, B> Transform<S, ServiceRequest> for RequireAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RequireAuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequireAuthMiddleware {
            service,
        }))
    }
}

pub struct RequireAuthMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RequireAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        async move {
            // Check if claims exist in request extensions (set by Authentication middleware)
            if req.extensions().get::<Claims>().is_none() {
                return Err(ErrorUnauthorized("Authentication required"));
            }

            // Continue to the next service
            let service_response = self.service.call(req).await?;
            Ok(service_response)
        }
        .boxed_local()
    }
}

/// Extractor for authenticated user ID
pub struct AuthenticatedUser(pub Uuid);

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let result = req
            .extensions()
            .get::<Claims>()
            .map(|claims| AuthenticatedUser(claims.user_id))
            .ok_or_else(|| ErrorUnauthorized("No authentication claims were found"));

        ready(result)
    }
}

/// Extractor for full authentication claims
pub struct AuthClaims(pub Claims);

impl FromRequest for AuthClaims {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let result = req
            .extensions()
            .get::<Claims>()
            .cloned()
            .map(AuthClaims)
            .ok_or_else(|| ErrorUnauthorized("No authentication claims were found"));

        ready(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::HttpResponse;

    async fn protected_endpoint(_claims: AuthClaims) -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({
            "message": "Protected resource accessed"
        }))
    }

    async fn public_endpoint() -> HttpResponse {
        HttpResponse::Ok().json(serde_json::json!({
            "message": "Public resource"
        }))
    }

    #[actix_web::test]
    async fn test_middleware_creation() {
        let jwt_service = JwtService::new("test_secret");
        let _middleware = Authentication::new(jwt_service);
    }
}
