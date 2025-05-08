use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpMessage,
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use crate::{
    auth::jwt::JwtService,
    auth::models::Claims,
};

pub struct JwtMiddleware {
    jwt_service: JwtService,
}

impl JwtMiddleware {
    pub fn new(jwt_service: JwtService) -> Self {
        Self { jwt_service }
    }
}

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddlewareService {
            service,
            jwt_service: self.jwt_service.clone(),
        }))
    }
}

pub struct JwtMiddlewareService<S> {
    service: S,
    jwt_service: JwtService,
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Check if the road is exempt from authentication
        if req.path().starts_with("/api/auth/") || req.path() == "/health" {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res)
            });
        }

        // extract the token jwt from the Authorization header
        let auth_header = req.headers().get("Authorization");
        let token = match auth_header {
            Some(header) => {
                let header_str = header.to_str().unwrap_or_default();
                if header_str.starts_with("Bearer ") {
                    header_str[7..].to_string()
                } else {
                    return Box::pin(async move {
                        Err(actix_web::error::ErrorUnauthorized("Invalid authorization header format"))
                    });
                }
            }
            None => {
                return Box::pin(async move {
                    Err(actix_web::error::ErrorUnauthorized("Missing authorization header"))
                });
            }
        };

        // Validate the token jwt
        let jwt_service = self.jwt_service.clone();
        let claims = match jwt_service.validate_token(&token) {
            Ok(claims) => claims,
            Err(err) => {
                let error_message = match err {
                    JwtError::Expired => "Token expired",
                    _ => "Invalid token",
                };
                return Box::pin(async move {
                    Err(actix_web::error::ErrorUnauthorized(error_message))
                });
            }
        };

        // Add the claims to the extension of the request
        req.extensions_mut().insert(claims);

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res)
        })
    }
}

// Middleware to check the roles
pub struct RoleMiddleware {
    required_roles: Vec<String>,
}

impl RoleMiddleware {
    pub fn new(required_roles: Vec<String>) -> Self {
        Self { required_roles }
    }
}

impl<S, B> Transform<S, ServiceRequest> for RoleMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RoleMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RoleMiddlewareService {
            service,
            required_roles: self.required_roles.clone(),
        }))
    }
}

pub struct RoleMiddlewareService<S> {
    service: S,
    required_roles: Vec<String>,
}

impl<S, B> Service<ServiceRequest> for RoleMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Recover user claims from the request for the request
        if let Some(claims) = req.extensions().get::<Claims>() {
            // Check if the user has at least one of the required roles
            let has_required_role = self.required_roles.iter().any(|role| claims.roles.contains(role));

            if has_required_role {
                let fut = self.service.call(req);
                return Box::pin(async move {
                    let res = fut.await?;
                    Ok(res)
                });
            }
        }

        // refuse access if the user does not have the required roles
        Box::pin(async move {
            Err(actix_web::error::ErrorForbidden("Insufficient permissions"))
        })
    }
}
