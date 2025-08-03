//! User management routes
//!
//! Configuration of all user-related HTTP endpoints.

use crate::user::handlers;
use actix_web::{web, Scope};

/// Configure user management routes
pub fn configure_user_routes() -> Scope {
    web::scope("/users")
        // Get user by ID
        .route("/{id}", web::get().to(handlers::get_user))
        // Update user profile
        .route("/{id}/profile", web::put().to(handlers::update_profile))
        // Change password
        .route("/{id}/password", web::put().to(handlers::change_password))
        // Update user status (Admin only)
        .route("/{id}/status", web::put().to(handlers::update_user_status))
        // List users with pagination and filters
        .route("", web::get().to(handlers::list_users))
        // Assign a role to a user (Admin only)
        .route("/{id}/roles", web::post().to(handlers::assign_role))
        // Get user roles
        .route("/{id}/roles", web::get().to(handlers::get_user_roles))
        // Get user statistics (Admin only)
        .route("/stats", web::get().to(handlers::get_user_stats))
        // Get user by email (Admin only)
        .route("/by-email", web::get().to(handlers::get_user_by_email))
        // Get user by username (Admin only)
        .route("/by-username", web::get().to(handlers::get_user_by_username))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, App};

    #[actix_web::test]
    async fn test_routes_configuration() {
        let app = test::init_service(App::new().service(configure_user_routes())).await;

        // Test if the /users/{id} route exists
        let req = test::TestRequest::get().uri("/users/stats").to_request();

        let resp = test::call_service(&app, req).await;

        // Shouldn't return 404 (route exists)
        assert_ne!(resp.status(), 404);
    }

    #[tokio::test]
    async fn test_scope_creation() {
        let _scope = configure_user_routes();
        assert!(true);
    }

    #[test]
    async fn test_handlers_exist() {
        // Import handlers to ensure they're accessible
        // Handlers with 2 parameters (service, path)
        let _h1 = handlers::get_user;
        let _h2 = handlers::get_user_roles;

        // Handlers with 3 parameters (service, path, payload)
        let _h3 = handlers::update_profile;
        let _h4 = handlers::change_password;
        let _h5 = handlers::update_user_status;
        let _h6 = handlers::assign_role;

        // Handlers with 2 parameters spéciaux (service, query)
        let _h7 = handlers::list_users;
        let _h8 = handlers::get_user_by_email;
        let _h9 = handlers::get_user_by_username;

        // Handler with 1 parameter (service)
        let _h10 = handlers::get_user_stats;

        // If we reach here, all handlers are accessible
        assert!(true);
    }
}
