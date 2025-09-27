//! Simbld Authentication Service
//!
//! A comprehensive authentication and user management service built with Actix-web and `PostgreSQL`.
//! Provides JWT-based authentication, user management, and health monitoring capabilities.

// pub mod auth;
pub mod health;
pub mod mocks;
pub mod protected;
// pub mod mock_handlers;
pub mod simple_health;
pub mod user;

pub mod sqlx;
pub mod types;
pub mod utils;

// Re-export commonly used types and functions
pub use simple_health::{database_test_only, simple_health_with_db};

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SERVICE_NAME: &str = "simbld-auth";
