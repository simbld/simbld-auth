//! User management module
//!
//! Handles user profile management, user administration, and user-related operations
//! (excluding authentication which is handled by the auth module).

pub mod dto;
pub mod error;
pub mod handlers;
pub mod models;
pub mod repository;
pub mod routes;
pub mod service;

pub use dto::{ChangePasswordRequest, UpdateProfileRequest, UserResponse};
pub use error::UserError;
pub use models::{User, UserRole, UserStatus};
pub use routes::configure_user_routes;
pub use service::UserService;
