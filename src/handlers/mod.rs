//! HTTP handlers

pub mod auth;
pub mod health;

// Re-export for convenience
pub use health::health_check;
