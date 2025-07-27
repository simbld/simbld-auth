use actix_web::web;

pub mod protected_routes;
pub use protected_routes::*;

pub fn configure_protected_api(cfg: &mut web::ServiceConfig) {
    cfg.configure_protected_api();
}
