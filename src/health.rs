//! Health check handler using simbld_http

use serde_json::json;
use simbld_http::responses::CustomResponse;

/// Health check endpoint
pub async fn health_check() -> CustomResponse {
    CustomResponse::new(
        simbld_http::responses::ResponsesSuccessCodes::Ok.get_code(),
        "Healthy",
        json!({
            "status": "healthy",
            "service": "simbld_auth",
            "version": "1.0.0",
            "timestamp": chrono::Utc::now()
        })
        .to_string(),
        "Service is operational and healthy",
    )
}
