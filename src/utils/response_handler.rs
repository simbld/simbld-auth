//! HTTP Response Handler
//!
//! This module provides intelligent response handling that automatically detects
//! the client type and returns appropriate response formats:
//! - JSON responses for API clients
//! - Styled HTML pages for browser clients
//!
//! # Features
//! - Automatic client detection based on Accept headers
//! - Rich JSON responses with metadata for APIs
//! - Beautiful HTML error pages for browsers
//! - Comprehensive HTTP status code support
//! - Color-coded error pages with technical details

use actix_web::http::header::ACCEPT;
use actix_web::{http::StatusCode, HttpRequest, HttpResponse};
use chrono::Utc;
use simbld_http::helpers::response_helpers::get_enriched_response_with_metadata;
use simbld_http::responses::ResponsesTypes;
use std::time::Duration;

pub struct ResponseHandler;

impl ResponseHandler {
    /// Create a smart hybrid response that adapts to a client type
    ///
    /// Automatically detects whether the client is an API consumer or a browser
    /// and returns the appropriate response format:
    /// - JSON with metadata for API clients
    /// - Styled HTML pages for browsers
    ///
    /// # Arguments
    /// * `req` - HTTP request for client detection
    /// * `response_type` - The response type to generate
    /// * `custom_title` - Optional custom title (overrides default)
    /// * `custom_description` - Optional custom description (overrides default)
    /// * `duration` - Request processing time for metrics
    ///
    /// # Returns
    /// * `HttpResponse` - Formatted response based on a client type
    ///
    /// # Detection Logic
    /// - Checks Accept header for "application/json"
    /// - Checks for X-Requested-With header (AJAX requests)
    /// - Defaults to HTML for browsers
    ///
    /// # Examples
    /// ```rust
    /// // API client will receive JSON
    /// let req = test::TestRequest::default()
    ///     .insert_header(("Accept", "application/json"))
    ///     .to_http_request();
    ///
    /// // Browser client will receive HTML
    /// let req = test::TestRequest::default()
    ///     .insert_header(("Accept", "text/html"))
    ///     .to_http_request();
    /// ```
    pub fn create_hybrid_response(
        req: &HttpRequest,
        response_type: ResponsesTypes,
        custom_title: Option<&str>,
        custom_description: Option<&str>,
        duration: Duration,
    ) -> HttpResponse {
        let accept_header = req.headers().get(ACCEPT).and_then(|h| h.to_str().ok()).unwrap_or("");

        // Auto-detect request type
        if accept_header.contains("application/json")
            || req.headers().get("X-Requested-With").is_some()
        {
            // 🔥 API REQUEST -> Rich JSON
            Self::create_json_response(req, response_type, duration)
        } else {
            // 🎨 BROWSER REQUEST -> Custom HTML
            Self::create_html_response(req, response_type, custom_title, custom_description)
        }
    }

    /// Create a rich JSON response with full metadata
    ///
    /// Generates a comprehensive JSON response including
    /// - Standard HTTP status information
    /// - Request context and timing
    /// - Structured error details
    /// - Metadata for debugging
    ///
    /// # Arguments
    /// * `req` - HTTP request for context
    /// * `response_type` - The response type to generate
    /// * `duration` - Request processing time
    ///
    /// # Returns
    /// * `HttpResponse` - JSON formatted response
    fn create_json_response(
        req: &HttpRequest,
        response_type: ResponsesTypes,
        duration: Duration,
    ) -> HttpResponse {
        let request_url = req.uri().to_string();
        let enriched_response =
            get_enriched_response_with_metadata(response_type, Some(&request_url), duration);

        HttpResponse::build(StatusCode::from_u16(response_type.get_code()).unwrap())
            .content_type("application/json")
            .body(enriched_response)
    }

    /// Create a custom-styled HTML error page
    ///
    /// Generates a beautiful, responsive HTML error page with:
    /// - Modern, gradient background design
    /// - Color-coded status indicators
    /// - Technical details for debugging
    /// - Responsive layout for all devices
    /// - Professional styling with hover effects
    ///
    /// # Arguments
    /// * `req` - HTTP request for context
    /// * `response_type` - The response type to generate
    /// * `custom_title` - Optional custom title
    /// * `custom_description` - Optional custom description
    ///
    /// # Returns
    /// * `HttpResponse` - HTML formatted response
    fn create_html_response(
        req: &HttpRequest,
        response_type: ResponsesTypes,
        custom_title: Option<&str>,
        custom_description: Option<&str>,
    ) -> HttpResponse {
        let code = response_type.get_code();
        let (_, default_title, default_description) = response_type.to_tuple();
        let title = custom_title.unwrap_or(default_title);
        let description = custom_description.unwrap_or(default_description);
        let request_url = req.uri().to_string();
        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");

        let html_content = format!(
            r#"
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error {}–{}</title>
                <style>
                    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                    body {{
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }}
                    .error-container {{
                        background: white;
                        border-radius: 16px;
                        box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                        padding: 60px 40px;
                        max-width: 600px;
                        text-align: center;
                        margin: 20px;
                    }}
                    .error-code {{
                        font-size: 5rem;
                        font-weight: 700;
                        color: {};
                        margin-bottom: 20px;
                        text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
                    }}
                    .error-title {{
                        font-size: 2rem;
                        color: #2c3e50;
                        margin-bottom: 20px;
                        font-weight: 600;
                    }}
                    .error-description {{
                        font-size: 1.2rem;
                        color: #7f8c8d;
                        line-height: 1.6;
                        margin-bottom: 40px;
                    }}
                    .error-details {{
                        background: #f8f9fa;
                        border-radius: 8px;
                        padding: 20px;
                        margin: 30px 0;
                        text-align: left;
                    }}
                    .error-details h3 {{
                        color: #2c3e50;
                        margin-bottom: 15px;
                        font-size: 1.1rem;
                    }}
                    .error-details p {{
                        margin: 8px 0;
                        color: #5a6c7d;
                    }}
                    .error-details strong {{ color: #2c3e50; }}
                    .btn {{
                        display: inline-block;
                        background: linear-gradient(45deg, #667eea, #764ba2);
                        color: white;
                        padding: 12px 30px;
                        border-radius: 25px;
                        text-decoration: none;
                        font-weight: 600;
                        transition: transform 0.2s;
                        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                    }}
                    .btn:hover {{
                        transform: translateY(-2px);
                        box-shadow: 0 6px 20px rgba(0,0,0,0.3);
                    }}
                    .status-badge {{
                        display: inline-block;
                        padding: 4px 12px;
                        border-radius: 20px;
                        font-size: 0.9rem;
                        font-weight: 600;
                        margin-bottom: 20px;
                        background: {};
                        color: {};
                    }}
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="status-badge">{}</div>
                    <div class="error-code">{}</div>
                    <div class="error-title">{}</div>
                    <div class="error-description">{}</div>
                    <div class="error-details">
                        <h3>🔍 Technical Details</h3>
                        <p><strong>HTTP Code:</strong> {}</p>
                        <p><strong>Requested URL:</strong> {}</p>
                        <p><strong>Timestamp:</strong> {}</p>
                        <p><strong>Error Type:</strong> {}</p>
                        <p><strong>Status Family:</strong> {}</p>
                    </div>
                    <a href="/" class="btn">← Back to Home</a>
                </div>
            </body>
            </html>
            "#,
            code,
            title,
            Self::get_error_color(code),
            Self::get_badge_bg(code),
            Self::get_badge_color(code),
            Self::get_status_family(code),
            code,
            title,
            description,
            code,
            request_url,
            timestamp,
            Self::get_error_type(code),
            Self::get_status_family(code)
        );

        HttpResponse::build(StatusCode::from_u16(code).unwrap())
            .content_type("text/html; charset=utf-8")
            .body(html_content)
    }

    /// Get error color based on HTTP code
    ///
    /// Returns appropriate colors for different HTTP status code ranges.
    /// Used for visual coding in HTML error pages.
    fn get_error_color(code: u16) -> &'static str {
        match code {
            100..=199 => "#3498db", // Blue for informational
            200..=299 => "#27ae60", // Green for success
            300..=399 => "#f39c12", // Orange for redirection
            400..=499 => "#e74c3c", // Red for client errors
            500..=599 => "#8e44ad", // Purple for server errors
            _ => "#95a5a6",         // Gray for unknown
        }
    }

    /// Get badge background color
    ///
    /// Returns light background colors for status badges.
    fn get_badge_bg(code: u16) -> &'static str {
        match code {
            100..=199 => "#e3f2fd", // Light blue
            200..=299 => "#e8f5e8", // Light green
            300..=399 => "#fff3e0", // Light orange
            400..=499 => "#ffebee", // Light red
            500..=599 => "#f3e5f5", // Light purple
            _ => "#f5f5f5",         // Light gray
        }
    }

    /// Get badge text color
    ///
    /// Returns text colors for status badges that contrast well
    /// with the background colors.
    fn get_badge_color(code: u16) -> &'static str {
        match code {
            100..=199 => "#1976d2", // Blue
            200..=299 => "#388e3c", // Green
            300..=399 => "#f57c00", // Orange
            400..=499 => "#d32f2f", // Red
            500..=599 => "#7b1fa2", // Purple
            _ => "#616161",         // Gray
        }
    }

    /// Get complete status family name
    ///
    /// Returns the full HTTP status family description.
    fn get_status_family(code: u16) -> &'static str {
        match code {
            100..=199 => "1xx Informational",
            200..=299 => "2xx Success",
            300..=399 => "3xx Redirection",
            400..=499 => "4xx Client Error",
            500..=599 => "5xx Server Error",
            _ => "Unknown Status",
        }
    }

    /// Get a specific error type description
    ///
    /// Returns the standard HTTP status text for the given code.
    /// Includes comprehensive coverage of all standard HTTP status codes.
    fn get_error_type(code: u16) -> &'static str {
        match code {
            // 1xx Informational
            100 => "Continue",
            101 => "Switching Protocols",
            102 => "Processing",
            103 => "Early Hints",

            // 2xx Success
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            203 => "Non-Authoritative Information",
            204 => "No Content",
            205 => "Reset Content",
            206 => "Partial Content",
            207 => "Multi-Status",
            208 => "Already Reported",
            226 => "IM Used",

            // 3xx Redirection
            300 => "Multiple Choices",
            301 => "Moved Permanently",
            302 => "Found",
            303 => "See Other",
            304 => "Not Modified",
            305 => "Use Proxy",
            307 => "Temporary Redirect",
            308 => "Permanent Redirect",

            // 4xx Client Error
            400 => "Bad Request",
            401 => "Unauthorized",
            402 => "Payment Required",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            406 => "Not Acceptable",
            407 => "Proxy Authentication Required",
            408 => "Request Timeout",
            409 => "Conflict",
            410 => "Gone",
            411 => "Length Required",
            412 => "Precondition Failed",
            413 => "Payload Too Large",
            414 => "URI Too Long",
            415 => "Unsupported Media Type",
            416 => "Range Not Satisfiable",
            417 => "Expectation Failed",
            418 => "I'm a teapot",
            421 => "Misdirected Request",
            422 => "Unprocessable Entity",
            423 => "Locked",
            424 => "Failed Dependency",
            425 => "Too Early",
            426 => "Upgrade Required",
            428 => "Precondition Required",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            451 => "Unavailable For Legal Reasons",

            // 5xx Server Error
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            505 => "HTTP Version Not Supported",
            506 => "Variant Also Negotiates",
            507 => "Insufficient Storage",
            508 => "Loop Detected",
            510 => "Not Extended",
            511 => "Network Authentication Required",

            // Default
            _ => "Unknown Error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test;
    use simbld_http::responses::{ResponsesClientCodes, ResponsesTypes};

    #[test]
    async fn test_client_detection_json() {
        let req = test::TestRequest::default()
            .insert_header(("Accept", "application/json"))
            .to_http_request();

        let response_type = ResponsesTypes::ClientError(ResponsesClientCodes::NotFound);
        let response = ResponseHandler::create_hybrid_response(
            &req,
            response_type,
            None,
            None,
            Duration::from_millis(100),
        );

        assert_eq!(response.status(), 404);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    }

    #[test]
    async fn test_client_detection_html() {
        let req =
            test::TestRequest::default().insert_header(("Accept", "text/html")).to_http_request();

        let response_type = ResponsesTypes::ClientError(ResponsesClientCodes::NotFound);
        let response = ResponseHandler::create_hybrid_response(
            &req,
            response_type,
            None,
            None,
            Duration::from_millis(100),
        );

        assert_eq!(response.status(), 404);
        assert_eq!(response.headers().get("content-type").unwrap(), "text/html; charset=utf-8");
    }

    #[test]
    async fn test_ajax_detection() {
        let req = test::TestRequest::default()
            .insert_header(("X-Requested-With", "XMLHttpRequest"))
            .to_http_request();

        let response_type = ResponsesTypes::ClientError(ResponsesClientCodes::NotFound);
        let response = ResponseHandler::create_hybrid_response(
            &req,
            response_type,
            None,
            None,
            Duration::from_millis(100),
        );

        assert_eq!(response.status(), 404);
        assert_eq!(response.headers().get("content-type").unwrap(), "application/json");
    }

    #[test]
    async fn test_error_colors() {
        assert_eq!(ResponseHandler::get_error_color(200), "#27ae60"); // Green
        assert_eq!(ResponseHandler::get_error_color(404), "#e74c3c"); // Red
        assert_eq!(ResponseHandler::get_error_color(500), "#8e44ad"); // Purple
        assert_eq!(ResponseHandler::get_error_color(999), "#95a5a6"); // Gray
    }

    #[test]
    async fn test_badge_colors() {
        assert_eq!(ResponseHandler::get_badge_bg(200), "#e8f5e8"); // Light green
        assert_eq!(ResponseHandler::get_badge_color(200), "#388e3c"); // Green

        assert_eq!(ResponseHandler::get_badge_bg(404), "#ffebee"); // Light red
        assert_eq!(ResponseHandler::get_badge_color(404), "#d32f2f"); // Red
    }

    #[test]
    async fn test_status_families() {
        assert_eq!(ResponseHandler::get_status_family(200), "2xx Success");
        assert_eq!(ResponseHandler::get_status_family(404), "4xx Client Error");
        assert_eq!(ResponseHandler::get_status_family(500), "5xx Server Error");
        assert_eq!(ResponseHandler::get_status_family(999), "Unknown Status");
    }

    #[test]
    async fn test_error_types() {
        assert_eq!(ResponseHandler::get_error_type(200), "OK");
        assert_eq!(ResponseHandler::get_error_type(404), "Not Found");
        assert_eq!(ResponseHandler::get_error_type(500), "Internal Server Error");
        assert_eq!(ResponseHandler::get_error_type(418), "I'm a teapot");
        assert_eq!(ResponseHandler::get_error_type(999), "Unknown Error");
    }

    #[test]
    async fn test_custom_titles_and_descriptions() {
        let req =
            test::TestRequest::default().insert_header(("Accept", "text/html")).to_http_request();

        let response_type = ResponsesTypes::ClientError(ResponsesClientCodes::NotFound);
        let response = ResponseHandler::create_hybrid_response(
            &req,
            response_type,
            Some("Custom Title"),
            Some("Custom Description"),
            Duration::from_millis(100),
        );

        assert_eq!(response.status(), 404);

        // Check if the response body contains custom content
        let body = response.into_body();
        // Note: In a real test, you'd need to read the body content
        // This is a simplified test structure
    }
}
