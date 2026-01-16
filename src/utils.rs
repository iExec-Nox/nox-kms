use axum::{Json, http::StatusCode, response::IntoResponse};
use serde_json::json;

/// Strip the 0x prefix from a hex string if present.
pub fn strip_0x_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Add the 0x prefix to a hex string.
pub fn add_0x_prefix(s: &str) -> String {
    format!("0x{}", s)
}

/// Truncate a hex string for logging, showing first N chars + "..."
pub fn truncate_hex(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

///Helper to build a BAD_REQUEST response with a JSON error message.
pub fn bad_request(e: impl std::fmt::Display) -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": e.to_string() })),
    )
        .into_response()
}
