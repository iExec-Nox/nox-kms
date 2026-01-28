/// Strip the 0x prefix from a hex string if present.
pub fn strip_0x_prefix(s: &str) -> &str {
    s.strip_prefix("0x").unwrap_or(s)
}

/// Add the 0x prefix to a hex string if not already present.
pub fn add_0x_prefix(s: &str) -> String {
    if s.starts_with("0x") {
        s.to_string()
    } else {
        format!("0x{}", s)
    }
}

/// Truncate a hex string for logging, showing first N chars + "..."
pub fn truncate_hex(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

pub fn serialize_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
