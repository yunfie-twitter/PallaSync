use serde_json::Value;

/// Serialize JSON using RFC 8785/JCS. Signing callers must never silently
/// substitute a value when canonicalization fails.
pub fn canonicalize_json(value: &Value) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(value)
}
