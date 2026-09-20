use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::crypto::jcs::canonicalize_json;

pub fn verify_signature(
    public_key_b64: &str,
    signature_b64: &str,
    message: &[u8],
) -> Result<bool, &'static str> {
    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(public_key_b64)
        .map_err(|_| "Invalid base64 in public key")?;
    if pub_key_bytes.len() != 32 {
        return Err("Public key must be 32 bytes");
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| "Invalid base64 in signature")?;
    if sig_bytes.len() != 64 {
        return Err("Signature must be 64 bytes");
    }

    let pub_key = VerifyingKey::from_bytes(pub_key_bytes.as_slice().try_into().unwrap())
        .map_err(|_| "Invalid Ed25519 public key format")?;

    let signature = Signature::from_bytes(sig_bytes.as_slice().try_into().unwrap());

    Ok(pub_key.verify(message, &signature).is_ok())
}

pub const CTX_SYNC_RECORD: &[u8] = b"PALLASYNC-SYNC-RECORD-v2.1\0";
pub const CTX_DEVICE_RECORD: &[u8] = b"PALLASYNC-DEVICE-RECORD-v2.1\0";
pub const CTX_INVITATION: &[u8] = b"PALLASYNC-INVITATION-v2.1\0";
pub const CTX_CAPABILITY: &[u8] = b"PALLASYNC-CAPABILITY-v2.1\0";
pub const CTX_ADMIN_OP: &[u8] = b"PALLASYNC-ADMIN-OP-v2.1\0";

/// PallaSync 2.1 signs `context || JCS(record without signature)` directly with Ed25519.
pub fn verify_signed_json(
    public_key_b64: &str,
    signature_b64: &str,
    value: &serde_json::Value,
    context: &[u8],
) -> Result<bool, String> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| "Signed value must be a JSON object".to_string())?
        .remove("signature");
    let canonical = canonicalize_json(&unsigned).map_err(|error| error.to_string())?;

    let mut message = Vec::with_capacity(context.len() + canonical.len());
    message.extend_from_slice(context);
    message.extend_from_slice(&canonical);

    // First try v2.1 context-string direct signing
    if let Ok(true) = verify_signature(public_key_b64, signature_b64, &message) {
        return Ok(true);
    }

    // Fallback: Legacy v2.0 pre-hashed signature (SHA-256(JCS))
    let digest = Sha256::digest(&canonical);
    verify_signature(public_key_b64, signature_b64, &digest).map_err(str::to_string)
}
