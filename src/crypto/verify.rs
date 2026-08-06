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

/// PallaSync v2 signs SHA-256(JCS(record without `signature`)).
pub fn verify_signed_json(
    public_key_b64: &str,
    signature_b64: &str,
    value: &serde_json::Value,
) -> Result<bool, String> {
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or_else(|| "Signed value must be a JSON object".to_string())?
        .remove("signature");
    let canonical = canonicalize_json(&unsigned).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(canonical);
    verify_signature(public_key_b64, signature_b64, &digest).map_err(str::to_string)
}
