"""Independent §18.1 enrollment transcript/SAS; public results, no Rust/JNI reuse.

The caller must first authenticate the physical QR and verify its selected history.
Python key objects are test-only and do not claim production zeroization/storage.
"""
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from protocol import decode, jcs, object_hash, verify

OFFER_FIELDS = frozenset(("protocol", "relay_origin", "chain_id", "generation", "parameters_hash",
    "epoch_hash", "request_id", "offer_nonce", "expires_at_ms", "admin_public_key",
    "approver_device_id", "approver_device_public_key", "approver_device_kex_public_key", "approver_device_record_hash"))


def sas(private, offer, request, role):
    if set(offer) != OFFER_FIELDS or offer["protocol"] != "pallasync/3" or role not in ("approver", "subject"):
        raise ValueError("C_SCHEMA_VIOLATION")
    if any(request.get(field) != offer[field] for field in ("request_id", "chain_id", "generation", "offer_nonce")):
        raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
    verify(request, decode(request["device_public_key"], 32), b"PALLASYNC-ENROLL-REQUEST-v3\0")
    approver = decode(offer["approver_device_kex_public_key"], 32)
    subject = decode(request["device_kex_public_key"], 32)
    if any(int.from_bytes(key, "little") >= 2**255 - 19 for key in (approver, subject)):
        raise ValueError("C_SCHEMA_VIOLATION")
    own, other = (approver, subject) if role == "approver" else (subject, approver)
    if private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) != own:
        raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(other))
    except ValueError as error:
        raise ValueError("C_SCHEMA_VIOLATION") from error
    if not any(shared):
        raise ValueError("C_SCHEMA_VIOLATION")
    transcript = jcs({"offer": offer, "request_hash": object_hash(request)})
    return hashlib.sha256(b"PALLASYNC-ENROLL-SAS-v3\0" + shared + transcript).digest()[:6].hex()
