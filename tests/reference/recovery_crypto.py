"""Independent §7.11 recovery cryptography for conformance tests only.

No Rust/JNI implementation is imported. These Python buffers are not protected
production storage. Test callers must not supply user recovery material.
"""
import hmac
import struct
import unicodedata

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.signing import SigningKey
from protocol import b64, decode, digest, jcs, object_hash, root_keys, share_commitment, strict_loads, verify

MAX_PACKAGE = 4_194_304
BUCKETS = (1024, 4096, 16384, 65536, 262144, 1048576)


def associated(value, kind, removed):
    return jcs({**{k: v for k, v in value.items() if k not in removed}, "type": kind})


def unwrap_share(record, rswk, expected_admin):
    if record["admin_public_key"] != expected_admin or len(rswk) != 32:
        raise ValueError("C_RECOVERY_SET_MISMATCH")
    verify(record, decode(expected_admin, 32), b"PALLASYNC-RECOVERY-SHARE-v3\0")
    raw = crypto_aead_xchacha20poly1305_ietf_decrypt(
        decode(record["encrypted_share"], 48),
        associated(record, "PALLASYNC-RECOVERY-SHARE-AAD-v3",
                   ("encrypted_share", "share_wrap_nonce", "signature", "ext")),
        decode(record["share_wrap_nonce"], 24), rswk)
    expected = share_commitment(record["recovery_set_id"], record["share_index"], raw)
    if not hmac.compare_digest(expected, record["share_commitment"]):
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    return record["share_index"], raw


def offline_wrap_key(package, credential):
    envelope, record = package["offline_key_envelope"], package["record"]
    fields = {"type", "version", "recovery_set_id", "recovery_share_id", "holder_instance_id",
              "share_wrap_key_id", "kdf", "argon2_version", "memory_kib", "iterations",
              "parallelism", "salt", "key_nonce", "encrypted_key"}
    if set(envelope) != fields or record["holder_kind"] != "offline":
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    constants = {"type": "PALLASYNC-OFFLINE-SHARE-KEY-v3", "version": "3.0", "kdf": "argon2id",
                 "argon2_version": 19, "memory_kib": 65536, "iterations": 3, "parallelism": 1}
    if any(envelope[k] != v or type(envelope[k]) is not type(v) for k, v in constants.items()):
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    for key in ("recovery_set_id", "recovery_share_id", "holder_instance_id", "share_wrap_key_id"):
        if envelope[key] != record[key]:
            raise ValueError("C_RECOVERY_SET_MISMATCH")
    normalized = unicodedata.normalize("NFKD", credential)
    if not normalized:
        raise ValueError("C_RECOVERY_WRAP_KEY_UNAVAILABLE")
    key = Argon2id(salt=decode(envelope["salt"], 16), length=32, iterations=3,
                  lanes=1, memory_cost=65536).derive(normalized.encode("utf-8"))
    return crypto_aead_xchacha20poly1305_ietf_decrypt(
        decode(envelope["encrypted_key"], 48),
        jcs({k: v for k, v in envelope.items() if k not in ("encrypted_key", "key_nonce")}),
        decode(envelope["key_nonce"], 24), key)


def open_blob_identity(blob, rms, expected_admin):
    frame = crypto_aead_xchacha20poly1305_ietf_decrypt(
        decode(blob["encrypted_blob"]),
        associated(blob, "PALLASYNC-RECOVERY-BLOB-AAD-v3", ("encrypted_blob", "blob_nonce")),
        decode(blob["blob_nonce"], 24), rms)
    if len(frame) not in BUCKETS:
        raise ValueError("C_RECOVERY_BLOB_INVALID")
    length = struct.unpack(">I", frame[:4])[0]
    if length > len(frame) - 4:
        raise ValueError("C_RECOVERY_BLOB_INVALID")
    body = frame[4:4 + length]
    plaintext = strict_loads(body, BUCKETS[-1])
    if set(plaintext) != {"mnemonic", "passphrase", "created_at_ms", "recovery_set_id",
                         "recovery_secret_fingerprint", "chain_id", "generation"} or jcs(plaintext) != body:
        raise ValueError("C_RECOVERY_BLOB_INVALID")
    for field in ("mnemonic", "passphrase"):
        if unicodedata.normalize("NFKD", plaintext[field]) != plaintext[field]:
            raise ValueError("C_RECOVERY_BLOB_INVALID")
    for field in ("created_at_ms", "recovery_set_id", "recovery_secret_fingerprint", "chain_id", "generation"):
        if plaintext[field] != blob[field]:
            raise ValueError("C_RECOVERY_SET_MISMATCH")
    fingerprint = b64(digest(b"PALLASYNC-RECOVERY-SECRET-FP-v3\0" + jcs(
        {"mnemonic": plaintext["mnemonic"], "passphrase": plaintext["passphrase"]})))
    roots = root_keys(plaintext["mnemonic"], plaintext["passphrase"])
    admin = b64(bytes(SigningKey(roots["admin_seed"]).verify_key))
    chain = b64(roots["chain_id_digest"])
    if not hmac.compare_digest(fingerprint, blob["recovery_secret_fingerprint"]) or admin != expected_admin or chain != blob["chain_id"]:
        raise ValueError("C_RECOVERY_ROOT_MISMATCH")
    return {"chain_id": chain, "admin_public_key": admin}


def verify_package_bindings(package, expected_admin):
    """Validate public schemas/ancestry before the independent crypto/binding check."""
    from recovery_artifacts import package as validate_artifact
    validate_artifact(package, expected_admin)
    if set(package) != {"type", "version", "manifest", "status_chain", "record", "blob", "offline_key_envelope"}:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    if package["type"] != "PALLASYNC-RECOVERY-PACKAGE-v3" or package["version"] != "3.0" or len(jcs(package)) > MAX_PACKAGE:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    manifest, record, blob = package["manifest"], package["record"], package["blob"]
    verify(manifest, decode(expected_admin, 32), b"PALLASYNC-RECOVERY-SET-v3\0")
    verify(record, decode(expected_admin, 32), b"PALLASYNC-RECOVERY-SHARE-v3\0")
    if manifest["admin_public_key"] != expected_admin or record["admin_public_key"] != expected_admin:
        raise ValueError("C_RECOVERY_SET_MISMATCH")
    if manifest["profile"] != "shamir-gf256-aes/1" or not 2 <= manifest["threshold"] < manifest["total_shares"] <= 255:
        raise ValueError("C_RECOVERY_PARAMETER_INVALID")
    for field in ("chain_id", "generation", "recovery_set_id", "threshold", "total_shares", "recovery_secret_fingerprint", "created_at_ms"):
        if not manifest[field] == record[field] == blob[field]:
            raise ValueError("C_RECOVERY_SET_MISMATCH")
    if record["set_manifest_hash"] != object_hash(manifest) or not manifest["recovery_blob_hash"] == record["recovery_blob_hash"] == object_hash(blob):
        raise ValueError("C_RECOVERY_SET_MISMATCH")
    holders = manifest["holders"]
    if len(holders) != manifest["total_shares"] or [h["share_index"] for h in holders] != list(range(1, len(holders) + 1)):
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    for field in ("holder_instance_id", "recovery_share_id"):
        if len({h[field] for h in holders}) != len(holders):
            raise ValueError("C_RECOVERY_SHARE_ALREADY_USED")
    holder = holders[record["share_index"] - 1]
    if any(record[k] != v for k, v in holder.items()):
        raise ValueError("C_RECOVERY_SET_MISMATCH")
    statuses = package["status_chain"]
    if not statuses:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    transitions = {"prepared": {"active", "retired", "compromised"}, "active": {"retired", "compromised"},
                   "retired": {"compromised"}, "compromised": set()}
    previous = None
    for index, status in enumerate(statuses, 1):
        verify(status, decode(expected_admin, 32), b"PALLASYNC-RECOVERY-STATUS-v3\0")
        if status["status_seq"] != index or status["recovery_set_id"] != manifest["recovery_set_id"] or status["set_manifest_hash"] != object_hash(manifest):
            raise ValueError("C_RECOVERY_SET_MISMATCH")
        if status["previous_status_hash"] != (None if previous is None else object_hash(previous)):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        if (previous is None and status["state"] != "prepared") or (previous is not None and status["state"] not in transitions[previous["state"]]):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        if status["replacement_set_id"] is not None and status["state"] not in ("retired", "compromised"):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        previous = status
    if (record["holder_kind"] == "device") != (package["offline_key_envelope"] is None):
        raise ValueError("C_RECOVERY_SHARE_INVALID")

MAX_PORTABLE = 5 + ((MAX_PACKAGE + 2) // 3) * 4


def portable(package, expected_admin):
    verify_package_bindings(package, expected_admin)
    body = jcs(package)
    if len(body) > MAX_PACKAGE:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    return "PSR3:" + b64(body)


def parse_portable(encoded, expected_admin):
    if not isinstance(encoded, str) or not encoded.startswith("PSR3:") or len(encoded) > MAX_PORTABLE:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    body = decode(encoded[5:])
    package = strict_loads(body, MAX_PACKAGE)
    if jcs(package) != body:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    verify_package_bindings(package, expected_admin)
    return package


def fragments(package, expected_admin, part_bytes):
    if type(part_bytes) is not int or part_bytes <= 0:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    encoded = portable(package, expected_admin)
    count = (len(encoded) + part_bytes - 1) // part_bytes
    if count > 4096:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    checksum = b64(digest(encoded.encode("ascii")))
    return [{"package_hash": checksum, "part_index": index + 1, "part_count": count,
             "data": encoded[index * part_bytes:(index + 1) * part_bytes]} for index in range(count)]


def assemble_fragments(items, expected_admin):
    known_hash, count, parts, size = None, None, {}, 0
    for item in items:
        if set(item) != {"package_hash", "part_index", "part_count", "data"}:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        index, length, data = item["part_index"], item["part_count"], item["data"]
        if (type(index) is not int or type(length) is not int or not 1 <= index <= length <= 4096
                or not isinstance(data, str) or not data.isascii()):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        decode(item["package_hash"], 32)
        if known_hash is not None and (known_hash != item["package_hash"] or count != length):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        known_hash, count = item["package_hash"], length
        if index in parts:
            if parts[index] != data:
                raise ValueError("C_RECOVERY_SHARE_INVALID")
        else:
            size += len(data)
            if size > MAX_PORTABLE:
                raise ValueError("C_RECOVERY_SHARE_INVALID")
            parts[index] = data
    if not parts or len(parts) != count:
        return None
    encoded = "".join(parts[index] for index in range(1, count + 1))
    if not hmac.compare_digest(b64(digest(encoded.encode("ascii"))), known_hash):
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    return parse_portable(encoded, expected_admin)
