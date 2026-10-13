"""Independent §§3/7.11 public recovery-artifact validation for test clients only.

No Rust/JNI code or server runtime is used. This validates schemas and signed
ancestry; it cannot prove physical independence or globally fresh offline status.
"""
import re
from nacl.exceptions import BadSignatureError
from protocol import MAX_INTEGER, decode, jcs, object_hash, strict_loads, verify

MAX_PACKAGE = 4_194_304
BUCKETS = (1024, 4096, 16384, 65536, 262144, 1048576)
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")
LABEL = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def require(condition):
    if not condition:
        raise ValueError("C_RECOVERY_SHARE_INVALID")


def verify_signed(value, key, context):
    try:
        verify(value, decode(key,32), context)
    except (ValueError, BadSignatureError):
        raise ValueError("C_RECOVERY_SHARE_INVALID") from None


def field(value, kind):
    if kind.endswith("?"):
        return value is None or field(value, kind[:-1])
    if kind == "int":
        return type(value) is int and 0 <= value <= MAX_INTEGER
    if kind == "u32":
        return type(value) is int and 0 <= value < 1 << 32
    if kind == "uuid":
        return isinstance(value, str) and UUID4.fullmatch(value) is not None
    if kind.startswith("b") and kind[1:].isdigit():
        return isinstance(value, str) and len(decode(value, int(kind[1:]))) == int(kind[1:])
    if kind == "array":
        return type(value) is list
    if kind == "object":
        return type(value) is dict
    return isinstance(value, str) and value in kind.split("|")


def extension(ext):
    require(type(ext) is dict and len(jcs(ext)) <= 1024)
    for name in ext:
        labels = name.split(".")
        require(len(name) <= 255 and len(labels) >= 3 and all(LABEL.fullmatch(part) for part in labels[:-1]) and NAME.fullmatch(labels[-1]))


def shape(value, fields, signed=False, allow_ext=False):
    require(type(value) is dict)
    expected = set(fields) | ({"signature"} if signed else set())
    require(set(value) == expected or ((signed or allow_ext) and set(value) == expected | {"ext"}))
    require(all(field(value[key], kind) for key, kind in fields.items()))
    if signed:
        decode(value["signature"], 64)
    if "ext" in value:
        extension(value["ext"])


def manifest(value, known_admin):
    shape(value, {"type":"PALLASYNC-RECOVERY-SET-v3", "version":"3.0", "profile":"shamir-gf256-aes/1",
        "chain_id":"b32", "generation":"u32", "recovery_set_id":"uuid", "threshold":"int", "total_shares":"int",
        "recovery_secret_fingerprint":"b32", "created_at_ms":"int", "admin_public_key":"b32", "recovery_blob_hash":"b32", "holders":"array"}, True)
    require(value["admin_public_key"] == known_admin and 2 <= value["threshold"] < value["total_shares"] <= 255)
    verify_signed(value, known_admin, b"PALLASYNC-RECOVERY-SET-v3\0")
    holders = value["holders"]
    require(len(holders) == value["total_shares"])
    for index, holder in enumerate(holders, 1):
        shape(holder, {"recovery_share_id":"uuid", "share_index":"int", "holder_kind":"device|offline",
            "holder_device_id":"uuid?", "holder_instance_id":"uuid", "share_commitment":"b32"})
        require(holder["share_index"] == index and (holder["holder_kind"] == "offline") == (holder["holder_device_id"] is None))
    for key in ("recovery_share_id", "holder_instance_id"):
        require(len({holder[key] for holder in holders}) == len(holders))


def status_chain(statuses, set_manifest, known_head=None):
    require(type(statuses) is list and bool(statuses))
    previous, found = None, known_head is None
    permitted = {("prepared","active"), ("prepared","retired"), ("prepared","compromised"),
        ("active","retired"), ("active","compromised"), ("retired","compromised")}
    for value in statuses:
        shape(value, {"type":"PALLASYNC-RECOVERY-STATUS-v3", "version":"3.0", "recovery_set_id":"uuid",
            "set_manifest_hash":"b32", "status_seq":"int", "state":"prepared|active|retired|compromised",
            "previous_status_hash":"b32?", "replacement_set_id":"uuid?", "created_at_ms":"int"}, True)
        require(value["recovery_set_id"] == set_manifest["recovery_set_id"] and value["set_manifest_hash"] == object_hash(set_manifest))
        require(value["replacement_set_id"] is None or value["state"] in ("retired","compromised"))
        if previous is None:
            require(value["status_seq"] == 1 and value["previous_status_hash"] is None and value["state"] == "prepared")
        else:
            require(value["status_seq"] == previous["status_seq"] + 1 and value["previous_status_hash"] == object_hash(previous)
                and (previous["state"],value["state"]) in permitted)
        verify_signed(value, set_manifest["admin_public_key"], b"PALLASYNC-RECOVERY-STATUS-v3\0")
        found |= object_hash(value) == known_head
        previous = value
    require(found)


def share(value, known_admin, signed=True):
    shape(value, {"type":"PALLASYNC-RECOVERY-SHARE-v3", "version":"3.0", "recovery_share_id":"uuid", "recovery_set_id":"uuid",
        "chain_id":"b32", "generation":"u32", "threshold":"int", "total_shares":"int", "share_index":"int",
        "recovery_secret_fingerprint":"b32", "created_at_ms":"int", "holder_kind":"device|offline", "holder_device_id":"uuid?",
        "holder_instance_id":"uuid", "share_wrap_key_id":"uuid", "admin_public_key":"b32", "set_manifest_hash":"b32",
        "recovery_blob_hash":"b32", "share_commitment":"b32", "encrypted_share":"b48", "share_wrap_nonce":"b24",
        "share_wrap_key_protection":"os-keystore|hardware|webcrypto-nonextractable|passphrase-wrapped"}, signed, True)
    require(value["admin_public_key"] == known_admin and 2 <= value["threshold"] < value["total_shares"] <= 255
        and 1 <= value["share_index"] <= value["total_shares"])
    require((value["holder_kind"] == "offline") == (value["holder_device_id"] is None))
    require(value["holder_kind"] != "offline" or value["share_wrap_key_protection"] == "passphrase-wrapped")
    if signed:
        verify_signed(value, known_admin, b"PALLASYNC-RECOVERY-SHARE-v3\0")


def blob(value):
    # Variable ciphertext has a constrained bucket length rather than an enum.
    fields = {"type":"PALLASYNC-RECOVERY-BLOB-v3", "version":"3.0", "chain_id":"b32", "generation":"u32",
        "recovery_set_id":"uuid", "threshold":"int", "total_shares":"int", "recovery_secret_fingerprint":"b32",
        "created_at_ms":"int", "blob_nonce":"b24"}
    require(type(value) is dict and "encrypted_blob" in value)
    shape({key:item for key,item in value.items() if key != "encrypted_blob"}, fields)
    require(len(decode(value["encrypted_blob"])) in tuple(size + 16 for size in BUCKETS))
    require(2 <= value["threshold"] < value["total_shares"] <= 255)


def offline(value, record):
    shape(value, {"type":"PALLASYNC-OFFLINE-SHARE-KEY-v3", "version":"3.0", "recovery_set_id":"uuid",
        "recovery_share_id":"uuid", "holder_instance_id":"uuid", "share_wrap_key_id":"uuid", "kdf":"argon2id",
        "argon2_version":"int", "memory_kib":"int", "iterations":"int", "parallelism":"int", "salt":"b16", "key_nonce":"b24", "encrypted_key":"b48"})
    require((value["argon2_version"],value["memory_kib"],value["iterations"],value["parallelism"]) == (19,65536,3,1))
    require(all(value[key] == record[key] for key in ("recovery_set_id","recovery_share_id","holder_instance_id","share_wrap_key_id")))


def package(value, known_admin, known_head=None):
    strict_loads(jcs(value),MAX_PACKAGE)
    shape(value, {"type":"PALLASYNC-RECOVERY-PACKAGE-v3", "version":"3.0", "manifest":"object", "status_chain":"array",
        "record":"object", "blob":"object", "offline_key_envelope":"object?"})
    m, r, b = value["manifest"], value["record"], value["blob"]
    manifest(m,known_admin)
    status_chain(value["status_chain"],m,known_head)
    share(r,known_admin)
    blob(b)
    require(all(m[key] == r[key] == b[key] for key in ("chain_id","generation","recovery_set_id","threshold","total_shares","recovery_secret_fingerprint","created_at_ms")))
    require(r["set_manifest_hash"] == object_hash(m) and m["recovery_blob_hash"] == r["recovery_blob_hash"] == object_hash(b))
    holder = m["holders"][r["share_index"]-1]
    require(all(r[key] == item for key,item in holder.items()))
    if r["holder_kind"] == "offline":
        offline(value["offline_key_envelope"],r)
    else:
        require(value["offline_key_envelope"] is None)
    return value
