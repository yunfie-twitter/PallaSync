"""Independent §8.6 recovery audit allowlist. Test client only; never imported by the relay."""
import re
from protocol import MAX_INTEGER, decode, jcs

EVENTS = frozenset((
    "recovery_share_set_created", "recovery_share_set_rotated", "recovery_share_holder_added",
    "recovery_share_holder_removed", "recovery_ceremony_started", "recovery_ceremony_succeeded",
    "recovery_ceremony_failed", "recovery_share_lost", "recovery_share_compromised",
))
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z")


def require(condition):
    if not condition:
        raise ValueError("C_SCHEMA_VIOLATION")


def integer(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def validate(operation):
    require(type(operation) is dict and set(operation) == {
        "entity_id", "operation", "lamport", "created_at_ms", "context", "body"})
    require(isinstance(operation["entity_id"], str) and UUID4.fullmatch(operation["entity_id"]) is not None)
    require(operation["operation"] == "upsert" and operation["context"] == {}
            and type(operation["context"]) is dict and integer(operation["lamport"]) and integer(operation["created_at_ms"]))
    body = operation["body"]
    require(type(body) is dict and set(body) == {"event", "subject_id", "object_hash", "result", "ext"})
    require(isinstance(body["event"], str) and body["event"] in EVENTS
            and body["subject_id"] is None and body["object_hash"] is None
            and body["result"] in ("started", "succeeded", "failed", "blocked"))
    extension = body["ext"]
    require(type(extension) is dict and set(extension) == {"org.palleria.recovery"} and len(jcs(extension)) <= 1024)
    metadata = extension["org.palleria.recovery"]
    require(type(metadata) is dict and set(metadata) == {
        "recovery_set_id", "recovery_secret_fingerprint", "threshold", "total_shares", "holder_kind", "holder_counts"})
    require(isinstance(metadata["recovery_set_id"], str) and UUID4.fullmatch(metadata["recovery_set_id"]) is not None)
    decode(metadata["recovery_secret_fingerprint"], 32)
    threshold, total, counts = metadata["threshold"], metadata["total_shares"], metadata["holder_counts"]
    require(integer(threshold) and integer(total) and 2 <= threshold < total <= 255)
    require(type(counts) is dict and set(counts) == {"device", "offline"}
            and all(integer(value) for value in counts.values()) and counts["device"] + counts["offline"] == total)
    require(metadata["holder_kind"] in (None, "device", "offline"))
    if body["event"].startswith(("recovery_share_set_", "recovery_ceremony_")):
        require(metadata["holder_kind"] is None)


def validate_collection(collection, operations):
    if collection == "pallasync.audit/3":
        for operation in operations:
            body = operation.get("body", {}) if type(operation) is dict else {}
            event = body.get("event") if type(body) is dict else None
            if isinstance(event, str) and event.startswith("recovery_"):
                validate(operation)
