"""Independent §§7.12/17.3/17.9 public-evidence verifier (no Rust/JNI calls)."""
import struct
import uuid
from dataclasses import dataclass
from protocol import MAX_INTEGER, b64, decode, digest, jcs, object_hash, verify


def exact(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError("C_SCHEMA_VIOLATION")


def integer(value, positive=False):
    if type(value) is not int or not (1 if positive else 0) <= value <= MAX_INTEGER:
        raise ValueError("C_SCHEMA_VIOLATION")


def identity(value):
    parsed = uuid.UUID(value)
    if parsed.version != 4 or str(parsed) != value:
        raise ValueError("C_SCHEMA_VIOLATION")
    return parsed.bytes


@dataclass(frozen=True)
class Pin:
    chain: str
    log: str
    public_key: bytes

    def signed(self, value, context):
        if (value["chain_id"] != self.chain or value["log_id"] != self.log
                or value["relay_key_id"] != b64(digest(self.public_key))):
            raise ValueError("C_RELAY_KEY_MISMATCH")
        verify(value, self.public_key, context, "relay_signature")


def data_zero(chain, log):
    return b64(digest(b"PALLASYNC-LOG-v3\0" + decode(chain,32) + identity(log)))


def data_link(previous, entry):
    mandatory = {"relay_seq", "received_at_ms", "kind", "object"}
    expected = mandatory | ({"committed_at_ms"} if entry["kind"] == "epoch" else set())
    if set(entry) != expected or entry["kind"] not in {"parameters","device","epoch","envelope","compaction","admin","record"}:
        raise ValueError("C_SCHEMA_VIOLATION")
    integer(entry["relay_seq"], True)
    integer(entry["received_at_ms"])
    if entry["kind"] == "epoch" and entry["received_at_ms"] != entry["committed_at_ms"]:
        raise ValueError("C_SCHEMA_VIOLATION")
    return b64(digest(decode(previous,32) + struct.pack(">Q",entry["relay_seq"]) + digest(jcs(entry))))


def transparency_zero(chain, transparency, public_key):
    return b64(digest(b"PALLASYNC-TRANSPARENCY-v3\0" + decode(chain,32) + identity(transparency) + digest(public_key)))


def transparency_link(previous, entry, pin):
    exact(entry, "type version transparency_id entry_index chain_id log_id relay_key_id operation object_hash relay_seq resulting_head_hash previous_transparency_hash timestamp code relay_signature")
    if entry["type"] != "PALLASYNC-TRANSPARENCY-ENTRY-v3" or entry["version"] != "3.0":
        raise ValueError("C_SCHEMA_VIOLATION")
    identity(entry["transparency_id"])
    integer(entry["entry_index"], True)
    integer(entry["timestamp"])
    decode(entry["object_hash"],32)
    decode(entry["resulting_head_hash"],32)
    if entry["relay_seq"] is not None:
        integer(entry["relay_seq"], True)
    if entry["operation"] not in {"accept","reject","prune","delete","migrate"}:
        raise ValueError("C_TRANSPARENCY_INVALID")
    if entry["operation"] == "accept":
        if entry["code"] is not None:
            raise ValueError("C_TRANSPARENCY_INVALID")
    elif entry["relay_seq"] is not None or (entry["operation"] != "reject" and entry["code"] is not None):
        raise ValueError("C_TRANSPARENCY_INVALID")
    pin.signed(entry,b"PALLASYNC-TRANSPARENCY-ENTRY-v3\0")
    if previous != entry["previous_transparency_hash"]:
        raise ValueError("C_TRANSPARENCY_INVALID")
    return b64(digest(b"PALLASYNC-TRANSPARENCY-LINK-v3\0" + decode(previous,32)
                      + struct.pack(">Q",entry["entry_index"]) + digest(jcs(entry))))


def receipt(receipt, obj, entry, pin, transparency=None):
    exact(receipt, "type version receipt_id chain_id log_id relay_key_id relay_seq object_hash entry_hash previous_head_hash resulting_head_hash received_at_ms transparency_id transparency_index transparency_hash relay_signature")
    if receipt["type"] != "PALLASYNC-UPLOAD-RECEIPT-v3" or receipt["version"] != "3.0":
        raise ValueError("C_SCHEMA_VIOLATION")
    for name in ("receipt_id","log_id","transparency_id"):
        identity(receipt[name])
    for name in ("chain_id","relay_key_id","object_hash","previous_head_hash","resulting_head_hash","transparency_hash"):
        decode(receipt[name],32)
    integer(receipt["received_at_ms"])
    integer(receipt["transparency_index"],True)
    pin.signed(receipt,b"PALLASYNC-UPLOAD-RECEIPT-v3\0")
    if obj["chain_id"] != pin.chain or object_hash(obj) != receipt["object_hash"]:
        raise ValueError("C_ACCEPTANCE_UNPROVEN")
    if entry is None:
        if receipt["relay_seq"] is not None or receipt["entry_hash"] is not None or receipt["previous_head_hash"] != receipt["resulting_head_hash"]:
            raise ValueError("C_ACCEPTANCE_UNPROVEN")
    else:
        integer(receipt["relay_seq"],True)
        decode(receipt["entry_hash"],32)
        if (obj != entry["object"] or receipt["relay_seq"] != entry["relay_seq"]
                or receipt["received_at_ms"] != entry["received_at_ms"]
                or object_hash(entry) != receipt["entry_hash"]
                or data_link(receipt["previous_head_hash"],entry) != receipt["resulting_head_hash"]):
            raise ValueError("C_ACCEPTANCE_UNPROVEN")
    if transparency is not None:
        for left,right in (("transparency_id","transparency_id"),("transparency_index","entry_index"),("object_hash","object_hash"),("relay_seq","relay_seq"),("resulting_head_hash","resulting_head_hash")):
            if receipt[left] != transparency[right]:
                raise ValueError("C_TRANSPARENCY_INVALID")
        if (transparency["operation"] != "accept" or transparency_link(transparency["previous_transparency_hash"],transparency,pin) != receipt["transparency_hash"]):
            raise ValueError("C_TRANSPARENCY_INVALID")


def ledger_hash(ledger):
    exact(ledger,"chain_id deletion_id authorized_parameters_hash authorized_epoch_hash authorization_hash requested_at_ms completed_at_ms assurance delete_after_ms receipt_hash")
    identity(ledger["deletion_id"])
    for name in ("chain_id","authorized_parameters_hash","authorized_epoch_hash","authorization_hash","receipt_hash"):
        decode(ledger[name],32)
    integer(ledger["requested_at_ms"])
    if ledger["completed_at_ms"] is not None:
        integer(ledger["completed_at_ms"])
        if ledger["completed_at_ms"] < ledger["requested_at_ms"]:
            raise ValueError("C_DELETION_UNVERIFIED")
    if object_hash({key:val for key,val in ledger.items() if key != "receipt_hash"}) != ledger["receipt_hash"]:
        raise ValueError("C_DELETION_UNVERIFIED")
    return ledger["receipt_hash"]
