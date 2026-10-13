"""Independent §7.11.5 local transfer primitives for interoperability tests.

No Rust/JNI imports, relay transport, production secret storage or Python memory
erasure guarantee. Public schemas are checked here; handlers enforce operation stages.
"""
import hmac
import secrets
import time
import uuid
from functools import wraps
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization
from nacl.signing import SigningKey
from crypto_client import hpke_open, hpke_seal
from protocol import MAX_INTEGER, b64, decode, digest, jcs, object_hash, share_commitment, signed, strict_loads, verify
from recovery_artifacts import blob, extension, field, manifest, package, require, shape, share

MAX_TRANSFER = 4_194_304
CODES = frozenset(strict_loads((Path(__file__).parent/"fixtures/error-catalogue-v3.json").read_bytes())["codes"])
DESCRIPTOR_FIELDS = {"type", "version", "ceremony_id", "session_id", "endpoint_id", "side", "role", "purpose",
    "chain_id", "generation", "recovery_set_id", "set_manifest_hash", "session_nonce",
    "session_signing_public_key", "session_kex_public_key", "ttl_ms", "signature"}
PACKET_FIELDS = {"type", "version", "transfer_id", "session_id", "sender_descriptor_hash",
    "recipient_descriptor_hash", "message_seq", "message_kind", "enc", "ciphertext", "signature"}
BINDINGS = ("ceremony_id", "session_id", "purpose", "chain_id", "generation", "recovery_set_id", "set_manifest_hash")


def x_key(encoded):
    value = decode(encoded, 32)
    if int.from_bytes(value, "little") >= (1 << 255) - 19:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    return value


def descriptor_shape(value):
    if set(value) not in (DESCRIPTOR_FIELDS, DESCRIPTOR_FIELDS | {"ext"}) or value["type"] != "PALLASYNC-RECOVERY-SESSION-v3" or value["version"] != "3.0" or value["ttl_ms"] != 300000 or type(value["ttl_ms"]) is not int:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    if "ext" in value:
        extension(value["ext"])
    if (value["side"] not in ("initiator", "responder") or value["role"] not in ("dealer", "holder", "reader", "collector")
            or value["purpose"] not in ("create", "rotate", "recover", "disable")
            or type(value["generation"]) is not int or not 0 <= value["generation"] < 1 << 32):
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    for field in ("ceremony_id", "session_id", "endpoint_id", "recovery_set_id"):
        parsed = uuid.UUID(value[field])
        if parsed.version != 4 or parsed.variant != uuid.RFC_4122 or str(parsed) != value[field]:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
    for field in ("chain_id", "set_manifest_hash", "session_nonce", "session_signing_public_key"):
        decode(value[field], 32)
    x_key(value["session_kex_public_key"])


def direction(sender, recipient, kind):
    pair = sender["role"], recipient["role"]
    allowed = ((kind in ("distribute_share", "signed_share") and pair[0] == "dealer" and pair[1] in ("holder", "reader"))
        or (kind in ("wrap_proposal", "persisted") and pair[0] in ("holder", "reader") and pair[1] == "dealer")
        or (kind == "collect_share" and pair[0] in ("holder", "reader") and pair[1] == "collector")
        or kind == "result")
    if not allowed:
        raise ValueError("C_RECOVERY_SHARE_INVALID")


def abort_on_failure(method):
    @wraps(method)
    def checked(self, *args, **kwargs):
        try:
            return method(self,*args,**kwargs)
        except BaseException as failure:
            if method.__name__ != "receive" or not isinstance(failure,ValueError) or str(failure) != "C_MISSING_DEPENDENCY":
                self.close()
            raise
    return checked


def payload_valid(kind, payload, descriptor, admin):
    if kind == "distribute_share":
        shape(payload,{"manifest":"object","blob":"object","share_index":"int","raw_share":"b32"})
        m, b = payload["manifest"],payload["blob"]
        manifest(m,admin)
        blob(b)
        require(object_hash(m) == descriptor["set_manifest_hash"] and object_hash(b) == m["recovery_blob_hash"]
            and 1 <= payload["share_index"] <= m["total_shares"])
        require(all(m[key] == b[key] for key in ("chain_id","generation","recovery_set_id","threshold","total_shares","recovery_secret_fingerprint","created_at_ms")))
        holder = m["holders"][payload["share_index"]-1]
        require(share_commitment(m["recovery_set_id"],payload["share_index"],decode(payload["raw_share"],32)) == holder["share_commitment"])
    elif kind in ("wrap_proposal","signed_share"):
        shape(payload,{"record":"object"})
        record = payload["record"]
        share(record,admin,kind == "signed_share")
        require(record["set_manifest_hash"] == descriptor["set_manifest_hash"]
            and all(record[key] == descriptor[key] for key in ("chain_id","generation","recovery_set_id")))
    elif kind == "persisted":
        require(type(payload) is dict and set(payload) == {"recovery_share_id","record_hash","verified"})
        require(field(payload["recovery_share_id"],"uuid") and field(payload["record_hash"],"b32") and type(payload["verified"]) is bool)
    elif kind == "collect_share":
        shape(payload,{"package":"object","raw_share":"b32"})
        artifact = package(payload["package"],admin)
        record = artifact["record"]
        require(object_hash(artifact["manifest"]) == descriptor["set_manifest_hash"]
            and share_commitment(record["recovery_set_id"],record["share_index"],decode(payload["raw_share"],32)) == record["share_commitment"])
    elif kind == "result":
        require(type(payload) is dict and set(payload) == {"result","code"} and payload["result"] in ("succeeded","failed","cancelled"))
        code = payload["code"]
        require(code is None or (isinstance(code,str) and code in CODES and code.isascii() and len(code) <= 64))
    else:
        require(False)


class RecoveryPair:
    def __init__(self, manifest, known_admin, ceremony_id, session_id, side, role, purpose):
        verify(manifest, decode(known_admin, 32), b"PALLASYNC-RECOVERY-SET-v3\0")
        if manifest["admin_public_key"] != known_admin:
            raise ValueError("C_RECOVERY_SET_MISMATCH")
        if side not in ("initiator", "responder") or role not in ("dealer", "holder", "reader", "collector") or purpose not in ("create", "rotate", "recover", "disable"):
            raise ValueError("C_RECOVERY_PARAMETER_INVALID")
        self.signing = SigningKey.generate()
        self.kex = X25519PrivateKey.generate()
        self.peer = None
        self.admin = known_admin
        self.confirmed = False
        self.closed = False
        self.deadline = time.monotonic() + 300
        self.sent = self.received = 0
        self.outgoing, self.incoming, self.ids = {}, {}, set()
        public = self.kex.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.descriptor = signed({"type": "PALLASYNC-RECOVERY-SESSION-v3", "version": "3.0",
            "ceremony_id": ceremony_id, "session_id": session_id, "endpoint_id": str(uuid.uuid4()),
            "side": side, "role": role, "purpose": purpose, "chain_id": manifest["chain_id"],
            "generation": manifest["generation"], "recovery_set_id": manifest["recovery_set_id"],
            "set_manifest_hash": object_hash(manifest), "session_nonce": b64(secrets.token_bytes(32)),
            "session_signing_public_key": b64(bytes(self.signing.verify_key)), "session_kex_public_key": b64(public),
            "ttl_ms": 300000}, self.signing, b"PALLASYNC-RECOVERY-SESSION-v3\0")

    def live(self):
        if self.closed or time.monotonic() >= self.deadline:
            self.close()
            raise ValueError("C_RECOVERY_SESSION_EXPIRED")

    def close(self):
        self.closed = True
        self.signing = self.kex = None
        self.outgoing.clear()
        self.incoming.clear()
        self.ids.clear()

    @abort_on_failure
    def bind(self, peer):
        self.live()
        descriptor_shape(peer)
        verify(peer, decode(peer["session_signing_public_key"], 32), b"PALLASYNC-RECOVERY-SESSION-v3\0")
        if any(peer[k] != self.descriptor[k] for k in BINDINGS) or peer["side"] == self.descriptor["side"]:
            raise ValueError("C_RECOVERY_SET_MISMATCH")
        for field in ("endpoint_id", "session_signing_public_key", "session_kex_public_key"):
            if peer[field] == self.descriptor[field]:
                raise ValueError("C_RECOVERY_SHARE_INVALID")
        if self.peer is not None and peer != self.peer:
            self.close()
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        if self.peer is None:
            self.deadline = time.monotonic() + 300
        self.peer = peer
        return self.sas()

    def sas(self):
        self.live()
        if self.peer is None:
            raise ValueError("C_RECOVERY_AUTH_REQUIRED")
        dh = self.kex.exchange(X25519PublicKey.from_public_bytes(x_key(self.peer["session_kex_public_key"])))
        if not any(dh):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        first, second = (self.descriptor, self.peer) if self.descriptor["side"] == "initiator" else (self.peer, self.descriptor)
        encoded = digest(b"PALLASYNC-RECOVERY-SAS-v3\0" + dh + jcs({"initiator": first, "responder": second}))[:6].hex()
        return " ".join(encoded[index:index + 4] for index in (0, 4, 8))

    def confirm(self, displayed, explicit):
        self.live()
        if not explicit or not hmac.compare_digest(displayed, self.sas()):
            self.close()
            raise ValueError("C_RECOVERY_AUTH_REQUIRED" if not explicit else "C_RECOVERY_SAS_MISMATCH")
        self.confirmed = True

    @abort_on_failure
    def seal(self, kind, payload):
        self.live()
        if not self.confirmed:
            raise ValueError("C_RECOVERY_AUTH_REQUIRED")
        direction(self.descriptor, self.peer, kind)
        payload_valid(kind,payload,self.descriptor,self.admin)
        require(self.sent < MAX_INTEGER)
        header = {"type": "PALLASYNC-RECOVERY-TRANSFER-v3", "version": "3.0", "transfer_id": str(uuid.uuid4()),
            "session_id": self.descriptor["session_id"], "sender_descriptor_hash": object_hash(self.descriptor),
            "recipient_descriptor_hash": object_hash(self.peer), "message_seq": self.sent + 1, "message_kind": kind}
        plain, aad = jcs(payload), jcs(header)
        if len(plain) > MAX_TRANSFER:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        enc, cipher = hpke_seal(x_key(self.peer["session_kex_public_key"]), plain,
            b"PALLASYNC-RECOVERY-TRANSFER-HPKE-v3\0" + aad, aad)
        packet = signed({**header, "enc": b64(enc), "ciphertext": b64(cipher)}, self.signing, b"PALLASYNC-RECOVERY-TRANSFER-v3\0")
        if len(jcs(packet)) > MAX_TRANSFER:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        self.sent += 1
        self.outgoing[self.sent] = packet
        return packet

    @abort_on_failure
    def receive(self, raw, process):
        self.live()
        if not self.confirmed:
            raise ValueError("C_RECOVERY_AUTH_REQUIRED")
        packet = strict_loads(raw, MAX_TRANSFER)
        if set(packet) not in (PACKET_FIELDS,PACKET_FIELDS | {"ext"}) or packet["type"] != "PALLASYNC-RECOVERY-TRANSFER-v3" or packet["version"] != "3.0" or jcs(packet) != raw:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        require(field(packet["transfer_id"],"uuid"))
        if "ext" in packet:
            extension(packet["ext"])
        if (packet["session_id"] != self.descriptor["session_id"] or packet["sender_descriptor_hash"] != object_hash(self.peer)
                or packet["recipient_descriptor_hash"] != object_hash(self.descriptor)):
            raise ValueError("C_RECOVERY_SET_MISMATCH")
        verify(packet, decode(self.peer["session_signing_public_key"], 32), b"PALLASYNC-RECOVERY-TRANSFER-v3\0")
        seq, checksum = packet["message_seq"], digest(raw)
        if type(seq) is not int or not 1 <= seq <= (1 << 53) - 1:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        if seq in self.incoming:
            previous, public = self.incoming[seq]
            if not hmac.compare_digest(previous, checksum):
                raise ValueError("C_RECOVERY_SHARE_INVALID")
            return public
        direction(self.peer, self.descriptor, packet["message_kind"])
        if packet["transfer_id"] in self.ids:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        if seq > self.received + 1:
            raise ValueError("C_MISSING_DEPENDENCY")
        if seq != self.received + 1:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        header = {k: v for k, v in packet.items() if k not in ("enc", "ciphertext", "signature")}
        aad = jcs(header)
        plain = hpke_open(self.kex, x_key(packet["enc"]), decode(packet["ciphertext"]),
            b"PALLASYNC-RECOVERY-TRANSFER-HPKE-v3\0" + aad, aad)
        payload = strict_loads(plain, MAX_TRANSFER)
        if jcs(payload) != plain:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        payload_valid(packet["message_kind"],payload,self.descriptor,self.admin)
        public = process(packet["message_kind"], payload)
        self.received = seq
        self.ids.add(packet["transfer_id"])
        self.incoming[seq] = checksum, public
        return public
