"""Independent PALLASYNC-3.0-R1 reference primitives, derived from the specification.

No Rust/JNI library is imported. This module is test infrastructure, not a protected
production holder; its fixed public-vector inputs must never be replaced by user keys.
"""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import unicodedata
import uuid
from dataclasses import dataclass, field
from fractions import Fraction

import galois
import rfc8785
from nacl.bindings import crypto_core_ed25519_is_valid_point
from nacl.signing import SigningKey, VerifyKey
from mnemonic import Mnemonic

MAX_INTEGER = (1 << 53) - 1
ED_ORDER = (1 << 252) + 27742317777372353535851937790883648493
GF = galois.GF(256, irreducible_poly=0x11B, primitive_element=3, compile="python-calculate")


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def decode(value, size=None):
    if not isinstance(value, str) or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in value):
        raise ValueError("C_SCHEMA_VIOLATION")
    data = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if b64(data) != value or (size is not None and len(data) != size):
        raise ValueError("C_SCHEMA_VIOLATION")
    return data


def strict_loads(data, ceiling=8_388_608):
    if len(data) > ceiling or data.startswith(b"\xef\xbb\xbf"):
        raise ValueError("C_SCHEMA_VIOLATION")

    def pairs(items):
        obj = {}
        for key, value in items:
            if key in obj:
                raise ValueError("C_SCHEMA_VIOLATION")
            obj[key] = value
        return obj

    def integer(text):
        if text.startswith("-") or int(text) > MAX_INTEGER:
            raise ValueError("C_SCHEMA_VIOLATION")
        return int(text)

    def invalid(_):
        raise ValueError("C_SCHEMA_VIOLATION")

    value = json.loads(data.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                       parse_int=integer, parse_float=invalid, parse_constant=invalid)

    def check(node, depth=0):
        if isinstance(node, str):
            node.encode("utf-8", errors="strict")
        elif isinstance(node, (dict, list)):
            if depth >= 32:
                raise ValueError("C_SCHEMA_VIOLATION")
            if isinstance(node, dict):
                for key, item in node.items():
                    check(key, depth + 1)
                    check(item, depth + 1)
            else:
                for item in node:
                    check(item, depth + 1)

    check(value)
    return value


def jcs(value):
    return rfc8785.dumps(value)


def digest(data):
    return hashlib.sha256(data).digest()


def object_hash(value):
    return b64(digest(jcs(value)))


def signed(value, key, context, member="signature"):
    value = {name: item for name, item in value.items() if name != member}
    result = dict(value)
    result[member] = b64(key.sign(context + jcs(value)).signature)
    verify(result, bytes(key.verify_key), context, member)
    return result


def verify(value, public_key, context, member="signature"):
    signature = decode(value[member], 64)
    if not crypto_core_ed25519_is_valid_point(public_key) or not crypto_core_ed25519_is_valid_point(signature[:32]):
        raise ValueError("C_SIGNATURE_INVALID")
    if int.from_bytes(signature[32:], "little") >= ED_ORDER:
        raise ValueError("C_SIGNATURE_INVALID")
    message = context + jcs({key: item for key, item in value.items() if key != member})
    VerifyKey(public_key).verify(message, signature)


def hkdf_extract(salt, material):
    return hmac.digest(salt, material, "sha256")


def hkdf_expand(prk, info, length):
    out, previous = bytearray(), b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        out.extend(previous)
    return bytes(out[:length])


def root_keys(mnemonic, passphrase=""):
    if len(mnemonic.split(" ")) != 24 or not Mnemonic("english").check(mnemonic):
        raise ValueError("C_RECOVERY_PARAMETER_INVALID")
    phrase = unicodedata.normalize("NFKD", mnemonic)
    passphrase = unicodedata.normalize("NFKD", passphrase)
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), ("mnemonic" + passphrase).encode(), 2048, 64)
    salt = digest(b"PALLASYNC-CHAIN-SALT-v3\0" + seed)
    chain = digest(b"PALLASYNC-CHAIN-ID-v3\0" + salt + seed)
    prk = hkdf_extract(salt, seed)
    return {"root_seed": seed, "chain_salt": salt, "chain_id_digest": chain, "prk": prk,
            "admin_seed": hkdf_expand(prk, b"PALLASYNC-v3\0admin-ed25519\0", 32),
            "recovery_kek": hkdf_expand(prk, b"PALLASYNC-v3\0recovery-kek\0", 32)}


def epoch_keys(chain_digest, epoch, secret):
    if len(secret) != 32 or not 0 <= epoch < 1 << 32:
        raise ValueError("C_SCHEMA_VIOLATION")
    prk = hkdf_extract(b"PALLASYNC-v3\0epoch\0" + chain_digest + struct.pack(">I", epoch), secret)
    result = {"epoch_prk": prk}
    for label in ("record", "device-meta", "collection-tag", "epoch-commitment"):
        result[label] = hkdf_expand(prk, b"PALLASYNC-v3\0" + label.encode() + b"\0", 32)
    return result


def share_commitment(set_id, index, raw):
    if not 1 <= index <= 255 or len(raw) != 32:
        raise ValueError("C_RECOVERY_SHARE_INVALID")
    return b64(digest(b"PALLASYNC-RECOVERY-SHARE-COMMIT-v3\0" + uuid.UUID(set_id).bytes + bytes([index]) + raw))


def split(secret, threshold, total, coefficients=None):
    if len(secret) != 32 or not 2 <= threshold < total <= 255:
        raise ValueError("C_RECOVERY_PARAMETER_INVALID")
    if coefficients is None:
        coefficients = [secrets.token_bytes(32) for _ in range(threshold - 1)]
    if len(coefficients) != threshold - 1 or any(len(c) != 32 for c in coefficients):
        raise ValueError("C_RECOVERY_PARAMETER_INVALID")
    polynomial = [GF(list(secret))] + [GF(list(c)) for c in coefficients]
    pieces = []
    for index in range(1, total + 1):
        value = polynomial[-1].copy()
        for coefficient in reversed(polynomial[:-1]):
            value = value * GF(index) + coefficient
        pieces.append((index, bytes(int(x) for x in value)))
    return pieces


def reconstruct(pieces, threshold, total):
    if not 2 <= threshold < total <= 255:
        raise ValueError("C_RECOVERY_PARAMETER_INVALID")
    distinct = {}
    for index, raw in pieces:
        if not 1 <= index <= total or len(raw) != 32:
            raise ValueError("C_RECOVERY_SHARE_INVALID")
        if index in distinct and not hmac.compare_digest(distinct[index], raw):
            raise ValueError("C_RECOVERY_SHARE_ALREADY_USED")
        distinct[index] = raw
    if len(distinct) < threshold:
        raise ValueError("C_RECOVERY_THRESHOLD_NOT_MET")
    basis = sorted(distinct.items())[:threshold]

    def interpolate(at):
        result = GF.Zeros(32)
        for xi, yi in basis:
            weight = GF(1)
            for xj, _ in basis:
                if xi != xj:
                    weight *= (GF(at) - GF(xj)) / (GF(xi) - GF(xj))
            result += GF(list(yi)) * weight
        return bytes(int(x) for x in result)

    for index, raw in sorted(distinct.items())[threshold:]:
        if not hmac.compare_digest(raw, interpolate(index)):
            raise ValueError("C_RECOVERY_SHARE_INVALID")
    return interpolate(0)


def order_between(lower, upper):
    def rational(key, default):
        if key is None:
            return default
        if not 1 <= len(key) <= 256 or any(c not in "0123456789abcdef" for c in key) or key[-1] == "0":
            raise ValueError("C_SCHEMA_VIOLATION")
        return Fraction(int(key, 16), 16 ** len(key))
    a, b = rational(lower, Fraction(0)), rational(upper, Fraction(1))
    if a >= b:
        raise ValueError("C_SCHEMA_VIOLATION")
    for digits in range(1, 257):
        candidate = int(a * 16 ** digits) + 1
        if Fraction(candidate, 16 ** digits) < b:
            return format(candidate, f"0{digits}x").rstrip("0")
    raise ValueError("C_ORDER_KEY_EXHAUSTED")


def comparison_key(lamport, action, device, record, index):
    if not 0 <= lamport <= MAX_INTEGER or not 0 <= index <= 1023:
        raise ValueError("C_SCHEMA_VIOLATION")
    return lamport, {"upsert": 0, "delete": 1, "clear": 1}[action], uuid.UUID(device).bytes, uuid.UUID(record).bytes, index


@dataclass
class LogicalState:
    winners: dict = field(default_factory=dict)
    clears: dict = field(default_factory=dict)
    records: dict = field(default_factory=dict)
    lamport: int = 0

    def apply(self, chain, record_id, record_hash, device, inner):
        identity = (chain, record_id)
        if identity in self.records:
            if self.records[identity] != record_hash:
                raise ValueError("C_RECORD_ID_CONFLICT")
            return
        for index, operation in enumerate(inner["operations"]):
            key = comparison_key(operation["lamport"], operation["operation"], device, record_id, index)
            self.lamport = max(self.lamport, key[0])
            if operation["operation"] == "clear":
                identity = chain, inner["collection"], operation["context"]["scope"]
                self.clears[identity] = max(self.clears.get(identity, key), key)
            else:
                identity = chain, inner["collection"], operation["entity_id"]
                if identity not in self.winners or key > self.winners[identity][0]:
                    self.winners[identity] = key, operation
        self.records[chain, record_id] = record_hash
