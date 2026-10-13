"""Independent prospective peer used only in conformance tests (§18.1).

No mnemonic/root key or Rust/JNI is used. Python memory is not a production protected holder.
The source history/QR is selected and verified by the test caller before construction.
"""
import secrets
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
from nacl.signing import SigningKey
from crypto_client import CryptoClient, frame, hpke_open
from peer_sas import sas
from protocol import b64, decode, digest, epoch_keys, jcs, object_hash, signed, verify


class PeerClient:
    record = CryptoClient.record

    def __init__(self, offer, explicitly_selected):
        if not explicitly_selected:
            raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        self.offer = offer
        self.chain = offer["chain_id"]
        self.generation = offer["generation"]
        self.device = SigningKey.generate()
        self.kex = X25519PrivateKey.generate()
        self.kex_public = self.kex.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.device_id = str(uuid.uuid4())
        now = int(time.time() * 1000)
        if not now < offer["expires_at_ms"] <= now + 300000:
            raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        self.request = signed({"request_id": offer["request_id"], "chain_id": self.chain, "generation": offer["generation"],
            "device_id": self.device_id, "device_public_key": b64(bytes(self.device.verify_key)), "device_kex_public_key": b64(self.kex_public),
            "offer_nonce": offer["offer_nonce"], "created_at_ms": now, "expires_at_ms": offer["expires_at_ms"]}, self.device, b"PALLASYNC-ENROLL-REQUEST-v3\0")
        self.visual = sas(self.kex, offer, self.request, "subject")
        self.confirmed = False
        self.sequence, self.tail = 0, None
        self.prepared = None

    def confirm(self, observed, explicitly_confirmed):
        if not explicitly_confirmed or observed != self.visual:
            raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        self.confirmed = True

    def prepare(self, certificate, envelope, epoch):
        if not self.confirmed:
            raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        for name in ("chain_id", "generation", "device_id", "device_public_key", "device_kex_public_key"):
            if certificate[name] != self.request[name]:
                raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        if (certificate["request_hash"] != object_hash(self.request) or certificate["signer_kind"] != "device"
                or certificate["signer_device_id"] != self.offer["approver_device_id"]):
            raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        verify(certificate, decode(self.offer["approver_device_public_key"], 32), b"PALLASYNC-ENROLLMENT-v3\0")
        self.verify_envelope(envelope, epoch)
        if self.prepared is not None:
            if self.prepared["device_record"]["enrollment"] != certificate or self.prepared["envelopes"] != [envelope]:
                raise ValueError("C_DEVICE_EQUIVOCATION")
            return self.prepared
        nonce = secrets.token_bytes(24)
        aad = jcs({"type":"PALLASYNC-DEVICE-META-v3", "chain_id":self.chain, "generation":self.offer["generation"], "device_id":self.device_id, "epoch":self.epoch})
        cipher = crypto_aead_xchacha20poly1305_ietf_encrypt(frame({"name":"Independent Python paired client", "key_protection":"os-keystore"}, (1024,4096)), aad, nonce, self.keys["device-meta"])
        record = signed({"version":"3.0", "chain_id":self.chain, "generation":self.offer["generation"], "device_id":self.device_id,
            "device_public_key":b64(bytes(self.device.verify_key)), "device_kex_public_key":b64(self.kex_public), "meta_epoch":self.epoch,
            "meta_nonce":b64(nonce), "encrypted_device_meta":b64(cipher), "enrollment":certificate}, self.device, b"PALLASYNC-DEVICE-RECORD-v3\0")
        self.prepared = {"device_record":record, "envelopes":[envelope], "admin_operation":None}
        return self.prepared

    def verify_envelope(self, envelope, epoch):
        if (object_hash(epoch) != self.offer["epoch_hash"] or epoch["chain_id"] != self.chain or epoch["generation"] != self.generation
                or envelope["chain_id"] != self.chain or envelope["generation"] != self.offer["generation"]
                or envelope["recipient_kind"] != "device" or envelope["recipient_device_id"] != self.device_id
                or envelope["recipient_key_hash"] != b64(digest(self.kex_public)) or envelope["signer_kind"] != "device"
                or envelope["signer_device_id"] != self.offer["approver_device_id"]
                or any(envelope[name] != epoch[name] for name in ("epoch", "previous_epoch_hash", "epoch_commitment"))):
            raise ValueError("C_BOOTSTRAP_TRUST_REQUIRED")
        verify(envelope, decode(self.offer["approver_device_public_key"],32), b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
        binding = {name:value for name,value in envelope.items() if name not in ("signature", "ext", "enc", "nonce", "ciphertext")}
        secret = hpke_open(self.kex, decode(envelope["enc"],32), decode(envelope["ciphertext"],48), b"PALLASYNC-EPOCH-ENVELOPE-v3\0" + jcs(binding), jcs(binding))
        keys = epoch_keys(decode(self.chain,32), epoch["epoch"], secret)
        if not secrets.compare_digest(keys["epoch-commitment"], decode(epoch["epoch_commitment"],32)):
            raise ValueError("C_COMMITMENT_MISMATCH")
        self.secret, self.keys, self.epoch = secret, keys, epoch["epoch"]

    def ack(self, epoch):
        return {"epoch_hash":object_hash(epoch), "epoch_commitment":epoch["epoch_commitment"]}
