"""Independent test client cryptography: PyNaCl/cryptography, no Rust/JNI imports.

The HPKE schedule is RFC 9180's fixed base suite, for interoperability tests only.
Python secret objects are not a production protected-storage implementation.
"""
import secrets
import struct
import time
import uuid
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import serialization
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.signing import SigningKey
from protocol import b64, decode, digest, epoch_keys, hkdf_extract, hkdf_expand, jcs, object_hash, root_keys, signed, strict_loads, verify
from artifact_boundary import require_normal_data


def hpke_key(recipient, ephemeral, info):
    sender = X25519PrivateKey.from_private_bytes(ephemeral)
    enc = sender.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    dh = sender.exchange(X25519PublicKey.from_public_bytes(recipient))
    if not any(dh):
        raise ValueError("C_SCHEMA_VIOLATION")

    return enc, *hpke_schedule(recipient,enc,dh,info)


def hpke_schedule(recipient, enc, dh, info):
    def extract(suite, salt, label, material):
        return hkdf_extract(salt,b"HPKE-v1" + suite + label + material)

    def expand(suite, prk, label, extra, length):
        return hkdf_expand(prk,struct.pack(">H",length) + b"HPKE-v1" + suite + label + extra,length)

    kem = b"KEM\x00\x20"
    prk = extract(kem,b"",b"eae_prk",dh)
    shared = expand(kem,prk,b"shared_secret",enc + recipient,32)
    suite = b"HPKE\x00\x20\x00\x01\x00\x03"
    context = b"\x00" + extract(suite,b"",b"psk_id_hash",b"") + extract(suite,b"",b"info_hash",info)
    secret = extract(suite,shared,b"secret",b"")
    return expand(suite,secret,b"key",context,32), expand(suite,secret,b"base_nonce",context,12)


def hpke_seal(recipient, plaintext, info, aad, ephemeral=None):
    enc,key,nonce = hpke_key(recipient,ephemeral or secrets.token_bytes(32),info)
    return enc, ChaCha20Poly1305(key).encrypt(nonce,plaintext,aad)


def hpke_open(recipient, enc, cipher, info, aad):
    public = recipient.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    dh = recipient.exchange(X25519PublicKey.from_public_bytes(enc))
    if not any(dh):
        raise ValueError("C_SCHEMA_VIOLATION")
    key, nonce = hpke_schedule(public,enc,dh,info)
    return ChaCha20Poly1305(key).decrypt(nonce,cipher,aad)


def frame(value, buckets=(1024,4096,16384,65536,262144,1048576)):
    body = jcs(value)
    length = next((bucket for bucket in buckets if len(body) + 4 <= bucket),None)
    if length is None:
        raise ValueError("C_SCHEMA_VIOLATION")
    return struct.pack(">I",len(body)) + body + secrets.token_bytes(length - 4 - len(body))


class CryptoClient:
    def __init__(self, mnemonic, passphrase=""):
        self.roots = root_keys(mnemonic,passphrase)
        self.chain = b64(self.roots["chain_id_digest"])
        self.admin = SigningKey(self.roots["admin_seed"])
        self.device = SigningKey.generate()
        self.kex = X25519PrivateKey.generate()
        self.kex_public = self.kex.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.device_id = str(uuid.uuid4())
        self.epoch = 0
        self.secret = secrets.token_bytes(32)
        self.keys = epoch_keys(self.roots["chain_id_digest"],0,self.secret)
        self.sequence = 0
        self.tail = None

    def genesis(self):
        common = {"chain_id":self.chain,"generation":0}
        params = signed({**common,"version":"3.0","admin_public_key":b64(bytes(self.admin.verify_key)),"previous_parameters_hash":None,
                         "policy":{"metadata_profile":"private","allow_device_chain_delete":False,"allow_peer_enrollment":True,
                                   "allow_device_rotation":True,"epoch_retention":"retain","epoch_window_ms":2592000000,"scheduled_rotation_ms":0}},self.admin,b"PALLASYNC-CHAIN-PARAMS-v3\0")
        cert = signed({**common,"certificate_id":str(uuid.uuid4()),"device_id":self.device_id,"device_public_key":b64(bytes(self.device.verify_key)),
                       "device_kex_public_key":b64(self.kex_public),"signer_kind":"admin","signer_device_id":None,"request_hash":None,"approved_at_ms":int(time.time()*1000)},self.admin,b"PALLASYNC-ENROLLMENT-v3\0")
        meta_nonce = secrets.token_bytes(24)
        meta_aad = jcs({"type":"PALLASYNC-DEVICE-META-v3",**common,"device_id":self.device_id,"epoch":0})
        meta = crypto_aead_xchacha20poly1305_ietf_encrypt(frame({"name":"Independent Python test client","key_protection":"os-keystore"},(1024,4096)),meta_aad,meta_nonce,self.keys["device-meta"])
        device = signed({"version":"3.0",**common,"device_id":self.device_id,"device_public_key":cert["device_public_key"],"device_kex_public_key":cert["device_kex_public_key"],
                         "meta_epoch":0,"meta_nonce":b64(meta_nonce),"encrypted_device_meta":b64(meta),"enrollment":cert},self.device,b"PALLASYNC-DEVICE-RECORD-v3\0")
        bindings = {**common,"epoch":0,"previous_epoch_hash":None,"epoch_commitment":b64(self.keys["epoch-commitment"]),"signer_kind":"admin","signer_device_id":None}
        recovery = {**bindings,"envelope_id":str(uuid.uuid4()),"recipient_kind":"recovery","recipient_device_id":None,"recipient_key_hash":None}
        nonce = secrets.token_bytes(24)
        recovery = signed({**recovery,"enc":None,"nonce":b64(nonce),"ciphertext":b64(crypto_aead_xchacha20poly1305_ietf_encrypt(self.secret,jcs(recovery),nonce,self.roots["recovery_kek"]))},self.admin,b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
        recipient = {**bindings,"envelope_id":str(uuid.uuid4()),"recipient_kind":"device","recipient_device_id":self.device_id,"recipient_key_hash":b64(digest(self.kex_public))}
        enc,cipher = hpke_seal(self.kex_public,self.secret,b"PALLASYNC-EPOCH-ENVELOPE-v3\0" + jcs(recipient),jcs(recipient))
        envelope = signed({**recipient,"enc":b64(enc),"nonce":None,"ciphertext":b64(cipher)},self.admin,b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
        epoch = signed({**bindings,"reason":"genesis","members":[self.device_id],"revoked_device_ids":[],"recovery_envelope_hash":object_hash(recovery)},self.admin,b"PALLASYNC-EPOCH-v3\0")
        return {"parameters":params,"device_record":device,"epoch":epoch,"envelopes":[envelope,recovery]}

    def record(self, collection, operations):
        require_normal_data(operations)
        self.sequence += 1
        inner = {"collection":collection,"device_seq":self.sequence,"prev_record_hash":self.tail,"operations":operations}
        record = {"version":"3.0","chain_id":self.chain,"generation":getattr(self,"generation",0),"record_id":str(uuid.uuid4()),"device_id":self.device_id,"epoch":self.epoch,"collection_tag":None}
        nonce = secrets.token_bytes(24)
        cipher = crypto_aead_xchacha20poly1305_ietf_encrypt(frame(inner),jcs({"type":"PALLASYNC-AAD-v3",**record}),nonce,self.keys["record"])
        record = signed({**record,"payload_nonce":b64(nonce),"encrypted_payload":b64(cipher)},self.device,b"PALLASYNC-SYNC-RECORD-v3\0")
        self.tail = object_hash(record)
        return record

    def propose_epoch(self, parameters, previous_epoch, devices, revoked=(), reason="manual", admin=False):
        """Independent test proposal; leave the installed secret unchanged until acceptance.

        Root material exists only in this test process. No relay/runtime code calls this.
        The exact payload deliberately uses recovery-first request order, independent
        of the relay's ordered control log.
        """
        generation, epoch = parameters["generation"], previous_epoch["epoch"] + 1
        if epoch > 0xffffffff:
            raise ValueError("C_COUNTER_EXHAUSTED")
        secret = secrets.token_bytes(32)
        keys = epoch_keys(self.roots["chain_id_digest"],epoch,secret)
        signing = self.admin if admin else self.device
        common = {"chain_id":self.chain,"generation":generation,"epoch":epoch,"previous_epoch_hash":object_hash(previous_epoch),
                  "epoch_commitment":b64(keys["epoch-commitment"]),"signer_kind":"admin" if admin else "device","signer_device_id":None if admin else self.device_id}
        binding = {**common,"envelope_id":str(uuid.uuid4()),"recipient_kind":"recovery","recipient_device_id":None,"recipient_key_hash":None}
        nonce = secrets.token_bytes(24)
        recovery = signed({**binding,"enc":None,"nonce":b64(nonce),"ciphertext":b64(crypto_aead_xchacha20poly1305_ietf_encrypt(secret,jcs(binding),nonce,self.roots["recovery_kek"]))},signing,b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
        recovered = crypto_aead_xchacha20poly1305_ietf_decrypt(decode(recovery["ciphertext"]),jcs(binding),nonce,self.roots["recovery_kek"])
        import hmac
        if not hmac.compare_digest(epoch_keys(self.roots["chain_id_digest"],epoch,recovered)["epoch-commitment"],keys["epoch-commitment"]):
            raise ValueError("C_COMMITMENT_MISMATCH")
        envelopes = [recovery]
        for device in sorted(devices,key=lambda d:d["device_id"],reverse=True):
            binding = {**common,"envelope_id":str(uuid.uuid4()),"recipient_kind":"device","recipient_device_id":device["device_id"],"recipient_key_hash":b64(digest(decode(device["device_kex_public_key"],32)))}
            enc,cipher = hpke_seal(decode(device["device_kex_public_key"],32),secret,b"PALLASYNC-EPOCH-ENVELOPE-v3\0"+jcs(binding),jcs(binding))
            envelopes.append(signed({**binding,"enc":b64(enc),"nonce":None,"ciphertext":b64(cipher)},signing,b"PALLASYNC-EPOCH-ENVELOPE-v3\0"))
        value = signed({**common,"reason":reason,"members":sorted(d["device_id"] for d in devices),"revoked_device_ids":sorted(revoked),"recovery_envelope_hash":object_hash(recovery)},signing,b"PALLASYNC-EPOCH-v3\0")
        action = {"epoch":value,"envelopes":envelopes}
        operation = None
        if admin and revoked:
            operation = signed({"operation_id":str(uuid.uuid4()),"chain_id":self.chain,"generation":generation,"action":"revoke_device",
                                "expected_parameters_hash":object_hash(parameters),"expected_epoch_hash":object_hash(previous_epoch),"target_hash":object_hash(action),"created_at_ms":int(time.time()*1000)},self.admin,b"PALLASYNC-ADMIN-OP-v3\0")
        return {"expected_epoch_hash":object_hash(previous_epoch),**action,"admin_operation":operation}, secret, keys

    def decrypt(self, record, author_public_key=None):
        verify(record,author_public_key if author_public_key is not None else bytes(self.device.verify_key),b"PALLASYNC-SYNC-RECORD-v3\0")
        aad = {"type":"PALLASYNC-AAD-v3",**{key:record[key] for key in ("version","chain_id","generation","record_id","device_id","epoch","collection_tag")}}
        clear = crypto_aead_xchacha20poly1305_ietf_decrypt(decode(record["encrypted_payload"]),jcs(aad),decode(record["payload_nonce"],24),self.keys["record"])
        length = struct.unpack(">I",clear[:4])[0]
        if length > len(clear)-4:
            raise ValueError("C_SCHEMA_VIOLATION")
        return strict_loads(clear[4:4+length])
