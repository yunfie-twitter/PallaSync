"""Independent v2.1 read/decrypt checks on a disposable frozen legacy store.

No Rust/JNI crypto is shared. No parameter signature context is invented. This
targeted Python/relay case does not certify client migration or the IT catalogue.
"""
import argparse
from contextlib import closing
from http.client import HTTPSConnection
import secrets
import sqlite3
import struct
import time
import uuid
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt, crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.signing import SigningKey
from crypto_client import CryptoClient
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT
from protocol import b64, decode, digest, hkdf_expand, hkdf_extract, jcs, signed, strict_loads, verify

MEDIA = "application/vnd.palleria.sync.v2+json"


def run(binary):
    current = CryptoClient(" ".join(["abandon"] * 23 + ["art"]))
    salt = secrets.token_bytes(32)
    seed = current.roots["root_seed"]
    chain = b64(digest(b"PALLASYNC-CHAIN-ID-v2.1\0" + salt + seed))
    prk = hkdf_extract(salt, seed)
    admin = SigningKey(hkdf_expand(prk, b"PALLASYNC-v2.1\0admin-ed25519\0", 32))
    epoch_key = hkdf_expand(prk, b"PALLASYNC-v2.1\0epoch\0" + struct.pack(">I", 0), 32)
    record_key = hkdf_expand(epoch_key, b"PALLASYNC-v2.1\0record\0", 32)
    device_key, device_id = SigningKey.generate(), str(uuid.uuid4())
    public = b64(bytes(device_key.verify_key))
    name_aad = {"type": "PALLASYNC-DEVICE-NAME-v2.1", "chain_id": chain, "device_id": device_id,
                "device_public_key": public, "updated_at_ms": 0}
    nonce = secrets.token_bytes(24)
    device = signed({"protocol_version": "2.1", "chain_id": chain, "device_id": device_id,
                     "device_public_key": public, "encrypted_device_name": b64(crypto_aead_xchacha20poly1305_ietf_encrypt(
                         b"Independent legacy holder", jcs(name_aad), nonce, record_key)),
                     "device_name_nonce": b64(nonce), "status": "active", "created_at_ms": 0, "updated_at_ms": 0},
                    device_key, b"PALLASYNC-DEVICE-RECORD-v2.1\0")
    expected = []
    for index, query in enumerate(["alpha", "猫", "é"], 1):
        payload = {"schema": "palleria.search_history/2", "entity_id": query, "operation": "upsert", "context": {},
                   "lamport": index, "created_at_ms": 0, "body": {"query": query}}
        aad = {"protocol_version": "2.1", "chain_id": chain, "record_id": f"01990000-0000-7000-8000-{index:012x}",
               "epoch": 0, "collection_name": payload["schema"], "action": "upsert", "device_id": device_id,
               "lamport": index, "created_at_ms": 0}
        nonce = secrets.token_bytes(24)
        record = signed({**aad, "payload_nonce": b64(nonce), "encrypted_payload": b64(
            crypto_aead_xchacha20poly1305_ietf_encrypt(jcs(payload), jcs(aad), nonce, record_key))},
            device_key, b"PALLASYNC-SYNC-RECORD-v2.1\0")
        expected.append((record, payload, aad))
    schema = strict_loads((ROOT / "docs/privacy.schema.json").read_bytes())
    with IsolatedRelay(binary) as relay:
        http = ReferenceHTTP(relay, current, True, schema)
        status, _, _ = http.request("POST", "/pallasync/v3/chains", current.genesis(), True)
        assert status == 201
        modern_path = "/pallasync/v3/chains/" + current.chain + "/log/head"
        status, before, _ = http.request("GET", modern_path, admin=True)
        assert status == 200
        # Fixture injection is restricted to the harness-owned disposable file.
        with closing(sqlite3.connect(relay.directory / "relay.sqlite")) as db:
            db.executescript((ROOT / "tests/fixtures/frozen-v2-schema.sql").read_text(encoding="utf-8-sig"))
            db.execute("INSERT INTO chains VALUES(?,?,?,?,?,?,NULL)",
                       (chain, b64(salt), b64(bytes(admin.verify_key)), 0, device_id, public))
            db.execute("INSERT INTO devices VALUES(?,?,?,?,?,?,?,?,?)", tuple(device[k] for k in
                       ("chain_id", "device_id", "device_public_key", "encrypted_device_name", "device_name_nonce", "status", "created_at_ms", "updated_at_ms", "signature")))
            for record, _, _ in expected:
                fields = ("chain_id", "record_id", "protocol_version", "epoch", "collection_name", "action", "encrypted_payload", "payload_nonce", "device_id", "lamport", "created_at_ms", "signature")
                db.execute("INSERT INTO sync_records(" + ",".join(fields) + ") VALUES(" + ",".join("?" for _ in fields) + ")", tuple(record[k] for k in fields))
            db.commit()

        def token(method, path):
            route, _, query = path.partition("?")
            now = int(time.time() * 1000)
            return b64(jcs(signed({"v": 1, "chain_id": chain, "device_id": device_id, "method": method,
                "path": route, "query": query, "body_sha256": b64(digest(b"")), "issued_at_ms": now,
                "expires_at_ms": now + 300000, "nonce": b64(secrets.token_bytes(16))}, device_key, b"PALLASYNC-CAPABILITY-v2.1\0")))

        def request(method, path, authorization=None):
            http.check_policy()
            connection = HTTPSConnection("127.0.0.1", relay.proxy.server_port, context=relay.client_tls, timeout=15)
            headers = {"Accept": MEDIA}
            if authorization is not None:
                headers["Authorization"] = "PallaSync " + authorization
            connection.request(method, path, b"", headers)
            response = connection.getresponse()
            status, headers = response.status, {name.lower(): value for name, value in response.getheaders()}
            data = response.read(8_388_609)
            connection.close()
            assert len(data) <= 8_388_608 and headers.get("cache-control") == "no-store" and "date" in headers
            assert headers.get("content-type") == MEDIA and "x-pallasync-protocol" not in headers
            return status, strict_loads(data) if data else None, headers

        prefix = "/pallasync/v2/chains/" + chain
        status, body, _ = request("GET", prefix + "/parameters")
        assert status == 500 and body is None, "Missing original parameter signatures must not be fabricated"
        path = prefix + "/devices"
        status, registry, _ = request("GET", path, token("GET", path))
        assert status == 200 and registry == {"devices": [device], "next_cursor": None}
        verify(registry["devices"][0], bytes(device_key.verify_key), b"PALLASYNC-DEVICE-RECORD-v2.1\0")
        assert crypto_aead_xchacha20poly1305_ietf_decrypt(decode(device["encrypted_device_name"]), jcs(name_aad),
            decode(device["device_name_nonce"], 24), record_key) == b"Independent legacy holder"
        path, replay = prefix + "/records?after_seq=0&limit=1", None
        for index, (original, payload, aad) in enumerate(expected, 1):
            authorization = token("GET", path)
            if replay is None:
                replay = (path, authorization)
            status, page, headers = request("GET", path, authorization)
            assert status == 200 and len(page["records"]) == 1 and headers["pallasync-next-seq"] == str(index)
            received = dict(page["records"][0])
            assert received.pop("relay_seq") == index and received.pop("server_sequence") == index and received == original
            verify(received, bytes(device_key.verify_key), b"PALLASYNC-SYNC-RECORD-v2.1\0")
            plaintext = crypto_aead_xchacha20poly1305_ietf_decrypt(decode(received["encrypted_payload"]), jcs(aad), decode(received["payload_nonce"], 24), record_key)
            assert strict_loads(plaintext) == payload
            path = prefix + "/records?cursor=" + str(index) + "&limit=1"
        assert page["next_cursor"] is None and headers["pallasync-has-more"] == "false"
        relay.restart()
        assert request("GET", replay[0], replay[1])[0] == 401
        assert request("POST", prefix + "/records")[0] == 405
        assert request("DELETE", prefix, token("DELETE", prefix))[0] == 200
        assert request("GET", prefix + "/parameters")[0] == 410
        status, after, _ = http.request("GET", modern_path, admin=True)
        assert status == 200
        for field in ("head_seq", "head_hash", "epoch_hash", "log_id", "parameters_hash", "generation", "min_available_seq"):
            assert after[field] == before[field]
        print("PASS: independent legacy KDF/signatures/AEAD, frozen paging, missing original signature report, persistent nonce and v3-isolated explicit deletion", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-binary", required=True)
    run(parser.parse_args().relay_binary)
