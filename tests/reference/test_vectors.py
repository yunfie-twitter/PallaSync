"""Independent cryptographic/convergence vectors. Passing is not an IT-01..50 claim."""
import itertools
import unittest
from pathlib import Path

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from nacl.signing import SigningKey
from protocol import *

MNEMONIC = " ".join(["abandon"] * 23 + ["art"])


class VectorTests(unittest.TestCase):
    def test_peer_fixed_transcript_matches_native_public_fixture(self):
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from peer_sas import sas

        fixture = strict_loads((Path(__file__).parent / "fixtures/peer-sas.json").read_bytes())
        self.assertEqual(sas(X25519PrivateKey.from_private_bytes(bytes(range(32))), fixture["offer"], fixture["request"], "approver"), fixture["expected_sas"])
        self.assertEqual(sas(X25519PrivateKey.from_private_bytes(bytes(range(32, 64))), fixture["offer"], fixture["request"], "subject"), fixture["expected_sas"])

    def test_peer_sas_binds_the_exact_offer_and_signed_request(self):
        import uuid
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from peer_sas import sas

        approver = X25519PrivateKey.from_private_bytes(bytes(range(32)))
        subject = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        signing = SigningKey(bytes(range(32)))
        public = lambda key: b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
        offer = {"protocol": "pallasync/3", "relay_origin": "https://relay.example.com", "chain_id": b64(bytes(32)),
            "generation": 0, "parameters_hash": b64(bytes(32)), "epoch_hash": b64(bytes(32)),
            "request_id": str(uuid.uuid4()), "offer_nonce": b64(bytes(range(32))), "expires_at_ms": 300001,
            "admin_public_key": b64(bytes(signing.verify_key)), "approver_device_id": str(uuid.uuid4()),
            "approver_device_public_key": b64(bytes(signing.verify_key)), "approver_device_kex_public_key": public(approver),
            "approver_device_record_hash": b64(bytes(32))}
        request = signed({"request_id": offer["request_id"], "chain_id": offer["chain_id"], "generation": 0,
            "device_id": str(uuid.uuid4()), "device_public_key": b64(bytes(signing.verify_key)),
            "device_kex_public_key": public(subject), "offer_nonce": offer["offer_nonce"], "created_at_ms": 1,
            "expires_at_ms": offer["expires_at_ms"]}, signing, b"PALLASYNC-ENROLL-REQUEST-v3\0")
        visual = sas(approver, offer, request, "approver")
        self.assertRegex(visual, r"^[0-9a-f]{12}$")
        self.assertEqual(visual, sas(subject, offer, request, "subject"))
        changed = {**offer, "epoch_hash": b64(bytes([1]) * 32)}
        self.assertNotEqual(visual, sas(subject, changed, request, "subject"))
        replacement = signed({**request, "device_id": str(uuid.uuid4())}, signing, b"PALLASYNC-ENROLL-REQUEST-v3\0")
        self.assertNotEqual(visual, sas(subject, offer, replacement, "subject"))
        with self.assertRaisesRegex(ValueError, "C_BOOTSTRAP_TRUST_REQUIRED"):
            sas(approver, offer, request, "subject")
        with self.assertRaisesRegex(ValueError, "C_SCHEMA_VIOLATION"):
            sas(approver, {**offer, "unknown": True}, request, "approver")

    def test_protected_artifacts_do_not_advance_normal_author_state(self):
        from artifact_boundary import LOCAL_ARTIFACTS
        from crypto_client import CryptoClient

        client = CryptoClient(MNEMONIC)
        forbidden = [{"type": kind} for kind in LOCAL_ARTIFACTS]
        forbidden.append({"mnemonic": "public fixture only", "passphrase": ""})
        forbidden.append("PSR3:" + b64(jcs({"type":"PALLASYNC-RECOVERY-PACKAGE-v3"})))
        for artifact in forbidden:
            with self.assertRaisesRegex(ValueError, "C_SCHEMA_VIOLATION"):
                client.record("palleria.search_history/3", [{"nested": [artifact]}])
            self.assertEqual((client.sequence, client.tail), (0, None))
        record = client.record("palleria.search_history/3", [{"entity_id": "PSR3:debug", "operation": "upsert",
            "lamport": 1, "created_at_ms": 1, "context": {}, "body": {"query": "PSR3:debug"}}])
        self.assertEqual(record["device_id"], client.device_id)

    def test_strict_json_and_utf16_jcs(self):
        for text in (b'{"x":1,"x":2}', b'-0', b'-1', b'1.0', b'1e0', b'9007199254740992',
                     b'"\\ud800"', b'"\xff"', b'\xef\xbb\xbf{}', b'[' * 33 + b'0' + b']' * 33):
            with self.assertRaises((ValueError, UnicodeError)):
                strict_loads(text)
        self.assertEqual(strict_loads(b'9007199254740991'), MAX_INTEGER)
        strict_loads(b'[' * 32 + b'0' + b']' * 32)
        self.assertEqual(jcs({"\ue000": 2, "\U00010000": 1}), b'{"\xf0\x90\x80\x80":1,"\xee\x80\x80":2}')

    def test_c2_c3_root_epoch_and_tag(self):
        roots = root_keys(MNEMONIC)
        self.assertEqual(roots["root_seed"].hex(), "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840")
        self.assertEqual(b64(roots["chain_id_digest"]), "ODtLW4w27pD6LS9IpFBfmvByjEoBFddv2Fx1QJIMJoc")
        self.assertEqual(roots["admin_seed"].hex(), "09525a4f4bf3c7b6bf9fb4bad49556e77e2af51b08695a334bf160e16c59c150")
        self.assertEqual(bytes(SigningKey(roots["admin_seed"]).verify_key).hex(), "0e29ac96ebc027a701a35ec2fb21f831ac32f591fce5c075a1d7839dc0b2170d")
        self.assertEqual(roots["recovery_kek"].hex(), "c9c01a7b0d75b4c31322a2d30a09cd8dcc785740059dbb99d243b70d48509eef")
        keys = epoch_keys(roots["chain_id_digest"], 0, bytes(range(0xa0, 0xc0)))
        self.assertEqual(keys["record"].hex(), "d96ff76d5c3ad5df7429153b52126e43a818c223f53fa3f52d7ce102026c0974")
        self.assertEqual(keys["epoch-commitment"].hex(), "ddf4f8d731af10c1c98684337103bfe010bf84fb646e2cfa11aecafab986f493")
        self.assertEqual(b64(hmac.digest(keys["collection-tag"], b"palleria.search_history/3", "sha256")[:16]), "ug37uPKZb2rNd2W3emGy3A")
        self.assertNotEqual(roots["chain_id_digest"], root_keys(MNEMONIC, "different")["chain_id_digest"])
        self.assertEqual(root_keys(MNEMONIC, "é"), root_keys(MNEMONIC, "e\u0301"))

    def test_c7_order_and_exhaustion(self):
        for lower, upper, expected in ((None,None,"1"),("1",None,"2"),("1","2","11"),("1","11","101")):
            self.assertEqual(order_between(lower,upper), expected)
        with self.assertRaisesRegex(ValueError, "C_ORDER_KEY_EXHAUSTED"):
            order_between(None, "0" * 255 + "1")

    def test_c8_gf_every_subset_and_extra_consistency(self):
        self.assertEqual(int(GF(0x57) * GF(0x13)), 0xfe)
        self.assertEqual(int(GF(0x53) * GF(0xca)), 1)
        secret = bytes(range(32))
        pieces = split(secret, 3, 5, [bytes(range(0x20,0x40)), bytes(range(0x40,0x60))])
        self.assertEqual(pieces[0][1], bytes(range(0x60,0x80)))
        for subset in itertools.combinations(pieces,3):
            for ordering in itertools.permutations(subset):
                self.assertEqual(reconstruct(ordering,3,5), secret)
        bad = pieces[:]
        bad[-1] = bad[-1][0], bytes([bad[-1][1][0] ^ 1]) + bad[-1][1][1:]
        with self.assertRaises(ValueError):
            reconstruct(bad,3,5)
        with self.assertRaisesRegex(ValueError,"C_RECOVERY_THRESHOLD_NOT_MET"):
            reconstruct([pieces[0],pieces[0]],3,5)

    def test_signature_context_and_nested_coverage(self):
        key = SigningKey(bytes(range(32)))
        value = signed({"nullable":None,"nested":{"signature":"covered"}}, key, b"PALLASYNC-ENROLLMENT-v3\0")
        verify(value, bytes(key.verify_key), b"PALLASYNC-ENROLLMENT-v3\0")
        with self.assertRaises(Exception):
            verify(value, bytes(key.verify_key), b"PALLASYNC-EPOCH-v3\0")
        value["nested"]["signature"] = "changed"
        with self.assertRaises(Exception):
            verify(value, bytes(key.verify_key), b"PALLASYNC-ENROLLMENT-v3\0")

    def test_c7_convergence_all_permutations_and_replays(self):
        a,b = "11111111-1111-4111-8111-111111111111", "33333333-3333-4333-8333-333333333333"
        r,s = "22222222-2222-4222-8222-222222222222", "44444444-4444-4444-8444-444444444444"
        inputs = [(8,"upsert",b,s,"x"),(8,"delete",a,r,"x"),(9,"upsert",a,r,"x"),(9,"clear",b,s,"*"),(10,"upsert",a,r,"y")]
        # C7 keys refer to op indexes in R/S; immutable record replay is tested separately.
        expected = None
        for order in itertools.permutations(inputs):
            winners, clear = {}, None
            for lamport, action, device, record, entity in order + order:
                key = comparison_key(lamport,action,device,record,0 if lamport==8 else 1 if lamport==9 else 2)
                if action=="clear":
                    clear = max(clear or key,key)
                elif entity not in winners or key>winners[entity][0]:
                    winners[entity] = key, action
            result = (winners,clear)
            expected = expected or result
            self.assertEqual(result,expected)
            self.assertLess(winners["x"][0],clear)
            self.assertGreater(winners["y"][0],clear)


if __name__ == "__main__":
    unittest.main()
