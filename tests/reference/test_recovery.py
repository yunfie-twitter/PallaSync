"""C.8 and §7.11 crypto checks against the document's public fixed inputs."""
import copy
import itertools
import struct
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
from protocol import GF, b64, decode, digest, jcs, object_hash, strict_loads, verify
from recovery_crypto import associated, offline_wrap_key, open_blob_identity, unwrap_share, portable, parse_portable, fragments, assemble_fragments

FIXTURES = Path(__file__).with_name("fixtures")
MNEMONIC = " ".join(["abandon"] * 23 + ["art"])


class RecoveryCryptoTests(unittest.TestCase):
    @staticmethod
    def _reference_shares(secret, threshold, total):
        """Independent test-only Shamir evaluation using galois.GF(256), poly 0x11b."""
        import numpy as np

        secret = GF(list(secret))
        coefficients = GF(
            np.array(
                [[(row * 29 + column * 17 + threshold) & 0xFF for column in range(32)]
                 for row in range(threshold - 1)],
                dtype=np.uint8,
            ),
        )
        shares = []
        for index in range(1, total + 1):
            x = GF(index)
            power = GF(1)
            share = secret.copy()
            for coefficient in coefficients:
                power *= x
                share += coefficient * power
            shares.append((index, share))
        return shares

    @staticmethod
    def _reference_reconstruct(points):
        import numpy as np

        indices = GF([int(index) for index, _ in points])
        shares = GF(np.array([list(map(int, share)) for _, share in points], dtype=np.uint8))
        numerator = np.broadcast_to(indices[None, :], (len(points), len(points))).copy()
        denominator = indices[:, None] + indices[None, :]
        np.fill_diagonal(numerator, GF(1))
        np.fill_diagonal(denominator, GF(1))
        weights = np.prod(numerator / denominator, axis=1)
        return (weights[:, None] * shares).sum(axis=0)

    def test_c8_galois_reconstructs_every_three_of_five_fixed_share_subset(self):
        vectors = (
            "5b5c55524740494e63646d6a7f7871762b2c25223730393e13141d1a0f080106",
            "3b3c35322720292e03040d0a1f1811164b4c45425750595e73747d7a6f686166",
            "ecf9c6d3b8ad928744516e7b10053a2fa7b28d98f3e6d9cc0f1a25305b4e7164",
            "8c99a6b3d8cdf2e724310e1b70655a4fc7d2edf89386b9ac6f7a45503b2e1104",
        )
        points = [(index + 2, GF(list(bytes.fromhex(value)))) for index, value in enumerate(vectors)]
        points.insert(0, (1, GF(list(bytes.fromhex(
            "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
        )))))
        for subset in itertools.combinations(points, 3):
            self.assertEqual(bytes(int(value) for value in self._reference_reconstruct(subset)), bytes(range(32)))

    def test_galois_profile_matrix_covers_every_valid_small_threshold(self):
        secret = bytes((index * 7 + 0x31) & 0xFF for index in range(32))
        profiles = [(threshold, total) for total in range(3, 9) for threshold in range(2, total)]
        for threshold, total in profiles:
            shares = self._reference_shares(secret, threshold, total)
            for basis in itertools.combinations(shares, threshold):
                self.assertEqual(bytes(int(value) for value in self._reference_reconstruct(basis)), secret,
                                 f"profile {threshold}-of-{total}")

    def test_portable_canonical_package_and_numbered_fragments(self):
        package = strict_loads((FIXTURES / "recovery-package-c8.json").read_bytes())
        encoded = portable(package, self.admin)
        self.assertEqual(parse_portable(encoded, self.admin), package)
        parts = fragments(package, self.admin, 128)
        self.assertIsNone(assemble_fragments(parts[:-1], self.admin))
        self.assertEqual(assemble_fragments(list(reversed(parts)) + [parts[0]], self.admin), package)
        with self.assertRaisesRegex(ValueError, "C_RECOVERY_SHARE_INVALID"):
            fragments(package, self.admin, 1)
        with self.assertRaisesRegex(ValueError, "C_RECOVERY_SHARE_INVALID"):
            parse_portable("PSR3:" + b64(b" " + jcs(package)), self.admin)
        conflicting = {**parts[0], "data": "changed"}
        with self.assertRaisesRegex(ValueError, "C_RECOVERY_SHARE_INVALID"):
            assemble_fragments(parts + [conflicting], self.admin)
        corrupt = [dict(part) for part in parts]
        corrupt[-1]["data"] += "A"
        with self.assertRaisesRegex(ValueError, "C_RECOVERY_SHARE_INVALID"):
            assemble_fragments(corrupt, self.admin)


    def test_local_sas_hpke_direction_gap_and_exact_retry(self):
        from recovery_pair import RecoveryPair
        import uuid
        ceremony, session = str(uuid.uuid4()), str(uuid.uuid4())
        dealer = RecoveryPair(self.manifest, self.admin, ceremony, session, "initiator", "dealer", "create")
        holder = RecoveryPair(self.manifest, self.admin, ceremony, session, "responder", "holder", "create")
        try:
            sas = dealer.bind(holder.descriptor)
            self.assertEqual(holder.bind(dealer.descriptor), sas)
            self.assertRegex(sas, r"^[0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4}$")
            dealer.confirm(sas, True)
            holder.confirm(sas, True)
            first = dealer.seal("result", {"result": "succeeded", "code": None})
            second = dealer.seal("result", {"result": "cancelled", "code": None})
            processed = []
            def process(kind, payload):
                processed.append(kind)
                return {"result": payload["result"]}
            with self.assertRaisesRegex(ValueError, "C_MISSING_DEPENDENCY"):
                holder.receive(jcs(second), process)
            self.assertEqual(processed, [])
            self.assertEqual(dealer.outgoing[1], first)
            for packet in (first, second, first):
                holder.receive(jcs(packet), process)
            self.assertEqual(processed, ["result", "result"])
            with self.assertRaisesRegex(ValueError, "C_RECOVERY_SHARE_INVALID"):
                holder.seal("distribute_share", {})
        finally:
            dealer.close()
            holder.close()

    def test_unconfirmed_local_transfer_is_an_abort_and_requires_fresh_keys(self):
        from recovery_pair import RecoveryPair
        import uuid
        ceremony, session = str(uuid.uuid4()), str(uuid.uuid4())
        dealer = RecoveryPair(self.manifest,self.admin,ceremony,session,"initiator","dealer","create")
        holder = RecoveryPair(self.manifest,self.admin,ceremony,session,"responder","holder","create")
        try:
            sas = dealer.bind(holder.descriptor)
            holder.bind(dealer.descriptor)
            with self.assertRaisesRegex(ValueError,"C_RECOVERY_AUTH_REQUIRED"):
                dealer.seal("result",{"result":"succeeded","code":None})
            self.assertTrue(dealer.closed)
            self.assertIsNone(dealer.signing)
            self.assertIsNone(dealer.kex)
            with self.assertRaisesRegex(ValueError,"C_RECOVERY_SESSION_EXPIRED"):
                dealer.confirm(sas,True)
        finally:
            dealer.close()
            holder.close()

    def test_signed_descriptor_extension_and_literal_result_code_validation(self):
        from recovery_pair import RecoveryPair
        from protocol import signed
        import uuid
        ceremony, session = str(uuid.uuid4()), str(uuid.uuid4())
        dealer = RecoveryPair(self.manifest,self.admin,ceremony,session,"initiator","dealer","create")
        holder = RecoveryPair(self.manifest,self.admin,ceremony,session,"responder","holder","create")
        try:
            dealer.descriptor = signed({**dealer.descriptor,"ext":{"org.example.flag":True}},dealer.signing,b"PALLASYNC-RECOVERY-SESSION-v3\0")
            sas = dealer.bind(holder.descriptor)
            self.assertEqual(holder.bind(dealer.descriptor),sas)
            dealer.confirm(sas,True)
            holder.confirm(sas,True)
            packet = dealer.seal("result",{"result":"failed","code":"C_RECOVERY_AUTH_REQUIRED"})
            self.assertEqual(holder.receive(jcs(packet),lambda kind,payload: payload),{"result":"failed","code":"C_RECOVERY_AUTH_REQUIRED"})
            with self.assertRaisesRegex(ValueError,"C_RECOVERY_SHARE_INVALID"):
                dealer.seal("result",{"result":"failed","code":"arbitrary diagnostic"})
            self.assertTrue(dealer.closed)
        finally:
            dealer.close()
            holder.close()

    def test_denied_or_mismatched_local_confirmation_cannot_be_resumed(self):
        from recovery_pair import RecoveryPair
        import uuid
        for denied in (True, False):
            ceremony, session = str(uuid.uuid4()), str(uuid.uuid4())
            first = RecoveryPair(self.manifest, self.admin, ceremony, session, "initiator", "dealer", "create")
            second = RecoveryPair(self.manifest, self.admin, ceremony, session, "responder", "holder", "create")
            try:
                sas = first.bind(second.descriptor)
                second.bind(first.descriptor)
                with self.assertRaisesRegex(ValueError, "C_RECOVERY_AUTH_REQUIRED" if denied else "C_RECOVERY_SAS_MISMATCH"):
                    first.confirm(sas if denied else "wrong", not denied)
                with self.assertRaisesRegex(ValueError, "C_RECOVERY_SESSION_EXPIRED"):
                    first.confirm(sas, True)
            finally:
                first.close()
                second.close()
    def setUp(self):
        self.manifest = strict_loads((FIXTURES / "recovery-manifest-c8.json").read_bytes())
        self.record = strict_loads((FIXTURES / "recovery-share-c8.json").read_bytes())
        self.admin = self.manifest["admin_public_key"]

    def test_c8_wrapped_share_and_changed_bindings(self):
        verify(self.manifest, decode(self.admin, 32), b"PALLASYNC-RECOVERY-SET-v3\0")
        self.assertEqual(object_hash(self.manifest), "AAK-KG_c1kPemS3aCSWBxcbKXMJQVNbs_52b_wHiJBg")
        self.assertEqual(unwrap_share(self.record, bytes(range(0x60, 0x80)), self.admin), (1, bytes([0x20] * 32)))
        with self.assertRaises(Exception):
            unwrap_share(self.record, bytes(32), self.admin)
        altered = copy.deepcopy(self.record)
        altered["holder_instance_id"] = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        with self.assertRaises(Exception):
            unwrap_share(altered, bytes(range(0x60, 0x80)), self.admin)

    def test_c8_blob_hash_tag_identity(self):
        fields = ("chain_id", "created_at_ms", "generation", "recovery_secret_fingerprint", "recovery_set_id", "threshold", "total_shares")
        blob = {k: self.manifest[k] for k in fields}
        blob.update(type="PALLASYNC-RECOVERY-BLOB-v3", version="3.0")
        body = {k: blob[k] for k in ("chain_id", "created_at_ms", "generation", "recovery_secret_fingerprint", "recovery_set_id")}
        body.update(mnemonic=MNEMONIC, passphrase="")
        encoded = jcs(body)
        self.assertEqual(len(encoded), 453)
        frame = struct.pack(">I", len(encoded)) + encoded + bytes(1024 - 4 - len(encoded))
        cipher = crypto_aead_xchacha20poly1305_ietf_encrypt(frame,
            associated(blob, "PALLASYNC-RECOVERY-BLOB-AAD-v3", ("blob_nonce", "encrypted_blob")),
            bytes(range(0x40, 0x58)), bytes(range(32)))
        self.assertEqual(digest(cipher).hex(), "249cf29c28c094a09269fed9f9454ebe014cfb2e46fad51f4c72ce9313d2a7a0")
        self.assertEqual(cipher[-16:].hex(), "82c953209db2ea8e3e7a541cded31127")
        blob.update(blob_nonce=b64(bytes(range(0x40, 0x58))), encrypted_blob=b64(cipher))
        self.assertEqual(object_hash(blob), self.manifest["recovery_blob_hash"])
        self.assertEqual(open_blob_identity(blob, bytes(range(32)), self.admin),
            {"chain_id": self.manifest["chain_id"], "admin_public_key": self.admin})
        with self.assertRaises(Exception):
            open_blob_identity(blob, bytes(32), self.admin)

    def test_offline_argon2_credential_binding_normalization(self):
        record = {k: self.record[k] for k in ("recovery_set_id", "recovery_share_id", "holder_instance_id", "share_wrap_key_id")}
        record["holder_kind"] = "offline"
        envelope = {k: record[k] for k in ("recovery_set_id", "recovery_share_id", "holder_instance_id", "share_wrap_key_id")}
        envelope.update(type="PALLASYNC-OFFLINE-SHARE-KEY-v3", version="3.0", kdf="argon2id",
            argon2_version=19, memory_kib=65536, iterations=3, parallelism=1, salt=b64(bytes(range(16))))
        wrapping = Argon2id(salt=bytes(range(16)), length=32, iterations=3, lanes=1, memory_cost=65536).derive("e\u0301".encode())
        encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(bytes(range(32)), jcs(envelope), bytes(range(24)), wrapping)
        envelope.update(key_nonce=b64(bytes(range(24))), encrypted_key=b64(encrypted))
        package = {"record": record, "offline_key_envelope": envelope}
        self.assertEqual(offline_wrap_key(package, "é"), bytes(range(32)))
        self.assertEqual(offline_wrap_key(package, "e\u0301"), bytes(range(32)))
        with self.assertRaises(Exception):
            offline_wrap_key(package, "wrong")
        envelope["iterations"] = 4
        with self.assertRaisesRegex(ValueError, "C_RECOVERY_SHARE_INVALID"):
            offline_wrap_key(package, "é")


if __name__ == "__main__":
    unittest.main()
