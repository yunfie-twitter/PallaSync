"""Independent recovery audit schema and encrypted roundtrip. Not completion of three-party IT."""
import copy
import unittest
import uuid
from crypto_client import CryptoClient
from protocol import b64
from recovery_audit import EVENTS, validate


def operation(event="recovery_ceremony_started", result="started"):
    return {"entity_id": str(uuid.uuid4()), "operation": "upsert", "lamport": 1, "created_at_ms": 42,
            "context": {}, "body": {"event": event, "result": result, "subject_id": None, "object_hash": None,
            "ext": {"org.palleria.recovery": {"recovery_set_id": str(uuid.uuid4()),
            "recovery_secret_fingerprint": b64(bytes(32)), "threshold": 2, "total_shares": 3,
            "holder_kind": None, "holder_counts": {"device": 2, "offline": 1}}}}}


class RecoveryAuditTests(unittest.TestCase):
    def test_every_literal_event_and_result_uses_only_the_allowlist(self):
        for event in EVENTS:
            for result in ("started", "succeeded", "failed", "blocked"):
                validate(operation(event, result))
        for kind in ("device", "offline"):
            value = operation("recovery_share_lost", "succeeded")
            value["body"]["ext"]["org.palleria.recovery"]["holder_kind"] = kind
            validate(value)

    def test_secret_fields_wrong_counts_and_whole_set_holder_kind_are_refused_before_authorship(self):
        client = CryptoClient(" ".join(["abandon"] * 23 + ["art"]))
        mutations = [
            lambda op: op["body"].update(credential="public test credential"),
            lambda op: op["body"].update(subject_id=str(uuid.uuid4())),
            lambda op: op["body"].update(object_hash=b64(bytes(32))),
            lambda op: op["body"]["ext"]["org.palleria.recovery"].update(holder_instance_id=str(uuid.uuid4())),
            lambda op: op["body"]["ext"]["org.palleria.recovery"].update(holder_kind="device"),
            lambda op: op["body"]["ext"]["org.palleria.recovery"]["holder_counts"].update(device=3),
            lambda op: op["body"]["ext"]["org.palleria.recovery"].update(threshold=True),
            lambda op: op.update(created_at_ms=1 << 53),
        ]
        for change in mutations:
            value = copy.deepcopy(operation())
            change(value)
            with self.assertRaisesRegex(ValueError, "C_SCHEMA_VIOLATION"):
                client.record("pallasync.audit/3", [value])
            self.assertEqual((client.sequence, client.tail), (0, None))

    def test_exact_event_id_and_original_occurrence_time_survive_signature_and_aead_roundtrip(self):
        client = CryptoClient(" ".join(["abandon"] * 23 + ["art"]))
        value = operation()
        record = client.record("pallasync.audit/3", [value])
        self.assertEqual(client.decrypt(record)["operations"], [value])


if __name__ == "__main__":
    unittest.main()
