"""Independent §11.1 check for real Android stale-epoch sources and replacements.

Only public signed ciphertext leaves instrumentation. This process uses its own
epoch keys and Python crypto; no native/JNI construction or validation is shared.
"""
from protocol import object_hash


def verify_android_rebase(client, sources, accepted, keys_by_epoch, public_key):
    assert len(sources) == 2
    originals = []
    for source in sources:
        assert source["epoch"] == 0 and source["device_id"] == accepted[0][0]["device_id"]
        client.keys = keys_by_epoch[0]
        originals.append((source, client.decrypt(source, public_key)))
    source_ids = {record["record_id"] for record, _ in originals}
    source_nonces = {record["payload_nonce"] for record, _ in originals}
    assert not source_ids.intersection(record["record_id"] for record, _ in accepted)
    last_sequence = max(inner["device_seq"] for _, inner in originals)
    highest_lamport = max(op["lamport"] for _, inner in originals for op in inner["operations"])
    previous = object_hash(originals[-1][0])
    for offset, (_, original) in enumerate(originals, 1):
        expected = original["operations"][0]
        matches = [(r, inner) for r, inner in accepted if any(op["entity_id"] == expected["entity_id"] for op in inner["operations"])]
        assert len(matches) == 1, "A stale intent was lost or replayed twice"
        record, inner = matches[0]
        assert record["epoch"] == 1 and record["record_id"] not in source_ids and record["payload_nonce"] not in source_nonces
        assert inner["device_seq"] == last_sequence + offset and inner["prev_record_hash"] == previous
        assert inner["collection"] == original["collection"] and len(inner["operations"]) == 1
        op = inner["operations"][0]
        for field in ("entity_id", "operation", "body", "context"):
            assert op[field] == expected[field]
        assert op["lamport"] > max(highest_lamport, 1_000_000)
        highest_lamport = op["lamport"]
        previous = object_hash(record)
    print("PASS: actual Android stale-epoch rebase; Python independently verified absent old IDs, fresh IDs/nonces/seq/Lamport, exact preserved operations and predecessor links", flush=True)
