"""Independent test-client boundary for local-only artifacts (§§5.5/7.11).

No cryptographic implementation or runtime module is shared with the Rust clients.
"""

LOCAL_ARTIFACTS = frozenset((
    "PALLASYNC-RECOVERY-BLOB-v3", "PALLASYNC-RECOVERY-SET-v3",
    "PALLASYNC-RECOVERY-STATUS-v3", "PALLASYNC-RECOVERY-SHARE-v3",
    "PALLASYNC-RECOVERY-PACKAGE-v3", "PALLASYNC-OFFLINE-SHARE-KEY-v3",
    "PALLASYNC-RECOVERY-SESSION-v3", "PALLASYNC-RECOVERY-TRANSFER-v3",
))


def require_normal_data(value):
    if isinstance(value, dict):
        kind = value.get("type")
        if (isinstance(kind, str) and kind in LOCAL_ARTIFACTS) or {"mnemonic", "passphrase"} <= value.keys():
            raise ValueError("C_SCHEMA_VIOLATION")
        for child in value.values():
            require_normal_data(child)
    elif isinstance(value, list):
        for child in value:
            require_normal_data(child)
    elif isinstance(value, str) and value.startswith("PSR3:"):
        from protocol import decode, jcs, strict_loads
        if len(value) > 5 + ((4_194_304 + 2) // 3) * 4:
            return
        try:
            raw = decode(value[5:])
            package = strict_loads(raw, ceiling=4_194_304)
            canonical = jcs(package) == raw
        except (ValueError, UnicodeError, TypeError):
            return
        if canonical and isinstance(package, dict) and package.get("type") == "PALLASYNC-RECOVERY-PACKAGE-v3":
            raise ValueError("C_SCHEMA_VIOLATION")


def verify_relay_boundary(http, client, prefix):
    """Deliberately malformed signed public extensions, with opaque normal ciphertext."""
    import secrets
    import uuid
    from protocol import b64, signed

    status, before, _ = http.request("GET", prefix + "/log/head", admin=True)
    assert status == 200, before
    records = []
    for kind in sorted(LOCAL_ARTIFACTS):
        # A malformed-wire fixture has no application author sequence; the client is unchanged.
        record = {"version": "3.0", "chain_id": client.chain, "generation": 0,
                  "record_id": str(uuid.uuid4()), "device_id": client.device_id,
                  "epoch": client.epoch, "collection_tag": None,
                  "payload_nonce": b64(secrets.token_bytes(24)), "encrypted_payload": b64(bytes(1040))}
        record["ext"] = {"org.palleria.fixture": {"nested": [{"type": kind}]}}
        records.append(signed(record, client.device, b"PALLASYNC-SYNC-RECORD-v3\0"))
    status, result, _ = http.request("POST", prefix + "/records", {"records": records})
    assert status == 200 and result["accepted"] == [] and len(result["rejected"]) == 8, result
    assert all(item["code"] == "INVALID_FIELD" for item in result["rejected"]), result
    status, after, _ = http.request("GET", prefix + "/log/head", admin=True)
    assert status == 200, after
    assert (before["head_seq"], before["head_hash"]) == (after["head_seq"], after["head_hash"])
    print("PASS: independent Python signed public recovery-type extensions were rejected without data-log advancement", flush=True)
