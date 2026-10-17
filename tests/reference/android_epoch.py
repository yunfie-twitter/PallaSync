"""Independent verification of an actual Android-created epoch bundle and H/T.

This is a targeted rotation/delivery test, not completion of the IT catalogue.
"""
import hmac
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from protocol import decode, epoch_keys, jcs, object_hash, verify
from epoch_interop import envelope_secret
from attestations import Pin, data_zero, data_link, receipt, transparency_zero, transparency_link


def verify_android_epoch(http, client, genesis, created, device, relay_key, expected_members=None,
                         reason="manual", admin=False, revoked=()):
    prefix = "/pallasync/v3/chains/" + client.chain
    status, item, _ = http.request("GET", prefix + "/epochs/1", admin=True)
    assert status == 200, item
    epoch = item["epoch"]
    signer = bytes(client.admin.verify_key) if admin else decode(device["device_public_key"], 32)
    verify(epoch, signer, b"PALLASYNC-EPOCH-v3\0")
    assert (epoch["chain_id"] == client.chain and epoch["generation"] == 0 and epoch["epoch"] == 1
            and epoch["previous_epoch_hash"] == object_hash(genesis["epoch"])
            and epoch["reason"] == reason and epoch["signer_kind"] == ("admin" if admin else "device")
            and epoch["signer_device_id"] == (None if admin else device["device_id"])
            and epoch["revoked_device_ids"] == sorted(revoked)
            and epoch["members"] == sorted(expected_members or [client.device_id, device["device_id"]]))
    assert item["epoch_hash"] == object_hash(epoch)
    status, page, _ = http.request("GET", prefix + "/devices/" + client.device_id + "/envelopes?epoch=1&limit=200", admin=True)
    assert status == 200 and not page["has_more"], page
    envelope = page["items"][0]
    secret, keys = envelope_secret(client, envelope, signer)
    status, response, _ = http.request("GET", prefix + "/epochs/1/recovery-envelope", admin=True)
    assert status == 200, response
    recovery = response["envelope"]
    verify(recovery, signer, b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
    assert object_hash(recovery) == epoch["recovery_envelope_hash"]
    binding = {k: recovery[k] for k in ("envelope_id", "chain_id", "generation", "epoch", "previous_epoch_hash", "epoch_commitment", "recipient_kind", "recipient_device_id", "recipient_key_hash", "signer_kind", "signer_device_id")}
    recovered = crypto_aead_xchacha20poly1305_ietf_decrypt(decode(recovery["ciphertext"]), jcs(binding), decode(recovery["nonce"], 24), client.roots["recovery_kek"])
    assert hmac.compare_digest(secret, recovered)
    assert hmac.compare_digest(keys["epoch-commitment"], decode(epoch["epoch_commitment"], 32))
    assert keys == epoch_keys(client.roots["chain_id_digest"], 1, recovered)

    pin = Pin(client.chain, created["log_id"], relay_key)
    entries, receipts, cursor = {}, {}, None
    previous = data_zero(client.chain, pin.log)
    while True:
        status, page, _ = http.request("GET", prefix + "/log?limit=200" + ("&cursor=" + cursor if cursor else ""), admin=True)
        assert status == 200, page
        for entry in page["items"]:
            sequence = entry["relay_seq"]
            assert sequence == len(entries) + 1
            status, proof, _ = http.request("GET", prefix + "/receipts/" + str(sequence) + "?log_id=" + pin.log, admin=True)
            assert status == 200 and proof["entry"] == entry, proof
            receipt(proof["receipt"], entry["object"], entry, pin)
            assert proof["receipt"]["previous_head_hash"] == previous
            previous = data_link(previous, entry)
            assert proof["receipt"]["resulting_head_hash"] == previous
            entries[sequence], receipts[sequence] = entry, proof["receipt"]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    own_bundle = [e["object"] for e in entries.values() if e["kind"] == "envelope" and e["object"]["epoch"] == 1]
    assert len(own_bundle) == len(epoch["members"]) + 1
    assert sorted(e["recipient_device_id"] for e in own_bundle if e["recipient_kind"] == "device") == epoch["members"]
    for item in own_bundle:
        verify(item, signer, b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
        for field in ("chain_id", "generation", "epoch", "previous_epoch_hash", "epoch_commitment", "signer_kind", "signer_device_id"):
            assert item[field] == epoch[field]
    status, head, _ = http.request("GET", prefix + "/transparency/head", admin=True)
    assert status == 200, head
    head = head["head"]
    pin.signed(head, b"PALLASYNC-TRANSPARENCY-HEAD-v3\0")
    assert head["head_seq"] == len(entries) and head["head_hash"] == previous and head["epoch_hash"] == object_hash(epoch)
    previous = transparency_zero(client.chain, head["transparency_id"], relay_key)
    cursor, index = None, 0
    while True:
        path = prefix + "/transparency/entries?transparency_id=" + head["transparency_id"] + "&limit=200" + ("&cursor=" + cursor if cursor else "")
        status, page, _ = http.request("GET", path, admin=True)
        assert status == 200 and page["anchor_index"] == index and page["anchor_hash"] == previous, page
        for item in page["items"]:
            index += 1
            assert item["entry_index"] == index
            previous = transparency_link(previous, item, pin)
            if item["operation"] == "accept":
                sequence = item["relay_seq"]
                receipt(receipts[sequence], entries[sequence]["object"], entries[sequence], pin, item)
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert index == head["entry_index"] and previous == head["transparency_hash"]
    print("PASS: actual Android-created complete epoch bundle; independent Python HPKE, root recovery envelope, commitment and original H/T receipts", flush=True)
    return keys
