"""Targeted independent Python peer enrollment against a disposable relay.

This does not run Android or complete IT-01..IT-50. Confirmation calls here are explicit test inputs.
"""
import argparse
import secrets
import time
import uuid
from attestations import Pin, data_link, data_zero, receipt
from crypto_client import CryptoClient, hpke_seal
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT
from peer_client import PeerClient
from peer_sas import sas
from protocol import b64, digest, jcs, object_hash, signed, strict_loads


def public_request(http, prefix, request):
    for attempt in range(3):
        http.check_policy()
        status, raw, _ = http.raw("POST", prefix + "/enrollment-requests", jcs(request))
        result = strict_loads(raw)
        if status != 429:
            return status, result
        assert result["code"] == "RATE_LIMITED" and result["retryable"] is True, result
        wait = result["context"]["retry_after_ms"]
        assert 0 < wait < 60000, result
        time.sleep((wait + 100) / 1000)
    raise RuntimeError("Disposable public enrollment rate limit did not clear")


def run(binary):
    creator = CryptoClient(" ".join(["abandon"] * 23 + ["art"]))
    schema = strict_loads((ROOT / "docs/privacy.schema.json").read_bytes())
    with IsolatedRelay(binary, chain_delay=1.5) as relay:
        approver = ReferenceHTTP(relay, creator, True, schema)
        genesis = creator.genesis()
        status, created, _ = approver.request("POST", "/pallasync/v3/chains", genesis, True)
        assert status == 201, created
        prefix = "/pallasync/v3/chains/" + creator.chain
        now = int(time.time() * 1000)
        body = {"request_id": str(uuid.uuid4()), "offer_nonce": b64(secrets.token_bytes(32)), "expires_at_ms": now + 300000}
        status, offered, _ = approver.request("POST", prefix + "/enrollment-offers", body)
        assert status == 201, offered
        stored = {**body, "chain_id": creator.chain, "generation": 0, "offering_device_id": creator.device_id}
        assert offered == {"request_id": body["request_id"], "expires_at_ms": body["expires_at_ms"], "offer_hash": object_hash(stored)}
        offer = {"protocol": "pallasync/3", "relay_origin": relay.origin, "chain_id": creator.chain, "generation": 0,
            "parameters_hash": object_hash(genesis["parameters"]), "epoch_hash": object_hash(genesis["epoch"]), **body,
            "admin_public_key": b64(bytes(creator.admin.verify_key)), "approver_device_id": creator.device_id,
            "approver_device_public_key": b64(bytes(creator.device.verify_key)), "approver_device_kex_public_key": b64(creator.kex_public),
            "approver_device_record_hash": object_hash(genesis["device_record"])}
        subject = PeerClient(offer, True)
        pending = ReferenceHTTP(relay, subject, True, schema)
        status, requested = public_request(pending, prefix, subject.request)
        assert status == 201 and requested == {"request_id":body["request_id"], "status":"awaiting_approval", "request_hash":object_hash(subject.request)}, requested
        # The relay has no bearer membership grant for this public request; P cannot read records.
        other = PeerClient(offer, True)
        status, result = public_request(pending, prefix, other.request)
        assert status == 409 and result["code"] == "REQUEST_ID_CONFLICT", (status,result)
        status, page, _ = approver.request("GET", prefix + "/enrollment-requests?limit=200")
        assert status == 200 and page["items"][0]["request"] == subject.request, page
        visual = sas(creator.kex, offer, subject.request, "approver")
        assert visual == subject.visual
        subject.confirm(visual, True)
        certificate = signed({"chain_id":creator.chain,"generation":0,"certificate_id":str(uuid.uuid4()),
            "device_id":subject.device_id,"device_public_key":subject.request["device_public_key"],"device_kex_public_key":subject.request["device_kex_public_key"],
            "signer_kind":"device","signer_device_id":creator.device_id,"request_hash":object_hash(subject.request),"approved_at_ms":int(time.time()*1000)},creator.device,b"PALLASYNC-ENROLLMENT-v3\0")
        epoch = genesis["epoch"]
        binding = {"envelope_id":str(uuid.uuid4()),"chain_id":creator.chain,"generation":0,"epoch":0,"previous_epoch_hash":None,
            "epoch_commitment":epoch["epoch_commitment"],"recipient_kind":"device","recipient_device_id":subject.device_id,
            "recipient_key_hash":b64(digest(subject.kex_public)),"signer_kind":"device","signer_device_id":creator.device_id}
        enc, cipher = hpke_seal(subject.kex_public,creator.secret,b"PALLASYNC-EPOCH-ENVELOPE-v3\0"+jcs(binding),jcs(binding))
        envelope = signed({**binding,"enc":b64(enc),"nonce":None,"ciphertext":b64(cipher)},creator.device,b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
        approval = subject.prepare(certificate,envelope,epoch)
        assert secrets.compare_digest(subject.secret,creator.secret)
        status, accepted, _ = approver.request("POST",prefix+"/enrollment-requests/"+body["request_id"]+"/approve",approval)
        assert status == 201 and accepted["status"] == "pending_keys", accepted
        original = accepted["upload_receipts"]
        relay.restart()
        status, retry, _ = approver.request("POST",prefix+"/enrollment-requests/"+body["request_id"]+"/approve",approval)
        assert status == 200 and retry["upload_receipts"] == original, retry
        status, refused, _ = pending.request("GET",prefix+"/records?limit=200")
        assert status == 403 and refused["code"] == "DEVICE_PENDING_KEYS", refused
        status, delivered, _ = pending.request("GET",prefix+"/devices/"+subject.device_id+"/envelopes?epoch=0&limit=200")
        assert status == 200 and delivered["items"] == [envelope], delivered
        subject.verify_envelope(delivered["items"][0],epoch)
        status, ack, _ = pending.request("POST",prefix+"/devices/"+subject.device_id+"/keys/ack",subject.ack(epoch))
        assert status == 200 and ack == {"device_id":subject.device_id,"status":"active","epoch_hash":object_hash(epoch)}, ack
        record = subject.record("palleria.search_history/3",[{"entity_id":"peer fixture","operation":"upsert","lamport":1,"created_at_ms":1,"context":{},"body":{"query":"peer fixture"}}])
        status, uploaded, _ = pending.request("POST",prefix+"/records",{"records":[record]})
        assert status == 200 and len(uploaded["accepted"]) == 1, uploaded
        assert creator.decrypt(record, bytes(subject.device.verify_key))["operations"][0]["body"]["query"] == "peer fixture"
        pin = Pin(creator.chain,created["log_id"],bytes(relay.relay_key.verify_key))
        evidence = {r["relay_seq"]:r for r in [*created["upload_receipts"],*original,*uploaded["upload_receipts"]]}
        status, log, _ = approver.request("GET",prefix+"/log?limit=200",admin=True)
        assert status == 200, log
        previous = data_zero(creator.chain,pin.log)
        for entry in log["items"]:
            receipt(evidence[entry["relay_seq"]],entry["object"],entry,pin)
            previous = data_link(previous,entry)
        assert previous == log["head_hash"]
        print("PASS: independent Python bound offer/request/SAS, self-signed subject, HPKE commitment, P access denial, delivered envelope/ack, relay restart/original receipt retry and full data-log prefix",flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-binary",required=True)
    run(parser.parse_args().relay_binary)
