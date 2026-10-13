"""Run actual Python -> isolated HTTPS relay boundary tests. Not the full three-party IT suite."""
import argparse
import time
import uuid
from pathlib import Path
from protocol import b64, decode, digest, jcs, object_hash, signed, strict_loads, verify
from attestations import Pin, data_zero, data_link, receipt, transparency_zero, transparency_link
from crypto_client import CryptoClient, hpke_open
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT


def run(binary, epoch_checks=False):
    client = CryptoClient(" ".join(["abandon"]*23+["art"]))
    genesis = client.genesis()
    schema = strict_loads((ROOT/"docs/privacy.schema.json").read_bytes())
    with IsolatedRelay(binary, chain_delay=1.5 if epoch_checks else 0) as relay:
        print("Isolated TLS relay started",flush=True)
        http = ReferenceHTTP(relay,client,True,schema)
        prefix = "/pallasync/v3/chains/"+client.chain
        status,created,_ = http.request("POST","/pallasync/v3/chains",genesis,True)
        assert status == 201,created
        print("Independent genesis accepted",flush=True)
        pin = Pin(client.chain,created["log_id"],bytes(relay.relay_key.verify_key))
        known = {object_hash(value):value for value in [genesis["parameters"],genesis["device_record"],genesis["epoch"],*genesis["envelopes"]]}
        assert len(created["upload_receipts"]) == 5
        record = client.record("palleria.search_history/3",[{"entity_id":"猫","operation":"upsert","lamport":1,"created_at_ms":1,"context":{},"body":{"query":"猫"}}])
        assert client.decrypt(record)["operations"][0]["body"]["query"] == "猫"
        status,accepted,_ = http.request("POST",prefix+"/records",{"records":[record]})
        assert status == 200 and len(accepted["accepted"]) == 1,accepted
        entry = accepted["accepted"][0]["receipt"]
        original = accepted["upload_receipts"][0]
        receipt(original,record,entry,pin)
        status,retry,_ = http.request("POST",prefix+"/records",{"records":[record]})
        assert status == 200 and retry["accepted"][0]["duplicate"] is True and retry["upload_receipts"][0] == original
        status,proof,_ = http.request("GET",prefix+"/receipts/6?log_id="+pin.log)
        assert status == 200 and proof["entry"] == entry and proof["receipt"] == original
        status,_,token = http.request("GET",prefix+"/parameters")
        assert status == 200
        status,replay,_ = http.request("GET",prefix+"/parameters",token=token)
        assert status == 401 and replay["code"] == "TOKEN_REPLAYED"
        relay.restart()
        print("Persistent isolated relay restarted",flush=True)
        status,replay,_ = http.request("GET",prefix+"/parameters",token=token)
        assert status == 401 and replay["code"] == "TOKEN_REPLAYED"
        status,params,_ = http.request("GET",prefix+"/parameters")
        assert status == 200 and params["head_hash"] == accepted["head_hash"] and params["log_id"] == pin.log
        status,denied,_ = http.request("GET",prefix+"/log")
        assert status == 403 and denied["code"] == "ENVELOPE_ACCESS_DENIED"
        cursor,entries = None,[]
        log_pages = []
        while True:
            path = prefix+"/log?limit=3" + ("&cursor="+cursor if cursor else "")
            status,page,_ = http.request("GET",path,admin=True)
            assert status == 200,page
            log_pages.append(page)
            entries.extend(page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break
        previous = data_zero(client.chain,pin.log)
        receipts = {item["relay_seq"]:item for item in [*created["upload_receipts"],original]}
        for index,item in enumerate(entries,1):
            assert item["relay_seq"] == index
            obj = item["object"]
            if item["kind"] == "record":
                assert client.decrypt(obj)["device_seq"] == 1
            else:
                assert known[object_hash(obj)] == obj
                key = bytes(client.device.verify_key) if item["kind"] == "device" else bytes(client.admin.verify_key)
                context = {"parameters":b"PALLASYNC-CHAIN-PARAMS-v3\0","device":b"PALLASYNC-DEVICE-RECORD-v3\0","envelope":b"PALLASYNC-EPOCH-ENVELOPE-v3\0","epoch":b"PALLASYNC-EPOCH-v3\0"}[item["kind"]]
                verify(obj,key,context)
            receipt(receipts[index],obj,item,pin)
            previous = data_link(previous,item)
        assert previous == accepted["head_hash"] and len(entries) == 6
        status,data_head,_ = http.request("GET",prefix+"/log/head")
        assert status == 200 and set(data_head) == {"log_id","generation","head_seq","head_hash","min_available_seq","epoch_hash","parameters_hash"}
        assert data_head["generation"] == 0 and data_head["head_hash"] == accepted["head_hash"]
        status,head,_ = http.request("GET",prefix+"/transparency/head")
        assert status == 200
        head = head["head"]
        for name in set(data_head)-{"generation"}:
            assert data_head[name] == head[name]
        pin.signed(head,b"PALLASYNC-TRANSPARENCY-HEAD-v3\0")
        previous = transparency_zero(client.chain,head["transparency_id"],pin.public_key)
        cursor,index = None,0
        transparency_pages = []
        while True:
            path = prefix+"/transparency/entries?transparency_id="+head["transparency_id"]+"&limit=3"+("&cursor="+cursor if cursor else "")
            status,page,_ = http.request("GET",path)
            assert status == 200 and page["anchor_index"] == index and page["anchor_hash"] == previous,page
            transparency_pages.append(page)
            for item in page["items"]:
                index += 1
                assert item["entry_index"] == index
                previous = transparency_link(previous,item,pin)
                receipt(receipts[item["relay_seq"]],entries[item["relay_seq"]-1]["object"],entries[item["relay_seq"]-1],pin,item)
            cursor = page["next_cursor"]
            if cursor is None:
                break
        assert index == head["entry_index"] and previous == head["transparency_hash"]
        print("PASS: independent Python genesis, encrypted record, original receipt retry, full H/T paging, restart nonce persistence, recovery-envelope access denial")
        public_evidence = {"identity":{"chain_id":client.chain,"admin_public_key":b64(bytes(client.admin.verify_key))},
                           "origin":relay.origin,"relay_public_key":b64(pin.public_key),"genesis":genesis,"created":created,"record":record,
                           "record_upload":accepted,"parameters":params,"log_pages":log_pages,"log_head":data_head,"transparency_head":head,"transparency_pages":transparency_pages}
        peer = CryptoClient(" ".join(["abandon"]*23+["art"]))
        public_evidence["enrollment"] = enrollment(relay, http, client, genesis, params, schema, pin, peer)
        if epoch_checks:
            from epoch_interop import epochs
            public_evidence["epoch_checks"] = epochs(relay,http,client,peer,genesis,public_evidence["enrollment"],schema,pin,public_evidence)
    return public_evidence


def enrollment(relay, http, client, genesis, params, schema, pin, peer=None):
    peer = peer or CryptoClient(" ".join(["abandon"]*23+["art"]))
    peer.secret, peer.keys = client.secret, client.keys
    candidate = peer.genesis()
    action = {"device_record":candidate["device_record"],"envelopes":[candidate["envelopes"][0]]}
    operation = signed({"operation_id":str(uuid.uuid4()),"chain_id":client.chain,"generation":0,"action":"approve_enrollment",
        "expected_parameters_hash":params["parameters_hash"],"expected_epoch_hash":params["epoch_hash"],
        "target_hash":object_hash(action),"created_at_ms":int(time.time()*1000)},client.admin,b"PALLASYNC-ADMIN-OP-v3\0")
    body = {**action,"admin_operation":operation}
    prefix = "/pallasync/v3/chains/"+client.chain
    status,accepted,_ = http.request("POST",prefix+"/devices/enroll",body,admin=True)
    assert status == 201 and accepted["status"] == "pending_keys" and len(accepted["upload_receipts"]) == 3,accepted
    status,retried,_ = http.request("POST",prefix+"/devices/enroll",body,admin=True)
    assert status == 200 and retried == accepted,retried
    subject = ReferenceHTTP(relay,peer,True,schema)
    status,denied,_ = subject.request("GET",prefix+"/records")
    assert status == 403 and denied["code"] == "DEVICE_PENDING_KEYS",denied
    status,page,_ = subject.request("GET",prefix+"/devices/"+peer.device_id+"/envelopes")
    assert status == 200 and page["items"] == action["envelopes"],page
    envelope = page["items"][0]
    binding = {name:envelope[name] for name in ("envelope_id","chain_id","generation","epoch","previous_epoch_hash","epoch_commitment","recipient_kind","recipient_device_id","recipient_key_hash","signer_kind","signer_device_id")}
    verify(envelope,bytes(client.admin.verify_key),b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
    recovered = hpke_open(peer.kex,decode(envelope["enc"],32),decode(envelope["ciphertext"]),b"PALLASYNC-EPOCH-ENVELOPE-v3\0"+jcs(binding),jcs(binding))
    assert recovered == peer.secret and envelope["epoch_commitment"] == b64(peer.keys["epoch-commitment"])
    ack = {"epoch_hash":params["epoch_hash"],"epoch_commitment":envelope["epoch_commitment"]}
    status,acked,_ = subject.request("POST",prefix+"/devices/"+peer.device_id+"/keys/ack",ack)
    assert status == 200 and acked == {"device_id":peer.device_id,"status":"active","epoch_hash":params["epoch_hash"]},acked
    status,records,_ = subject.request("GET",prefix+"/records")
    assert status == 200 and peer.decrypt(records["items"][0]["object"],bytes(client.device.verify_key))["device_seq"] == 1,records
    pages,cursor = [],None
    while True:
        path = prefix+"/log?limit=3" + ("&cursor="+cursor if cursor else "&after_seq=6")
        status,page,_ = http.request("GET",path,admin=True)
        assert status == 200,page
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None: break
    receipts = {r["relay_seq"]:r for r in accepted["upload_receipts"]}
    previous = params["head_hash"]
    for page in pages:
        for entry in page["items"]:
            r = receipts[entry["relay_seq"]]
            receipt(r,entry["object"],entry,pin)
            previous = data_link(previous,entry)
    status,current,_ = http.request("GET",prefix+"/parameters")
    assert status == 200 and current["head_seq"] == 9 and current["head_hash"] == previous,current
    status,head,_ = http.request("GET",prefix+"/transparency/head")
    assert status == 200
    print("PASS: independent pending enrollment, exact retry, verified HPKE key receipt, pending restrictions and acknowledgement",flush=True)
    return {"body":body,"accepted":accepted,"ack_body":ack,"acked":acked,"log_pages":pages,"parameters":current,"transparency_head":head["head"]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-binary",required=True)
    parser.add_argument("--public-evidence-output")
    parser.add_argument("--epoch-checks",action="store_true")
    args = parser.parse_args()
    evidence = run(args.relay_binary,args.epoch_checks)
    if args.public_evidence_output:
        destination = Path(args.public_evidence_output)
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(jcs(evidence)+b"\n")
