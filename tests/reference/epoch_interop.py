"""Targeted independent rotation/CAS/revocation boundary; not complete IT-14/IT-50."""
import copy
import hmac
from protocol import b64, decode, epoch_keys, jcs, object_hash, signed, verify
from crypto_client import hpke_open
from http_client import ReferenceHTTP
from attestations import data_link, receipt, transparency_zero, transparency_link


def envelope_secret(client, envelope, signer):
    verify(envelope,signer,b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
    binding = {k:envelope[k] for k in ("envelope_id","chain_id","generation","epoch","previous_epoch_hash","epoch_commitment","recipient_kind","recipient_device_id","recipient_key_hash","signer_kind","signer_device_id")}
    secret = hpke_open(client.kex,decode(envelope["enc"],32),decode(envelope["ciphertext"]),b"PALLASYNC-EPOCH-ENVELOPE-v3\0"+jcs(binding),jcs(binding))
    keys = epoch_keys(client.roots["chain_id_digest"],envelope["epoch"],secret)
    assert hmac.compare_digest(keys["epoch-commitment"],decode(envelope["epoch_commitment"],32))
    return secret, keys


def epochs(relay,http,client,peer,genesis,enrollment,schema,pin,baseline):
    prefix = "/pallasync/v3/chains/"+client.chain
    parameters, old = genesis["parameters"], genesis["epoch"]
    devices = [genesis["device_record"],enrollment["body"]["device_record"]]
    proposal, secret, keys = client.propose_epoch(parameters,old,devices)
    loser, _, _ = client.propose_epoch(parameters,old,devices)
    bad = copy.deepcopy(proposal)
    bad["envelopes"].pop()
    status,problem,_ = http.request("POST",prefix+"/epochs",bad)
    assert status == 409 and problem["code"] == "MEMBER_SET_MISMATCH",problem
    status,unchanged,_ = http.request("GET",prefix+"/log/head")
    assert status == 200 and unchanged["head_seq"] == 9 and unchanged["epoch_hash"] == object_hash(old)
    for member in (client,peer):
        env = next(e for e in proposal["envelopes"] if e["recipient_device_id"] == member.device_id)
        recovered, derived = envelope_secret(member,env,bytes(client.device.verify_key))
        assert recovered == secret and derived == keys
    status,accepted,_ = http.request("POST",prefix+"/epochs",proposal)
    assert status == 201 and accepted["epoch_hash"] == object_hash(proposal["epoch"]),accepted
    status,retried,_ = http.request("POST",prefix+"/epochs",proposal)
    assert status == 200 and retried == accepted,retried
    status,conflict,_ = http.request("POST",prefix+"/epochs",loser)
    assert status == 409 and conflict["code"] == "CAS_MISMATCH",conflict
    relay.restart()
    status,head,_ = http.request("GET",prefix+"/log/head")
    assert status == 200 and head["head_seq"] == 13 and head["epoch_hash"] == accepted["epoch_hash"]
    client.epoch = peer.epoch = proposal["epoch"]["epoch"]
    client.secret = peer.secret = secret
    client.keys = peer.keys = keys
    subject = ReferenceHTTP(relay,peer,True,schema)
    ack = {"epoch_hash":accepted["epoch_hash"],"epoch_commitment":proposal["epoch"]["epoch_commitment"]}
    status,acked,_ = subject.request("POST",prefix+"/devices/"+peer.device_id+"/keys/ack",ack)
    assert status == 200 and acked["status"] == "active",acked
    record = peer.record("palleria.search_history/3",[{"entity_id":"epoch-one","operation":"upsert","lamport":2,"created_at_ms":2,"context":{},"body":{"query":"epoch-one"}}])
    status,upload,_ = subject.request("POST",prefix+"/records",{"records":[record]})
    assert status == 200 and len(upload["accepted"]) == 1,upload
    assert client.decrypt(record,bytes(peer.device.verify_key))["operations"][0]["body"]["query"] == "epoch-one"
    revoked, new_secret, new_keys = client.propose_epoch(parameters,proposal["epoch"],[devices[1]],[client.device_id],"emergency",True)
    wrong_target = copy.deepcopy(revoked)
    wrong_target["admin_operation"]["target_hash"] = object_hash({"epoch":revoked["epoch"],"envelopes":[]})
    wrong_target["admin_operation"] = signed(wrong_target["admin_operation"],client.admin,b"PALLASYNC-ADMIN-OP-v3\0")
    status,problem,_ = http.request("POST",prefix+"/devices/"+client.device_id+"/revoke",wrong_target,admin=True)
    assert status == 400 and problem["code"] == "INVALID_FIELD",problem
    status,unchanged,_ = http.request("GET",prefix+"/log/head")
    assert status == 200 and unchanged["head_seq"] == 14 and unchanged["epoch_hash"] == accepted["epoch_hash"]
    env = next(e for e in revoked["envelopes"] if e["recipient_device_id"] == peer.device_id)
    recovered, derived = envelope_secret(peer,env,bytes(client.admin.verify_key))
    assert recovered == new_secret and derived == new_keys
    status,revocation,_ = http.request("POST",prefix+"/devices/"+client.device_id+"/revoke",revoked,admin=True)
    assert status == 200 and revocation["status"] == "revoked",revocation
    status,denied,_ = http.request("GET",prefix+"/records")
    assert status == 403 and denied["code"] == "DEVICE_REVOKED",denied
    status,denied,_ = subject.request("GET",prefix+"/log?after_seq=9")
    assert status == 403 and denied["code"] == "ENVELOPE_ACCESS_DENIED",denied
    pages, cursor = [], None
    while True:
        status,page,_ = http.request("GET",prefix+"/log?limit=3"+("&cursor="+cursor if cursor else "&after_seq=9"),admin=True)
        assert status == 200,page
        pages.append(page)
        cursor = page["next_cursor"]
        if cursor is None: break
    receipts = {r["relay_seq"]:r for r in [*accepted["upload_receipts"],*upload["upload_receipts"],*revocation["upload_receipts"]]}
    previous = enrollment["parameters"]["head_hash"]
    for page in pages:
        for entry in page["items"]:
            evidence = receipts[entry["relay_seq"]]
            receipt(evidence,entry["object"],entry,pin)
            previous = data_link(previous,entry)
    status,head,_ = subject.request("GET",prefix+"/log/head")
    assert status == 200 and head["head_seq"] == 18 and head["head_hash"] == previous and head["epoch_hash"] == revocation["epoch_hash"]
    entries = {e["relay_seq"]:e for p in [*baseline["log_pages"],*enrollment["log_pages"],*pages] for e in p["items"]}
    receipts.update({r["relay_seq"]:r for r in [*baseline["created"]["upload_receipts"],*baseline["record_upload"]["upload_receipts"],*enrollment["accepted"]["upload_receipts"]]})
    status,transparency,_ = subject.request("GET",prefix+"/transparency/head")
    assert status == 200
    transparency = transparency["head"]
    pin.signed(transparency,b"PALLASYNC-TRANSPARENCY-HEAD-v3\0")
    assert transparency["head_hash"] == head["head_hash"] and transparency["epoch_hash"] == head["epoch_hash"]
    transparency_pages, cursor, index = [], None, 0
    previous = transparency_zero(client.chain,transparency["transparency_id"],pin.public_key)
    while True:
        path = prefix+"/transparency/entries?transparency_id="+transparency["transparency_id"]+"&limit=200"+("&cursor="+cursor if cursor else "")
        status,page,_ = subject.request("GET",path)
        assert status == 200 and page["anchor_index"] == index and page["anchor_hash"] == previous,page
        transparency_pages.append(page)
        for entry in page["items"]:
            index += 1
            assert entry["entry_index"] == index
            previous = transparency_link(previous,entry,pin)
            if entry["operation"] == "accept":
                sequence = entry["relay_seq"]
                assert sequence is not None
                receipt(receipts[sequence],entries[sequence]["object"],entries[sequence],pin,entry)
        cursor = page["next_cursor"]
        if cursor is None: break
    assert index == transparency["entry_index"] and previous == transparency["transparency_hash"]
    print("PASS: independent complete epoch delivery, exact retry, competing CAS, restart, new-epoch ciphertext and atomic revocation; recovery log access remains denied to D",flush=True)
    return {"manual_body":proposal,"manual_accepted":accepted,"record":record,"record_upload":upload,"revocation_body":revoked,"revocation_accepted":revocation,"log_pages":pages,"log_head":head,"transparency_head":transparency,"transparency_pages":transparency_pages}
