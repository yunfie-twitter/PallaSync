"""Actual Android coordinator + independent Python + disposable TLS relay boundary.

This targeted enrollment/outbox case is not IT-01..IT-50 completion.
Only the task-owned PallaSyncV3Conformance emulator is accepted.
"""
import argparse
import base64
from contextlib import ExitStack
import re
import subprocess
import uuid
from pathlib import Path
from protocol import b64, object_hash, strict_loads, verify
from attestations import Pin, ledger_hash
from crypto_client import CryptoClient
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT


def run(args):
    def adb(*command):
        result = subprocess.run([args.adb,"-s","emulator-5580",*command],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=600 if command[0] == "shell" else 240)
        if result.returncode != 0:
            raise RuntimeError("Managed emulator command failed: "+(result.stderr or "")[-2000:])
        return result.stdout

    if adb("emu","avd","name").splitlines()[0].strip() != "PallaSyncV3Conformance":
        raise RuntimeError("Only the disposable PallaSyncV3Conformance AVD is authorized")
    for apk in (args.app_apk,args.test_apk):
        if "Success" not in adb("install","-r","-t",str(Path(apk).resolve())):
            raise RuntimeError("APK installation did not succeed")
    client = CryptoClient(" ".join(["abandon"]*23+["art"]))
    schema = strict_loads((ROOT/"docs/privacy.schema.json").read_bytes())
    if args.delete_response_lost and not args.delete_chain:
        raise ValueError("--delete-response-lost requires --delete-chain")
    with ExitStack() as stack:
        relay = stack.enter_context(IsolatedRelay(args.relay_binary,chain_delay=1.5,drop_delete_response=args.delete_response_lost))
        target_relay = stack.enter_context(IsolatedRelay(args.relay_binary)) if args.reseed else None
        http = ReferenceHTTP(relay,client,True,schema)
        genesis = client.genesis()
        status,created,_ = http.request("POST","/pallasync/v3/chains",genesis,True)
        assert status == 201,created
        prefix = "/pallasync/v3/chains/"+client.chain
        from artifact_boundary import verify_relay_boundary
        verify_relay_boundary(http, client, prefix)
        python_record = client.record("palleria.search_history/3",[{"entity_id":"Python interop","operation":"upsert","lamport":1_000_000,"created_at_ms":1,"context":{},"body":{"query":"Python interop"}}])
        status,accepted,_ = http.request("POST",prefix+"/records",{"records":[python_record]})
        assert status == 200 and len(accepted["accepted"]) == 1,accepted
        port = relay.proxy.server_port
        adb("reverse",f"tcp:{port}",f"tcp:{port}")
        if target_relay is not None:
            adb("reverse",f"tcp:{target_relay.proxy.server_port}",f"tcp:{target_relay.proxy.server_port}")
        handoff = None
        if args.peer_enrollment:
            from android_peer import AndroidPeerHandoff
            handoff = AndroidPeerHandoff(args.adb,str(uuid.uuid4()),relay,client,genesis,schema,created["log_id"])
            handoff.thread.start()
        try:
            relay_cert = (relay.directory/"tls.pem").read_bytes()
            if target_relay is not None:
                relay_cert += (target_relay.directory/"tls.pem").read_bytes()
            command = ["shell","am","instrument","-w","-r","-e","class",
                "com.yunfie.illustia.pallasync.PallaSyncRelayInteropTest","-e","relay_origin",relay.origin,
                "-e","relay_ca_base64",base64.b64encode(relay_cert).decode(),
                "-e","rotate_epoch","true" if args.rotate_epoch else "false",
                "-e","replace_device","true" if args.replace_device else "false",
                "-e","delete_chain","true" if args.delete_chain else "false",
                "-e","delete_response_lost","true" if args.delete_response_lost else "false"]
            if target_relay is not None:
                command.extend(["-e","reseed_target_origin",target_relay.origin])
            if args.rebase_fault:
                command.extend(["-e","rebase_fault",args.rebase_fault])
            if handoff is not None:
                command.extend(["-e","peer_transfer_id",handoff.identifier])
            command.append("com.yunfie.illustia.test/com.yunfie.illustia.pallasync.PallaSyncTestRunner")
            output = adb(*command)
        finally:
            adb("reverse","--remove",f"tcp:{port}")
            if target_relay is not None:
                adb("reverse","--remove",f"tcp:{target_relay.proxy.server_port}")
        print(output[-6000:],flush=True)
        if not re.search(r"OK \(1 test\)",output):
            if args.delete_chain:
                deletion_status,deletion_proof,_ = http.request("GET",prefix+"/deletion",admin=True)
                safe_proof = {key: deletion_proof.get(key) for key in ("ledger","admin_operation","delete_receipt","deletion_transparency_entry")}
                authorization = deletion_proof.get("device_authorization")
                safe_proof["device_authorization"] = None if authorization is None else {"request": authorization.get("request")}
                print("DELETE PROOF DIAGNOSTIC",deletion_status,sorted(deletion_proof.keys()),
                      safe_proof,flush=True)
            if handoff is not None:
                handoff.stop.set()
                handoff.thread.join(timeout=25)
                if handoff.failure is not None:
                    raise handoff.failure
            raise RuntimeError("Actual Android integration test did not pass")
        if handoff is not None:
            handoff.finish()
        if target_relay is not None:
            if "pallasync_reseed_generation=1" not in output:
                raise RuntimeError("Android did not report a completed generation+1 reseed cutover")
            target_http = ReferenceHTTP(target_relay,client,True,schema)
            reseed_prefix = "/pallasync/v3/chains/"+client.chain
            status,parameters,_ = target_http.request("GET",reseed_prefix+"/parameters",admin=True)
            assert status == 200 and parameters["generation"] == 1 and parameters["parameters"]["generation"] == 1,parameters
            status,registry,_ = target_http.request("GET",reseed_prefix+"/devices",admin=True)
            assert status == 200,registry
            device_id = re.search(r"pallasync_reseed_device_id=([0-9a-f-]{36})",output)
            assert device_id is not None
            device = next(item["device_record"] for item in registry["items"] if item["device_record"]["device_id"] == device_id.group(1))
            verify(device,base64.urlsafe_b64decode(device["device_public_key"]+"="),b"PALLASYNC-DEVICE-RECORD-v3\0")
            verify(device["enrollment"],bytes(client.admin.verify_key),b"PALLASYNC-ENROLLMENT-v3\0")
            assert any(item["status"] == "active" and item["device_record"]["device_id"] == device["device_id"] for item in registry["items"])
            print("PASS: Android explicitly selected and consented to a second isolated relay, imported verified state, committed generation+1, validated the new relay authority, registered/read back/acked a fresh device, and switched origin; Python independently verified target parameters and device certificates",flush=True)
            return
        assert "pallasync_local_boundary=verified" in output,"No actual Android pre-persistence recovery-artifact boundary result"
        assert "pallasync_bound_origin=verified" in output,"No actual Android bound-origin check"
        if handoff is not None:
            assert "pallasync_peer_approval=verified" in output,"No actual Android peer approval result"
        print("PASS: actual Android JNI/Room rejected eight local artifact types, root-input shape and an encoded PSR3 package before application persistence, journal/outbox or author advancement",flush=True)
        print("PASS: actual Android rejected a different relay origin before chain transport and retained the protected origin binding",flush=True)
        if args.delete_chain:
            status,proof,_ = http.request("GET",prefix+"/deletion",admin=True)
            assert status == 200 and set(proof) == {"ledger","parameters","epoch","enrollment_chain","admin_operation","device_authorization","delete_receipt","deletion_transparency_entry"},proof
            pin = Pin(client.chain,created["log_id"],bytes(relay.relay_key.verify_key))
            ledger,receipt,entry = proof["ledger"],proof["delete_receipt"],proof["deletion_transparency_entry"]
            pin.signed(receipt,b"PALLASYNC-DELETE-RECEIPT-v3\0")
            assert ledger_hash(ledger) == receipt["ledger_receipt_hash"]
            assert ledger["chain_id"] == client.chain and ledger["deletion_id"] == receipt["deletion_id"]
            pin.signed(entry,b"PALLASYNC-TRANSPARENCY-ENTRY-v3\0")
            assert entry["operation"] == "delete" and entry["entry_index"] == receipt["transparency_index"]
            outcome = "after a deliberately lost DELETE response" if args.delete_response_lost else "after a confirmed DELETE response"
            print(f"PASS: Android GET /deletion proof {outcome}, local signed-proof/bundle file readback and post-confirmation erasure; Python independently verified relay receipt, deletion ledger and transparency signature",flush=True)
            return
        match = re.search(r"pallasync_device_id=([0-9a-f-]{36})",output)
        if match is None:
            raise RuntimeError("No public Android device identity was reported")
        subject = match.group(1)
        assert subject != client.device_id
        status,registry,_ = http.request("GET",prefix+"/devices",admin=True)
        assert status == 200,registry
        item = next(x for x in registry["items"] if x["device_record"]["device_id"] == subject)
        assert item["status"] == "active",item
        device = item["device_record"]
        verify(device,base64.urlsafe_b64decode(device["device_public_key"]+"="),b"PALLASYNC-DEVICE-RECORD-v3\0")
        verify(device["enrollment"],bytes(client.admin.verify_key),b"PALLASYNC-ENROLLMENT-v3\0")
        android_ids = {subject}
        old_android_device = None
        devices_by_id = {entry["device_record"]["device_id"]: entry for entry in registry["items"]}
        if args.replace_device:
            old_match = re.search(r"pallasync_replaced_old_device=([0-9a-f-]{36})",output)
            if old_match is None:
                raise RuntimeError("No old Android identity was reported for replacement")
            old_android_device = old_match.group(1)
            old_item = devices_by_id[old_android_device]
            assert old_item["status"] == "revoked",old_item
            android_ids.add(old_android_device)
        keys_by_epoch = {0: client.keys}
        if args.rotate_epoch or args.replace_device:
            from android_epoch import verify_android_epoch
            members = [client.device_id,device["device_id"]] + ([handoff.subject.device_id] if handoff is not None else [])
            if args.replace_device:
                keys_by_epoch[1] = verify_android_epoch(
                    http,client,genesis,created,device,bytes(relay.relay_key.verify_key),members,
                    reason="key_rotation",admin=False,revoked=[old_android_device])
            else:
                keys_by_epoch[1] = verify_android_epoch(http,client,genesis,created,device,bytes(relay.relay_key.verify_key),members)
        cursor,found,initial_found,rotated_found = None,False,False,False
        android_records = []
        paused_records = []
        replacement_records = []
        while True:
            path = prefix+"/records?limit=200"+("&cursor="+cursor if cursor else "")
            status,page,_ = http.request("GET",path)
            assert status == 200,page
            for entry in page["items"]:
                record = entry["object"]
                if record["device_id"] not in android_ids: continue
                client.keys = keys_by_epoch[record["epoch"]]
                record_device = devices_by_id[record["device_id"]]["device_record"]
                inner = client.decrypt(record,base64.urlsafe_b64decode(record_device["device_public_key"]+"="))
                android_records.append((record, inner))
                if any(op["body"].get("query") == "Android paused interop" for op in inner["operations"]):
                    paused_records.append((record, inner))
                if any(op["body"].get("query") == "Replacement pending" for op in inner["operations"]):
                    replacement_records.append((record, inner))
                found |= any(op["body"].get("query") == "Android interop" for op in inner["operations"])
                rotated_found |= record["epoch"] == 1 and any(op["body"].get("query") == "Android rotated interop" for op in inner["operations"])
                for op in inner["operations"]:
                    if op["body"].get("query") == "Python interop":
                        assert op["lamport"] > 1_000_000,"Initial local intent was stamped before the verified remote clock"
                        initial_found = True
                status,proof,_ = http.request("GET",prefix+"/receipts/"+str(entry["relay_seq"])+"?log_id="+created["log_id"])
                assert status == 200 and proof["entry"] == entry and proof["receipt"]["object_hash"] == object_hash(record),proof
            cursor = page["next_cursor"]
            if cursor is None: break
        assert found,"The independent receiver did not decrypt the Android-authored application operation"
        assert initial_found,"The independent receiver did not decrypt the preserved initial local intent"
        assert len(paused_records) == 1,"A paused editing intent was lost or signed twice"
        assert paused_records[0][0]["epoch"] == 0 and paused_records[0][1]["device_seq"] == 2
        if args.replace_device:
            assert len(replacement_records) == 1,"Replacement did not replay the unaccepted intent exactly once"
            assert replacement_records[0][0]["device_id"] == subject and replacement_records[0][0]["epoch"] == 1
            assert replacement_records[0][1]["device_seq"] == 1,"Fresh device author sequence did not start at one"
        print("PASS: actual Android disabled edit/projection preview, native session close/journal reopen and explicit same-identity resume; Python independently verified one exact accepted operation",flush=True)
        if args.rotate_epoch and not args.replace_device:
            assert rotated_found,"The independent receiver did not decrypt the post-ack Android epoch-one record"
            source_match = re.search(r"pallasync_rebase_sources=(\[[^\r\n]+\])",output)
            assert source_match is not None,"No public abandoned source ciphertext was reported"
            from android_rebase import verify_android_rebase
            verify_android_rebase(client,strict_loads(source_match.group(1).encode()),android_records,keys_by_epoch,base64.urlsafe_b64decode(device["device_public_key"]+"="))
        print("PASS: actual Android coordinator enrollment/initial sync/outbox -> isolated relay -> independent Python signature/AEAD receiver",flush=True)
        if args.replace_device:
            print("PASS: Android fresh-key replacement registered/read back/acked a new identity, committed device-signed key_rotation revoking the old ID, and Python independently verified the epoch and exactly-once reauthored intent",flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("adb","relay-binary","app-apk","test-apk"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--rotate-epoch",action="store_true")
    parser.add_argument("--replace-device",action="store_true")
    parser.add_argument("--peer-enrollment",action="store_true")
    parser.add_argument("--delete-chain",action="store_true")
    parser.add_argument("--delete-response-lost",action="store_true")
    parser.add_argument("--reseed",action="store_true",help="run a two-relay Android generation+1 reseed cutover")
    parser.add_argument(
        "--rebase-fault",
        choices=[
            "SOURCE_STAGED",
            "DESTINATION_COMMITTED",
            "SOURCE_RETIRED",
            "RESEED_ROOM_COMMITTED",
            "RESEED_KEYSTORE_PROMOTED",
            "RESEED_OUTBOX_REBASED",
            "RESEED_ORIGIN_SELECTED",
            "RESEED_COMPLETE_COMMITTED",
        ],
    )
    run(parser.parse_args())
