"""Actual Android coordinator + independent Python + disposable TLS relay boundary.

This targeted enrollment/outbox case is not IT-01..IT-50 completion.
Only the task-owned PallaSyncV3Conformance emulator is accepted.
"""
import argparse
import base64
import re
import subprocess
import uuid
from pathlib import Path
from protocol import b64, object_hash, strict_loads, verify
from crypto_client import CryptoClient
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT


def run(args):
    def adb(*command):
        result = subprocess.run([args.adb,"-s","emulator-5580",*command],capture_output=True,text=True,timeout=600 if command[0] == "shell" else 240)
        if result.returncode != 0:
            raise RuntimeError("Managed emulator command failed: "+result.stderr[-2000:])
        return result.stdout

    if adb("emu","avd","name").splitlines()[0].strip() != "PallaSyncV3Conformance":
        raise RuntimeError("Only the disposable PallaSyncV3Conformance AVD is authorized")
    for apk in (args.app_apk,args.test_apk):
        if "Success" not in adb("install","-r","-t",str(Path(apk).resolve())):
            raise RuntimeError("APK installation did not succeed")
    client = CryptoClient(" ".join(["abandon"]*23+["art"]))
    schema = strict_loads((ROOT/"docs/privacy.schema.json").read_bytes())
    with IsolatedRelay(args.relay_binary,chain_delay=1.5) as relay:
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
        handoff = None
        if args.peer_enrollment:
            from android_peer import AndroidPeerHandoff
            handoff = AndroidPeerHandoff(args.adb,str(uuid.uuid4()),relay,client,genesis,schema,created["log_id"])
            handoff.thread.start()
        try:
            command = ["shell","am","instrument","-w","-r","-e","class",
                "com.yunfie.illustia.pallasync.PallaSyncRelayInteropTest","-e","relay_origin",relay.origin,
                "-e","relay_ca_base64",base64.b64encode((relay.directory/"tls.pem").read_bytes()).decode(),
                "-e","rotate_epoch","true" if args.rotate_epoch else "false"]
            if args.rebase_fault:
                command.extend(["-e","rebase_fault",args.rebase_fault])
            if handoff is not None:
                command.extend(["-e","peer_transfer_id",handoff.identifier])
            command.append("com.yunfie.illustia.test/com.yunfie.illustia.pallasync.PallaSyncTestRunner")
            output = adb(*command)
        finally:
            adb("reverse","--remove",f"tcp:{port}")
        print(output[-6000:],flush=True)
        if not re.search(r"OK \(1 test\)",output):
            if handoff is not None:
                handoff.stop.set()
                handoff.thread.join(timeout=25)
                if handoff.failure is not None:
                    raise handoff.failure
            raise RuntimeError("Actual Android integration test did not pass")
        if handoff is not None:
            handoff.finish()
        assert "pallasync_local_boundary=verified" in output,"No actual Android pre-persistence recovery-artifact boundary result"
        assert "pallasync_bound_origin=verified" in output,"No actual Android bound-origin check"
        if handoff is not None:
            assert "pallasync_peer_approval=verified" in output,"No actual Android peer approval result"
        print("PASS: actual Android JNI/Room rejected eight local artifact types, root-input shape and an encoded PSR3 package before application persistence, journal/outbox or author advancement",flush=True)
        print("PASS: actual Android rejected a different relay origin before chain transport and retained the protected origin binding",flush=True)
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
        keys_by_epoch = {0: client.keys}
        if args.rotate_epoch:
            from android_epoch import verify_android_epoch
            members = [client.device_id,device["device_id"]] + ([handoff.subject.device_id] if handoff is not None else [])
            keys_by_epoch[1] = verify_android_epoch(http,client,genesis,created,device,bytes(relay.relay_key.verify_key),members)
        cursor,found,initial_found,rotated_found = None,False,False,False
        android_records = []
        paused_records = []
        while True:
            path = prefix+"/records?limit=200"+("&cursor="+cursor if cursor else "")
            status,page,_ = http.request("GET",path)
            assert status == 200,page
            for entry in page["items"]:
                record = entry["object"]
                if record["device_id"] != subject: continue
                client.keys = keys_by_epoch[record["epoch"]]
                inner = client.decrypt(record,base64.urlsafe_b64decode(device["device_public_key"]+"="))
                android_records.append((record, inner))
                if any(op["body"].get("query") == "Android paused interop" for op in inner["operations"]):
                    paused_records.append((record, inner))
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
        print("PASS: actual Android disabled edit/projection preview, native session close/journal reopen and explicit same-identity resume; Python independently verified one exact accepted operation",flush=True)
        if args.rotate_epoch:
            assert rotated_found,"The independent receiver did not decrypt the post-ack Android epoch-one record"
            source_match = re.search(r"pallasync_rebase_sources=(\[[^\r\n]+\])",output)
            assert source_match is not None,"No public abandoned source ciphertext was reported"
            from android_rebase import verify_android_rebase
            verify_android_rebase(client,strict_loads(source_match.group(1).encode()),android_records,keys_by_epoch,base64.urlsafe_b64decode(device["device_public_key"]+"="))
        print("PASS: actual Android coordinator enrollment/initial sync/outbox -> isolated relay -> independent Python signature/AEAD receiver",flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("adb","relay-binary","app-apk","test-apk"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--rotate-epoch",action="store_true")
    parser.add_argument("--peer-enrollment",action="store_true")
    parser.add_argument("--rebase-fault",choices=["SOURCE_STAGED","DESTINATION_COMMITTED","SOURCE_RETIRED"])
    run(parser.parse_args())
