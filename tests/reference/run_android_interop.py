"""Actual Android coordinator + independent Python + disposable TLS relay boundary.

This targeted enrollment/outbox case is not IT-01..IT-50 completion.
Only the task-owned PallaSyncV3Conformance emulator is accepted.
"""
import argparse
import base64
import struct
from contextlib import ExitStack
import re
import subprocess
import uuid
from pathlib import Path
from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
from protocol import b64, decode, epoch_keys, jcs, object_hash, strict_loads, verify
from attestations import Pin, ledger_hash
from crypto_client import CryptoClient
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT


def verify_reseed_snapshot_contains(remote, client, prefix, parameters, new_device_public_key, entity_id):
    """Independently decrypt the committed target snapshot; do not expect source log records copied verbatim."""
    status, snapshot_page, _ = remote.request("GET", prefix + "/snapshots?limit=200", admin=True)
    if status != 200:
        raise RuntimeError(f"Could not read target compactions: {status} {snapshot_page}")
    compaction = next(
        (item for item in snapshot_page["items"] if item["generation"] == parameters["generation"]),
        None,
    )
    if compaction is None:
        raise RuntimeError("Committed target snapshot is missing")
    verify(compaction, new_device_public_key, b"PALLASYNC-COMPACTION-v3\0")
    epoch_hash = compaction["epoch_hash"]
    status, epoch_page, _ = remote.request("GET", prefix + "/epochs?limit=200", admin=True)
    if status != 200:
        raise RuntimeError(f"Could not read target epoch history: {status} {epoch_page}")
    epoch = next(
        (item["epoch"] for item in epoch_page["items"] if item["epoch_hash"] == epoch_hash),
        None,
    )
    if epoch is None:
        raise RuntimeError("Target compaction's epoch is missing")
    status, envelope_response, _ = remote.request(
        "GET", prefix + f"/epochs/{epoch['epoch']}/recovery-envelope", admin=True
    )
    if status != 200:
        raise RuntimeError(f"Could not read target recovery envelope: {status} {envelope_response}")
    envelope = envelope_response["envelope"]
    verify(envelope, decode(parameters["admin_public_key"], 32), b"PALLASYNC-EPOCH-ENVELOPE-v3\0")
    binding_keys = {
        "chain_id", "generation", "epoch", "previous_epoch_hash", "epoch_commitment",
        "signer_kind", "signer_device_id", "envelope_id", "recipient_kind",
        "recipient_device_id", "recipient_key_hash",
    }
    binding = {key: envelope[key] for key in binding_keys}
    epoch_secret = crypto_aead_xchacha20poly1305_ietf_decrypt(
        decode(envelope["ciphertext"]), jcs(binding), decode(envelope["nonce"], 24), client.roots["recovery_kek"]
    )
    record_key = epoch_keys(client.roots["chain_id_digest"], epoch["epoch"], epoch_secret)["record"]
    for reference in compaction["snapshot_parts"]:
        status, part_response, _ = remote.request(
            "GET", prefix + "/snapshots/parts/" + reference["record_id"], admin=True
        )
        if status != 200:
            raise RuntimeError(f"Could not fetch committed snapshot part: {status} {part_response}")
        record = part_response["record"]
        if object_hash(record) != reference["record_hash"]:
            raise RuntimeError("Target snapshot part hash does not match its compaction")
        verify(record, new_device_public_key, b"PALLASYNC-SYNC-RECORD-v3\0")
        aad = {"type": "PALLASYNC-AAD-v3", **{key: record[key] for key in (
            "version", "chain_id", "generation", "record_id", "device_id", "epoch", "collection_tag"
        )}}
        padded = crypto_aead_xchacha20poly1305_ietf_decrypt(
            decode(record["encrypted_payload"]), jcs(aad), decode(record["payload_nonce"], 24), record_key
        )
        length = struct.unpack(">I", padded[:4])[0]
        if length > len(padded) - 4:
            raise RuntimeError("Snapshot frame length exceeds its padded payload")
        part = strict_loads(padded[4:4 + length])
        if (
            part.get("type") == "PALLASYNC-SNAPSHOT-v3"
            and part.get("collection") == "pallasync.snapshot/3"
            and part.get("compaction_id") == compaction["compaction_id"]
            and any(
                entry.get("kind") == "entity" and entry.get("entity_id") == entity_id
                for entry in part.get("entries", [])
            )
        ):
            return compaction
    raise RuntimeError("Committed target snapshot does not contain the racing source entity")


def run(args):
    listed = subprocess.run([args.adb,"devices"],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=30)
    if listed.returncode != 0:
        raise RuntimeError("ADB device enumeration failed")
    candidates = []
    for line in listed.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 2 or fields[1] != "device" or not fields[0].startswith("emulator-"):
            continue
        name = subprocess.run(
            [args.adb,"-s",fields[0],"emu","avd","name"],
            capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=30,
        )
        if name.returncode == 0 and name.stdout.splitlines() and name.stdout.splitlines()[0].strip() == "PallaSyncV3Conformance":
            candidates.append(fields[0])
    if len(candidates) != 1:
        raise RuntimeError("Exactly one running PallaSyncV3Conformance AVD is required")
    device_serial = candidates[0]

    def adb(*command):
        result = subprocess.run([args.adb,"-s",device_serial,*command],capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=600 if command[0] == "shell" else 240)
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
        if (args.reseed_split_view or args.reseed_pre_capture_write or args.reseed_staging_write) and target_relay is None:
            raise ValueError("reseed split-view/write races require --reseed")
        if args.reseed_archive_probe and not args.reseed:
            raise ValueError("--reseed-archive-probe requires --reseed")
        race_scenarios = sum((args.reseed_split_view, args.reseed_pre_capture_write, args.reseed_staging_write))
        if race_scenarios > 1:
            raise ValueError("split-view, staging-write and pre-capture-write are separate scenarios")
        if args.reseed_pre_capture_write and (args.rebase_process_death or args.reseed_late_source_write):
            raise ValueError("--reseed-pre-capture-write is a separate live-writer scenario")
        if args.reseed_staging_write and (args.rebase_process_death or args.reseed_late_source_write):
            raise ValueError("--reseed-staging-write is a separate live-writer scenario")
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
        pre_capture_source_record = None
        pre_capture_write_failure = []
        if args.reseed_split_view:
            target_relay.on_keys_ack = lambda: setattr(relay, "split_view_next_transparency_head", True)
        if args.reseed_pre_capture_write or args.reseed_staging_write:
            def inject_pre_capture_source_write():
                nonlocal pre_capture_source_record
                if pre_capture_source_record is not None:
                    return
                try:
                    pre_capture_source_record = client.record(
                        "palleria.search_history/3",
                        [{"entity_id":"Python source race before capture","operation":"upsert","lamport":1_000_002,
                          "created_at_ms":2,"context":{},"body":{"query":"Python source race before capture"}}],
                    )
                    write_status,write_result,_ = http.request("POST",prefix+"/records",{"records":[pre_capture_source_record]})
                    if write_status != 200 or len(write_result.get("accepted",[])) != 1:
                        pre_capture_write_failure.append(f"{write_status} {write_result}")
                except BaseException as error:
                    pre_capture_write_failure.append(repr(error))
            if args.reseed_pre_capture_write:
                target_relay.on_keys_ack = inject_pre_capture_source_write
        if args.reseed_staging_write:
            target_relay.on_snapshot_part = inject_pre_capture_source_write
        if args.reseed_late_source_write and (
            not args.rebase_process_death or args.rebase_fault != "RESEED_SOURCE_CAPTURED"
        ):
            raise ValueError("--reseed-late-source-write requires --rebase-process-death and RESEED_SOURCE_CAPTURED")
        late_source_record = None
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
            if args.rebase_process_death and (not args.reseed or not args.rebase_fault):
                raise ValueError("--rebase-process-death requires --reseed and --rebase-fault")

            def instrumentation(resume_after_death=False):
                command = ["shell","am","instrument","-w","-r","-e","class",
                    "com.yunfie.illustia.pallasync.PallaSyncRelayInteropTest","-e","relay_origin",relay.origin,
                    "-e","relay_ca_base64",base64.b64encode(relay_cert).decode(),
                    "-e","rotate_epoch","true" if args.rotate_epoch else "false",
                    "-e","replace_device","true" if args.replace_device else "false",
                    "-e","delete_chain","true" if args.delete_chain else "false",
                    "-e","delete_response_lost","true" if args.delete_response_lost else "false",
                    "-e","reseed_process_death","true" if args.rebase_process_death else "false",
                    "-e","reseed_resume_after_death","true" if resume_after_death else "false",
                    "-e","reseed_expect_late_source_write","true" if args.reseed_late_source_write else "false",
                    "-e","reseed_expect_split_view","true" if args.reseed_split_view else "false",
                    "-e","reseed_expect_pre_capture_source_write","true" if args.reseed_pre_capture_write else "false",
                    "-e","reseed_expect_staging_source_write","true" if args.reseed_staging_write else "false",
                    "-e","records_413_split","true" if args.records_413_split else "false",
                    "-e","reseed_archive_probe","true" if args.reseed_archive_probe else "false"]
                if target_relay is not None:
                    command.extend(["-e","reseed_target_origin",target_relay.origin])
                if args.rebase_fault and not resume_after_death:
                    command.extend(["-e","rebase_fault",args.rebase_fault])
                if handoff is not None:
                    command.extend(["-e","peer_transfer_id",handoff.identifier])
                command.append("com.yunfie.illustia.test/com.yunfie.illustia.pallasync.PallaSyncTestRunner")
                result = subprocess.run(
                    [args.adb,"-s",device_serial,*command],capture_output=True,text=True,
                    encoding="utf-8",errors="replace",timeout=600,
                )
                return result.returncode, result.stdout + result.stderr

            if args.rebase_process_death:
                first_code, first_output = instrumentation()
                if "reseed_process_death_phase_one=ready" not in first_output or "OK (1 test)" in first_output:
                    raise RuntimeError(
                        "Android did not terminate at the requested persisted reseed boundary "
                        f"(exit {first_code}): {first_output[-5000:]}"
                    )
                if args.reseed_late_source_write:
                    late_source_record = client.record(
                        "palleria.search_history/3",
                        [{"entity_id":"Python late source","operation":"upsert","lamport":1_000_002,
                          "created_at_ms":2,"context":{},"body":{"query":"Python late source"}}],
                    )
                    status,accepted,_ = http.request("POST",prefix+"/records",{"records":[late_source_record]})
                    if status != 200 or len(accepted.get("accepted",[])) != 1:
                        raise RuntimeError(f"Independent late source write was not accepted: {status} {accepted}")
                adb("shell","am","force-stop","com.yunfie.illustia")
                resume_code, resume_output = instrumentation(resume_after_death=True)
                if resume_code != 0:
                    raise RuntimeError("Android process-death resume instrumentation failed: "+resume_output[-2000:])
                output = first_output + "\nPROCESS-DEATH RESUME\n" + resume_output
                print(f"PASS: first instrumentation process terminated at the committed boundary (exit {first_code}); a fresh process reopened Room/Keystore state",flush=True)
            else:
                _, output = instrumentation()
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
        if args.records_413_split:
            if "pallasync_records_413_split=passed" not in output:
                raise RuntimeError("Android did not report successful PAYLOAD_TOO_LARGE outbox recovery")
            observations = relay.records_413_observations
            injected = [item for item in observations if item["outcome"] == "injected_413"]
            forwarded = [item for item in observations if item["outcome"] == "forwarded"]
            if len(injected) != 1 or len(injected[0]["record_ids"]) != 4:
                raise RuntimeError("The isolated proxy did not reject exactly one four-record batch: " + repr(observations))
            original_ids = injected[0]["record_ids"]
            replacement_ids = [record_id for item in forwarded for record_id in item["record_ids"]]
            if len(forwarded) < 2 or sorted(replacement_ids) != sorted(original_ids):
                raise RuntimeError("Smaller forwarded batches did not preserve the exact signed record IDs: " + repr(observations))
            if any(item["status"] != 200 or len(item["record_ids"]) >= len(original_ids) for item in forwarded):
                raise RuntimeError("An outbox replacement was not smaller and accepted: " + repr(observations))
            print("PASS: one injected top-level 413 was recovered by smaller batches containing the exact same four signed record IDs",flush=True)
        if target_relay is not None:
            if args.reseed_split_view:
                for marker in (
                    "pallasync_reseed_split_view_rejected=true",
                    "pallasync_reseed_split_view_evidence=retained",
                    "pallasync_reseed_split_view_writes=",
                ):
                    if marker not in output:
                        raise RuntimeError("Android did not prove signed split-view rejection: " + marker)
                if "pallasync_reseed_generation=1" in output:
                    raise RuntimeError("Android reported local reseed cutover after a signed split-view")
                target_http = ReferenceHTTP(target_relay,client,True,schema)
                status,parameters,_ = target_http.request("GET","/pallasync/v3/chains/"+client.chain+"/parameters",admin=True)
                if status != 200 or parameters["generation"] != 1:
                    raise RuntimeError("Split-view test did not reach the post-target-commit, pre-local-cutover boundary")
                print("PASS: Android rejected a relay-signed source checkpoint contradicting its replayed prefix, retained signed evidence, paused writes, and preserved the local source chain while the target commit remained isolated",flush=True)
                return
            if args.reseed_staging_write:
                if pre_capture_write_failure or pre_capture_source_record is None:
                    raise RuntimeError("Independent source write during target snapshot staging failed: " + repr(pre_capture_write_failure))
                for marker in (
                    "pallasync_reseed_staging_race_rejected=true",
                    "pallasync_reseed_staging_race_recovered=true",
                    "pallasync_reseed_generation=1",
                ):
                    if marker not in output:
                        raise RuntimeError("Android did not report recovery from staging race: " + marker)
            if args.reseed_pre_capture_write:
                if pre_capture_write_failure or pre_capture_source_record is None:
                    raise RuntimeError("Independent source write at the target acknowledgement boundary failed: " + repr(pre_capture_write_failure))
                if "pallasync_reseed_generation=1" not in output or "pallasync_reseed_source_audit=unimported" not in output:
                    raise RuntimeError("Android did not report completion and the expected source-only race")
                if "pallasync_reseed_unimported_count=1" not in output:
                    raise RuntimeError("Android did not report exactly one pre-capture source write")
            if "pallasync_reseed_generation=1" not in output:
                raise RuntimeError("Android did not report a completed generation+1 reseed cutover")
            expected_source_audit = "unimported" if (args.reseed_late_source_write or args.reseed_pre_capture_write) else "clean"
            if f"pallasync_reseed_source_audit={expected_source_audit}" not in output:
                raise RuntimeError("Android did not report the expected post-cutover source audit")
            if args.reseed_late_source_write:
                if "pallasync_reseed_unimported_count=1" not in output or late_source_record is None:
                    raise RuntimeError("Android did not report exactly one unimported source write")
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
            racing_source_record = late_source_record if args.reseed_late_source_write else pre_capture_source_record
            if args.reseed_late_source_write or args.reseed_pre_capture_write or args.reseed_staging_write:
                late_hash = object_hash(racing_source_record)

                def contains_record(remote):
                    cursor = None
                    while True:
                        path = reseed_prefix+"/records?limit=200"+(("&cursor="+cursor) if cursor else "")
                        status,page,_ = remote.request("GET",path,admin=True)
                        if status != 200:
                            raise RuntimeError(f"Could not independently audit migrated records: {status} {page}")
                        if any(object_hash(entry["object"]) == late_hash for entry in page["items"]):
                            return True
                        cursor = page["next_cursor"]
                        if cursor is None:
                            return False

                if not contains_record(http):
                    raise RuntimeError("Late source write was not retained on the source relay")
                target_contains = contains_record(target_http)
                if args.reseed_staging_write:
                    if target_contains:
                        raise RuntimeError("Source event was copied verbatim instead of being represented by the committed state snapshot")
                    verify_reseed_snapshot_contains(
                        target_http,
                        client,
                        reseed_prefix,
                        parameters["parameters"],
                        decode(device["device_public_key"], 32),
                        "Python source race before capture",
                    )
                    print("PASS: Android rejected the stale staged cut, synchronized the source writer, rebuilt snapshot state and committed generation+1; independent Python decrypted the committed target snapshot and found the racing source entity",flush=True)
                else:
                    if target_contains:
                        raise RuntimeError("Late source write was silently copied to the target relay")
                    timing = "after final source capture" if args.reseed_late_source_write else "after target acknowledgement and before final source capture"
                    print(f"PASS: independent old-generation write {timing} stayed on the source relay and Android reported it as one unimported edit",flush=True)
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
        if args.records_413_split:
            expected_split_queries = {f"Android 413 split {index}" for index in range(4)}
            observed_split_queries = {
                operation.get("body", {}).get("query")
                for _, inner in android_records
                for operation in inner.get("operations", [])
            }
            if not expected_split_queries.issubset(observed_split_queries):
                raise RuntimeError("Independent receiver did not decrypt every intent from the recovered 413 batch")
            print("PASS: independent Python decrypted all four local intents recovered from the rejected batch",flush=True)
        assert len(paused_records) == 1,"A paused editing intent was lost or signed twice"
        expected_paused_device_seq = 2 + (4 if args.records_413_split else 0)
        assert paused_records[0][0]["epoch"] == 0 and paused_records[0][1]["device_seq"] == expected_paused_device_seq
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
    parser.add_argument("--records-413-split",action="store_true",help="inject one isolated top-level records 413 and verify durable smaller-batch recovery")
    parser.add_argument("--reseed",action="store_true",help="run a two-relay Android generation+1 reseed cutover")
    parser.add_argument("--reseed-archive-probe",action="store_true",help="diagnose complete archive verification immediately after an isolated generation+1 cutover")
    parser.add_argument("--reseed-split-view",action="store_true",help="serve one relay-signed contradictory transparency head after target-key acknowledgement and require quarantine without local cutover")
    parser.add_argument("--reseed-pre-capture-write",action="store_true",help="append an independent old-generation record after target key acknowledgement but before the final source capture; require a source-only unimported-edit report")
    parser.add_argument("--reseed-staging-write",action="store_true",help="append an independent old-generation record during target snapshot-part staging and require fail-closed local retention")
    parser.add_argument("--reseed-late-source-write",action="store_true",help="write one independent old-generation record after source capture and require an unimported-edit report")
    parser.add_argument(
        "--rebase-process-death",
        action="store_true",
        help="kill instrumentation after the selected durable reseed boundary, then resume in a fresh process",
    )
    parser.add_argument(
        "--rebase-fault",
        choices=[
            "SOURCE_STAGED",
            "DESTINATION_COMMITTED",
            "SOURCE_RETIRED",
            "RESEED_ROOM_COMMITTED",
            "RESEED_SOURCE_CAPTURED",
            "RESEED_KEYSTORE_PROMOTED",
            "RESEED_OUTBOX_REBASED",
            "RESEED_ORIGIN_SELECTED",
            "RESEED_COMPLETE_COMMITTED",
        ],
    )
    run(parser.parse_args())
