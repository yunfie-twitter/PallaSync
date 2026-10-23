"""Test-only local-file handoff with an actual Android approver; never a relay mailbox."""
import subprocess
import threading
import time
from protocol import b64, decode, jcs, object_hash, strict_loads, verify
from http_client import ReferenceHTTP
from peer_client import PeerClient
from run_peer_interop import public_request


class AndroidPeerHandoff:
    def __init__(self, adb, identifier, relay, creator, genesis, schema, log_id):
        self.adb, self.identifier = adb, identifier
        self.relay, self.creator, self.genesis, self.schema = relay, creator, genesis, schema
        self.log_id = log_id
        listed = subprocess.run(
            [adb, "devices"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
        if listed.returncode != 0:
            raise RuntimeError("Could not enumerate ADB devices for the disposable peer handoff")
        candidates = []
        for line in listed.stdout.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 2 or fields[1] != "device" or not fields[0].startswith("emulator-"):
                continue
            name = subprocess.run(
                [adb, "-s", fields[0], "emu", "avd", "name"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
            )
            is_target = name.stdout.splitlines() and name.stdout.splitlines()[0].strip() == "PallaSyncV3Conformance"
            if name.returncode == 0 and is_target:
                candidates.append(fields[0])
        if len(candidates) != 1:
            raise RuntimeError("Exactly one running PallaSyncV3Conformance AVD is required for peer handoff")
        self.device_serial = candidates[0]
        self.stop = threading.Event()
        self.failure, self.subject = None, None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def file(self, name):
        return "files/pallasync-peer-test/" + self.identifier + "/" + name

    def read(self, name):
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline and not self.stop.is_set():
            try:
                result = subprocess.run([self.adb,"-s",self.device_serial,"shell","run-as","com.yunfie.illustia","cat",self.file(name)],capture_output=True,timeout=min(20,max(0.1,deadline-time.monotonic())))
            except subprocess.TimeoutExpired:
                # Read-only polling can retry within its original overall deadline.
                # A blocked ADB call is never evidence of a completed transfer.
                continue
            if result.returncode == 0 and result.stdout:
                if len(result.stdout) > 8_388_608:
                    raise RuntimeError("Disposable public handoff exceeds its bound")
                return result.stdout
            self.stop.wait(0.5)
        raise RuntimeError("Disposable Android peer handoff did not finish")

    def write(self, name, data):
        # UUID identifier and fixed names below are the only paths accepted; content is stdin.
        final = self.file(name)
        command = "cat > '" + final + ".pending' && mv '" + final + ".pending' '" + final + "'"
        shell = 'run-as com.yunfie.illustia sh -c "' + command + '"'
        result = subprocess.run([self.adb,"-s",self.device_serial,"shell",shell],input=data,capture_output=True,timeout=20)
        if result.returncode != 0:
            raise RuntimeError("Disposable public handoff write failed")

    def run(self):
        try:
            self.exchange()
        except BaseException as failure:
            self.failure = failure
            try:
                self.write("completed.json",jcs({"status":"failed"}))
            except RuntimeError:
                pass

    def exchange(self):
        offer = strict_loads(self.read("offer.json"))
        creator = self.creator
        prefix = "/pallasync/v3/chains/" + creator.chain
        source = ReferenceHTTP(self.relay,creator,True,self.schema)
        status, registry, _ = source.request("GET",prefix+"/devices?limit=200",admin=True)
        assert status == 200, registry
        approver = next(item["device_record"] for item in registry["items"] if item["device_record"]["device_id"] == offer["approver_device_id"])
        verify(approver,decode(approver["device_public_key"],32),b"PALLASYNC-DEVICE-RECORD-v3\0")
        verify(approver["enrollment"],bytes(creator.admin.verify_key),b"PALLASYNC-ENROLLMENT-v3\0")
        assert offer["chain_id"] == creator.chain and offer["relay_origin"] == self.relay.origin
        assert offer["parameters_hash"] == object_hash(self.genesis["parameters"]) and offer["epoch_hash"] == object_hash(self.genesis["epoch"])
        assert offer["admin_public_key"] == b64(bytes(creator.admin.verify_key)) and offer["approver_device_record_hash"] == object_hash(approver)
        assert offer["approver_device_public_key"] == approver["device_public_key"] and offer["approver_device_kex_public_key"] == approver["device_kex_public_key"]
        subject = PeerClient(offer,True)
        self.subject = subject
        http = ReferenceHTTP(self.relay,subject,True,self.schema)
        status, requested = public_request(http,prefix,subject.request)
        assert status == 201 and requested["request_hash"] == object_hash(subject.request), requested
        visual = self.read("approver-sas.txt").decode("ascii")
        assert visual == subject.visual
        subject.confirm(visual,True)  # Explicit test input; no production/UI confirmation shortcut.
        self.write("subject-sas.txt",subject.visual.encode("ascii"))
        certificate = strict_loads(self.read("certificate.json"))
        envelope = strict_loads(self.read("envelope.json"))
        body = subject.prepare(certificate,envelope,self.genesis["epoch"])
        self.write("approval.json",jcs(body))
        accepted = strict_loads(self.read("acceptance.json"))
        assert accepted["status"] == "pending_keys" and accepted["device_id"] == subject.device_id, accepted
        from attestations import Pin, receipt
        pin = Pin(creator.chain,self.log_id,bytes(self.relay.relay_key.verify_key))
        objects = {object_hash(body["device_record"]):body["device_record"],object_hash(envelope):envelope}
        assert len(accepted["upload_receipts"]) == 2
        for claim in accepted["upload_receipts"]:
            obj = objects[claim["object_hash"]]
            entry = {"relay_seq":claim["relay_seq"],"received_at_ms":claim["received_at_ms"],
                "kind":"device" if obj == body["device_record"] else "envelope","object":obj}
            receipt(claim,obj,entry,pin)
        status, refused, _ = http.request("GET",prefix+"/records?limit=200")
        assert status == 403 and refused["code"] == "DEVICE_PENDING_KEYS", refused
        status, delivered, _ = http.request("GET",prefix+"/devices/"+subject.device_id+"/envelopes?epoch=0&limit=200")
        assert status == 200 and delivered["items"] == [envelope], delivered
        subject.verify_envelope(delivered["items"][0],self.genesis["epoch"])
        status, active, _ = http.request("POST",prefix+"/devices/"+subject.device_id+"/keys/ack",subject.ack(self.genesis["epoch"]))
        assert status == 200 and active["status"] == "active", active
        self.write("completed.json",jcs({"status":"verified"}))

    def finish(self):
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            self.stop.set()
            self.thread.join(timeout=25)
            raise RuntimeError("Disposable Android peer exchange is incomplete")
        if self.failure is not None:
            raise self.failure
        if self.subject is None:
            raise RuntimeError("No independent prospective peer completed")
        print("PASS: actual Android approver JNI/protected journal/REST, independently compared Python SAS and subject signature/HPKE, original signed approval receipts, P delivery/ack",flush=True)
