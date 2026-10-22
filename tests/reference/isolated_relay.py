"""Disposable HTTPS relay harness. Every file/DB/key is test-only and never contacts production."""
import copy
import datetime
import http.client
import http.server
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from nacl.signing import SigningKey
from protocol import b64, digest, jcs, signed, strict_loads

ROOT = Path(__file__).resolve().parents[2]


class IsolatedRelay:
    def __init__(self, binary, chain_delay=0, drop_delete_response=False):
        self.binary = Path(binary).resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix="pallasync-reference-")
        self.directory = Path(self.temporary.name)
        self.process = None
        self.drop_delete_response = drop_delete_response
        self.split_view_next_transparency_head = False
        self.records_413_armed = False
        self.records_413_tracking = False
        self.records_413_original_ids = set()
        self.records_413_observations = []
        self.on_keys_ack = None
        self.on_snapshot_part = None
        self.relay_key = SigningKey(bytes(range(0xa0,0xc0)))  # Public C.9 test seed only.
        reserve = socket.socket()
        reserve.bind(("127.0.0.1",0))
        self.backend_port = reserve.getsockname()[1]
        reserve.close()
        harness = self

        class Proxy(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):
                pass

            def forward(self):
                if self.command == "POST" and self.path == "/__test__/arm-records-413":
                    self.rfile.read(int(self.headers.get("Content-Length",0)))
                    harness.records_413_observations.clear()
                    harness.records_413_original_ids.clear()
                    harness.records_413_tracking = True
                    harness.records_413_armed = True
                    payload = b'{"armed":true}'
                    self.send_response(200)
                    self.send_header("Content-Type","application/json")
                    self.send_header("Content-Length",str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                # Integration clients revalidate public documents before every request.
                # Pace this test transport within the unchanged disclosed rate ceilings.
                if chain_delay and self.path.startswith("/pallasync/v3/chains"):
                    time.sleep(chain_delay)
                size = int(self.headers.get("Content-Length",0))
                if size > 8_388_608:
                    self.send_error(413)
                    return
                body = self.rfile.read(size)
                record_batch = None
                if self.command == "POST" and self.path.endswith("/records"):
                    parsed = strict_loads(body)
                    record_batch = parsed.get("records") if isinstance(parsed,dict) else None
                    if not isinstance(record_batch,list):
                        raise ValueError("isolated records request did not contain a records array")
                    if harness.records_413_armed:
                        harness.records_413_armed = False
                        harness.records_413_original_ids = {record["record_id"] for record in record_batch}
                        harness.records_413_observations.append({
                            "outcome":"injected_413",
                            "record_ids":[record["record_id"] for record in record_batch],
                        })
                        payload = jcs({
                            "type":"about:blank",
                            "title":"Payload Too Large",
                            "status":413,
                            "code":"PAYLOAD_TOO_LARGE",
                            "retryable":True,
                            "server_time_ms":int(time.time()*1000),
                        })
                        self.send_response(413)
                        self.send_header("Content-Type","application/problem+json")
                        self.send_header("Content-Length",str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return
                connection = http.client.HTTPConnection("127.0.0.1",harness.backend_port,timeout=10)
                headers = {name:value for name,value in self.headers.items() if name.lower() not in {"host","connection","content-length"}}
                connection.request(self.command,self.path,body,headers)
                response = connection.getresponse()
                payload = response.read(8_388_609)
                if record_batch is not None and harness.records_413_tracking:
                    harness.records_413_observations.append({
                        "outcome":"forwarded",
                        "status":response.status,
                        "record_ids":[record["record_id"] for record in record_batch],
                    })
                    observed_ids = {
                        record_id
                        for item in harness.records_413_observations
                        if item["outcome"] == "forwarded"
                        for record_id in item["record_ids"]
                    }
                    if harness.records_413_original_ids.issubset(observed_ids):
                        harness.records_413_tracking = False
                if response.status == 200 and self.command == "POST" and self.path.endswith("/keys/ack"):
                    callback = harness.on_keys_ack
                    if callback is not None:
                        callback()
                if response.status == 200 and self.command == "POST" and self.path.endswith("/snapshots/parts"):
                    callback = harness.on_snapshot_part
                    if callback is not None:
                        callback()
                if (
                    response.status == 200
                    and self.command == "GET"
                    and self.path.endswith("/transparency/head")
                    and harness.split_view_next_transparency_head
                ):
                    harness.split_view_next_transparency_head = False
                    value = strict_loads(payload)
                    head = value["head"]
                    head["head_hash"] = b64(digest(b"Palleria isolated signed split-view test"))
                    value["head"] = signed(head, harness.relay_key, b"PALLASYNC-TRANSPARENCY-HEAD-v3\0", "relay_signature")
                    payload = jcs(value)
                if (harness.drop_delete_response and self.command == "DELETE"
                        and self.path.startswith("/pallasync/v3/chains/") and self.path.count("/") == 4):
                    harness.drop_delete_response = False
                    connection.close()
                    self.close_connection = True
                    return
                self.send_response(response.status)
                for name,value in response.getheaders():
                    if name.lower() not in {"transfer-encoding","connection","content-length","date","server"}:
                        self.send_header(name,value)
                self.send_header("Content-Length",str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                connection.close()

            do_GET = do_POST = do_PUT = do_DELETE = forward

        self.proxy = http.server.ThreadingHTTPServer(("127.0.0.1",0),Proxy)
        self.origin = f"https://127.0.0.1:{self.proxy.server_port}"
        self.certificates()
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(self.directory/"tls.pem",self.directory/"tls.key")
        self.proxy.socket = tls.wrap_socket(self.proxy.socket,server_side=True)
        self.client_tls = ssl.create_default_context(cafile=str(self.directory/"tls.pem"))
        self.client_tls.minimum_version = ssl.TLSVersion.TLSv1_2
        self.policy()
        self.thread = threading.Thread(target=self.proxy.serve_forever,daemon=True)

    def certificates(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"localhost")])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(hours=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),False)
                .sign(key,hashes.SHA256()))
        (self.directory/"tls.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (self.directory/"tls.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))

    def policy(self):
        # Use the normative closed disclosure example, filled for this disposable process.
        spec = (ROOT/"docs/v3.0.md").read_text(encoding="utf-8")
        import json,re
        examples = [json.loads(x) for x in re.findall(r"```json\s*\n(.*?)\n```",spec.split("### C.11 ",1)[1].split("\n## ",1)[0],re.S)]
        disclosure = copy.deepcopy(next(x for x in examples if isinstance(x,dict) and x.get("type") == "PALLASYNC-RELAY-PRIVACY-v3"))
        markdown = b"# Disposable integration-test operator\nNo production identities or data. Temporary local disk; no backups. TLS 1.2+.\n"
        timestamp = int(time.time()*1000)
        disclosure.update(relay_origin=self.origin,relay_key_id=b64(digest(bytes(self.relay_key.verify_key))),disclosure_id=str(uuid.uuid4()),published_at_ms=timestamp,effective_at_ms=timestamp,markdown_sha256=b64(digest(markdown)))
        disclosure["operator"] = {"name":"Disposable test operator","contact_url":self.origin+"/contact"}
        disclosure["change_notice"] = {"minimum_notice_ms":0,"notice_url":self.origin+"/notice","archive_url":self.origin+"/archive"}
        disclosure["quota"]["counted_components"].insert(3,"device_meta")
        disclosure["deletion"] = {"assurance":"backup-expiry","active_delete_max_ms":60000,"backup_delete_max_ms":None,"key_destroy_max_ms":None}
        for name in ("active_store","wal","snapshot_store","staging"):
            disclosure["copies"][name] = {"present":True,"content":"ciphertext","locations":["Disposable test disk"],"recipients":["Test process"],"purpose":"Isolated tests","retention":{"mode":"until_chain_deletion"},"after_delete":{"mode":"erase","max_ms":60000}}
        disclosure["copies"]["cache"] = {"present":True,"content":"metadata","locations":["Disposable test disk"],"recipients":["Test process"],"purpose":"IP digest rate buckets","retention":{"mode":"indefinite"},"after_delete":{"mode":"retain_metadata","max_ms":None}}
        disclosure["metadata"] = {"retained_fields":["ip","timing"],"purposes":["Test rate limits"],"retention":{"mode":"indefinite"},"recipients":["Test process"]}
        disclosure = signed(disclosure,self.relay_key,b"PALLASYNC-RELAY-PRIVACY-v3\0","relay_signature")
        (self.directory/"privacy.md").write_bytes(markdown)
        (self.directory/"privacy.json").write_bytes(jcs(disclosure))

    def start(self):
        env = os.environ.copy()
        for name in ("PALLASYNC_QUOTA_BYTES","PALLASYNC_SHUTDOWN_AT_MS","PALLASYNC_MIGRATION_ORIGIN","PALLASYNC_STOP_WRITES"):
            env.pop(name,None)
        env.update(DATABASE_URL="sqlite:"+(self.directory/"relay.sqlite").as_posix(),
                   PALLASYNC_BIND_ADDR=f"127.0.0.1:{self.backend_port}",PALLASYNC_RELAY_SIGNING_SEED=b64(bytes(self.relay_key)),
                   PALLASYNC_PRIVACY_MARKDOWN=str(self.directory/"privacy.md"),PALLASYNC_PRIVACY_JSON=str(self.directory/"privacy.json"))
        self.process = subprocess.Popen([str(self.binary)],env=env,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(100):
            if self.process.poll() is not None:
                raise RuntimeError("Isolated relay failed: " + self.process.stderr.read(4096).decode(errors="replace"))
            try:
                connection = socket.create_connection(("127.0.0.1",self.backend_port),timeout=.1)
                connection.close()
                return
            except OSError:
                time.sleep(.05)
        raise RuntimeError("Isolated relay startup timeout")

    def restart(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        self.process.stderr.close()
        self.start()

    def __enter__(self):
        try:
            self.start()
            self.thread.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self,*args):
        self.close()

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)
        if self.process:
            self.process.stderr.close()
        # BaseServer.shutdown blocks forever if serve_forever has not started.
        if self.thread.is_alive():
            self.proxy.shutdown()
            self.thread.join(timeout=5)
        self.proxy.server_close()
        resolved = self.directory.resolve()
        if (resolved != Path(self.temporary.name).resolve() or resolved.parent != Path(tempfile.gettempdir()).resolve()
                or not resolved.name.startswith("pallasync-reference-")):
            raise RuntimeError("Refusing cleanup outside the harness-owned temporary directory")
        self.temporary.cleanup()
