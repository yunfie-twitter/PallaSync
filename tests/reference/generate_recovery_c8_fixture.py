"""Generate C.8 holder fixtures using only the document's public fixed test keys."""
import argparse
from pathlib import Path
import struct

from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
from nacl.signing import SigningKey
from protocol import b64, jcs, object_hash, root_keys, signed, strict_loads
from recovery_crypto import associated, verify_package_bindings

parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("--fork-status-output", required=True)
args = parser.parse_args()
fixtures = Path(__file__).with_name("fixtures")
manifest = strict_loads((fixtures / "recovery-manifest-c8.json").read_bytes())
record = strict_loads((fixtures / "recovery-share-c8.json").read_bytes())
mnemonic = " ".join(["abandon"] * 23 + ["art"])
roots = root_keys(mnemonic)
admin = SigningKey(roots["admin_seed"])
assert b64(bytes(admin.verify_key)) == manifest["admin_public_key"]
blob = {k: manifest[k] for k in ("chain_id", "created_at_ms", "generation", "recovery_secret_fingerprint",
                                 "recovery_set_id", "threshold", "total_shares")}
blob.update(type="PALLASYNC-RECOVERY-BLOB-v3", version="3.0")
plain = {k: blob[k] for k in ("chain_id", "created_at_ms", "generation", "recovery_secret_fingerprint", "recovery_set_id")}
plain.update(mnemonic=mnemonic, passphrase="")
body = jcs(plain)
framed = struct.pack(">I", len(body)) + body + bytes(1024 - 4 - len(body))
cipher = crypto_aead_xchacha20poly1305_ietf_encrypt(framed,
    associated(blob, "PALLASYNC-RECOVERY-BLOB-AAD-v3", ("blob_nonce", "encrypted_blob")),
    bytes(range(0x40, 0x58)), bytes(range(32)))
blob.update(blob_nonce=b64(bytes(range(0x40, 0x58))), encrypted_blob=b64(cipher))
assert object_hash(blob) == manifest["recovery_blob_hash"]
status = {"type": "PALLASYNC-RECOVERY-STATUS-v3", "version": "3.0", "recovery_set_id": manifest["recovery_set_id"],
          "set_manifest_hash": object_hash(manifest), "status_seq": 1, "state": "prepared",
          "previous_status_hash": None, "replacement_set_id": None, "created_at_ms": manifest["created_at_ms"]}
prepared = signed(status, admin, b"PALLASYNC-RECOVERY-STATUS-v3\0")
successor = {**status, "status_seq": 2, "previous_status_hash": object_hash(prepared), "created_at_ms": manifest["created_at_ms"] + 1}
active = signed({**successor, "state": "active"}, admin, b"PALLASYNC-RECOVERY-STATUS-v3\0")
retired = signed({**successor, "state": "retired"}, admin, b"PALLASYNC-RECOVERY-STATUS-v3\0")
package = {"type": "PALLASYNC-RECOVERY-PACKAGE-v3", "version": "3.0", "manifest": manifest,
           "status_chain": [prepared, active], "record": record, "blob": blob, "offline_key_envelope": None}
verify_package_bindings(package, manifest["admin_public_key"])
Path(args.output).write_bytes(jcs(package) + b"\n")
Path(args.fork_status_output).write_bytes(jcs(retired) + b"\n")
print("PASS: independent C.8 package and conflicting signed status; public fixed test inputs only")
