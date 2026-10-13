"""Public fixture from a disposable real relay. All deterministic keys below are public test inputs.

The output contains signed public objects, ciphertext and original receipts only.
"""
import argparse
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization
from nacl.signing import SigningKey
from crypto_client import CryptoClient
from http_client import ReferenceHTTP
from isolated_relay import IsolatedRelay, ROOT
from protocol import b64, epoch_keys, jcs, strict_loads


def generate(binary, destination):
    client = CryptoClient(" ".join(["abandon"] * 23 + ["art"]))
    client.device = SigningKey(bytes(range(96,128)))
    client.kex = X25519PrivateKey.from_private_bytes(bytes(range(32)))
    client.kex_public = client.kex.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    client.device_id = "11111111-1111-4111-8111-111111111111"
    client.secret = bytes(range(0xa0,0xc0))
    client.keys = epoch_keys(client.roots["chain_id_digest"],0,client.secret)
    schema = strict_loads((ROOT/"docs/privacy.schema.json").read_bytes())
    with IsolatedRelay(binary) as relay:
        http = ReferenceHTTP(relay,client,True,schema)
        genesis = client.genesis()
        status,created,_ = http.request("POST","/pallasync/v3/chains",genesis,True)
        assert status == 201,created
        fixture = {"origin":relay.origin,"relay_public_key":b64(bytes(relay.relay_key.verify_key)),"genesis":genesis,"created":created,
            "identity":{"chain_id":client.chain,"admin_public_key":b64(bytes(client.admin.verify_key))}}
        Path(destination).write_bytes(jcs(fixture)+b"\n")
    print("PASS: public peer JNI fixture generated from an independent Python genesis and original disposable-relay receipts",flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-binary",required=True)
    parser.add_argument("--output",required=True)
    args = parser.parse_args()
    generate(args.relay_binary,args.output)
