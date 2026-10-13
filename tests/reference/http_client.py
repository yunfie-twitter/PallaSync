"""Explicitly selected test-origin client with a fresh policy guard at every chain request."""
import http.client
import secrets
import time
from urllib.parse import parse_qsl, quote
import jsonschema
from protocol import b64, digest, jcs, signed, strict_loads, verify

MEDIA = "application/vnd.palleria.sync.v3+json"


class ReferenceHTTP:
    def __init__(self, relay, crypto, consented, schema):
        self.relay,self.crypto = relay,crypto
        self.accepted = None
        self.schema = jsonschema.Draft202012Validator(schema)
        self.check_policy()
        if not consented:
            raise ValueError("C_RELAY_POLICY_CONSENT_REQUIRED")
        self.accepted = self.current

    def raw(self, method, path, body=b"", token=None):
        connection = http.client.HTTPSConnection("127.0.0.1",self.relay.proxy.server_port,context=self.relay.client_tls,timeout=15)
        headers = {"Accept":MEDIA,"Content-Type":MEDIA}
        if token is not None:
            headers["Authorization"] = "PallaSync " + token
        connection.request(method,path,body,headers)
        response = connection.getresponse()
        payload = response.read(8_388_609)
        status,headers = response.status,dict(response.getheaders())
        connection.close()
        if len(payload) > 8_388_608:
            raise ValueError("C_SCHEMA_VIOLATION")
        return status,payload,headers

    def check_policy(self):
        _,md,_ = self.raw("GET","/privacy.md")
        status,body,headers = self.raw("GET","/privacy.json")
        if status != 200 or headers.get("content-type") != "application/json" or len(md) > 1048576:
            raise ValueError("C_RELAY_POLICY_UNAVAILABLE")
        md.decode("utf-8",errors="strict")
        doc = strict_loads(body,1048576)
        self.schema.validate(doc)
        verify(doc,bytes(self.relay.relay_key.verify_key),b"PALLASYNC-RELAY-PRIVACY-v3\0","relay_signature")
        if (doc["relay_origin"] != self.relay.origin or doc["markdown_sha256"] != b64(digest(md))
                or doc["relay_key_id"] != b64(digest(bytes(self.relay.relay_key.verify_key)))):
            raise ValueError("C_RELAY_DISCLOSURE_INVALID")
        self.current = (self.relay.origin,doc["relay_key_id"],b64(digest(md)),b64(digest(jcs(doc))),doc["revision"])
        if self.accepted is not None and self.current != self.accepted:
            raise ValueError("C_RELAY_POLICY_CONSENT_REQUIRED")

    def token(self, method, path, body, admin=False):
        route,sep,query = path.partition("?")
        pairs = parse_qsl(query,keep_blank_values=True,encoding="utf-8",errors="strict")
        if len({name for name,_ in pairs}) != len(pairs):
            raise ValueError("C_SCHEMA_VIOLATION")
        normalized = "&".join(quote(name,safe="-._~")+"="+quote(value,safe="-._~") for name,value in sorted(pairs,key=lambda item:item[0].encode("utf-8")))
        issued = int(time.time()*1000)
        value = {"v":3,"aud":self.relay.origin,"chain_id":self.crypto.chain,"signer_kind":"admin" if admin else "device",
                 "device_id":None if admin else self.crypto.device_id,"method":method,"path":route,"query":normalized,
                 "body_sha256":b64(digest(body)),"issued_at_ms":issued,"expires_at_ms":issued+120000,"nonce":b64(secrets.token_bytes(16))}
        return b64(jcs(signed(value,self.crypto.admin if admin else self.crypto.device,b"PALLASYNC-CAPABILITY-v3\0")))

    def request(self,method,path,value=None,admin=False,token=None):
        self.check_policy()
        if self.accepted is None:
            raise ValueError("C_RELAY_POLICY_CONSENT_REQUIRED")
        body = b"" if value is None else jcs(value)
        token = token or self.token(method,path,body,admin)
        status,body,headers = self.raw(method,path,body,token)
        if headers.get("x-pallasync-protocol") != "pallasync/3" or headers.get("cache-control") != "no-store":
            raise ValueError("C_SCHEMA_VIOLATION")
        return status,strict_loads(body),token
