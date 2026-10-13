"""Independent C.10 byte-stream commitment. No claim of snapshot bootstrap/coverage."""
import hmac
import unittest

from protocol import b64, jcs, strict_loads


def state_commitment(key, parts):
    """Partitioning is deliberately outside the MAC: only the complete entry array is committed."""
    mac = hmac.new(key, digestmod="sha256")
    mac.update(b"[")
    first = True
    for part in parts:
        for entry in part:
            if not first:
                mac.update(b",")
            mac.update(jcs(entry))
            first = False
    mac.update(b"]")
    return b64(mac.digest())


class SnapshotCommitmentTests(unittest.TestCase):
    def test_c10_complete_array_and_partition_independence(self):
        key = bytes.fromhex("d96ff76d5c3ad5df7429153b52126e43a818c223f53fa3f52d7ce102026c0974")
        header = strict_loads(b'{"chain_id":"ODtLW4w27pD6LS9IpFBfmvByjEoBFddv2Fx1QJIMJoc","covered_log_hash":"0zeJRLV2xNFxHkbAzYH-TSb1kOcmVyl9r4kiBsQLCHQ","covered_through_seq":0,"epoch_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","generation":0,"kind":"header","lamport_max":0,"log_id":"cccccccc-cccc-4ccc-8ccc-cccccccccccc"}')
        self.assertEqual(state_commitment(key, [[header]]), "cEWZYwyPF0UbkBBP8J9BJnU69OPDBciCrjHKk2gt1bU")
        self.assertNotEqual(state_commitment(key, [[header]]), b64(hmac.digest(key, jcs(header), "sha256")))
        winner = [1, 0, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", 0]
        entries = [header,
            {"kind":"entity","collection":"palleria.search_history/3","entity_id":"猫","key":winner,"operation":"upsert","body":{"query":"猫"},"context":{}},
            {"kind":"clear","collection":"palleria.view_history/3","scope":"seen","key":[1,1,*winner[2:]]},
            {"kind":"retention","collection":"palleria.search_history/3","scope":"all","key":winner,"limit":None,"stop_on_safety_limit":False},
            {"kind":"author","generation":0,"device_id":winner[2],"device_seq":3,"record_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
            {"kind":"author_gap","generation":0,"device_id":winner[2],"first":1,"last":2},
            {"kind":"projection","collection":"palleria.search_history/3","scope":"all","limit":200,"eviction_floor":None}]
        expected = b64(hmac.digest(key, jcs(entries), "sha256"))
        for boundary in range(len(entries)+1):
            self.assertEqual(state_commitment(key, [entries[:boundary], entries[boundary:]]), expected)
        self.assertEqual(state_commitment(key, [[entry] for entry in entries]), expected)
        for missing in range(len(entries)):
            self.assertNotEqual(state_commitment(key, [entries[:missing]+entries[missing+1:]]), expected)


if __name__ == "__main__":
    unittest.main()
