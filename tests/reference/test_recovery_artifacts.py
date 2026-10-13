"""Public C.8 schema/ancestry rejection; no production holder or protected memory claim."""
import copy
import unittest
from pathlib import Path
from protocol import b64, object_hash, root_keys, signed, strict_loads
from nacl.signing import SigningKey
from recovery_artifacts import package, status_chain

FIXTURES = Path(__file__).parent / "fixtures"


class RecoveryArtifactTest(unittest.TestCase):
    def setUp(self):
        self.source = strict_loads((FIXTURES/"recovery-package-c8.json").read_bytes())
        self.admin = self.source["manifest"]["admin_public_key"]

    def test_unknown_members_and_all_uint_boundaries_precede_interpolation(self):
        package(self.source,self.admin)
        for member in ("manifest","record","blob","status"):
            altered = copy.deepcopy(self.source)
            target = altered["status_chain"][0] if member == "status" else altered[member]
            target["unknown"] = None
            with self.subTest(member=member), self.assertRaises(ValueError):
                package(altered,self.admin)
        for member in ("manifest","record","blob"):
            for invalid in (True,-1,1<<32):
                altered = copy.deepcopy(self.source)
                altered[member]["generation"] = invalid
                with self.subTest(member=member,value=invalid), self.assertRaises(ValueError):
                    package(altered,self.admin)
        altered = copy.deepcopy(self.source)
        altered["blob"]["ext"] = {"org.example.data":{}}
        with self.assertRaises(ValueError):
            package(altered,self.admin)

    def test_status_ancestry_requires_pinned_head_and_terminal_state(self):
        m, statuses = self.source["manifest"], self.source["status_chain"]
        head = object_hash(statuses[-1])
        status_chain(statuses,m,head)
        with self.assertRaises(ValueError):
            status_chain(statuses,m,b64(bytes(32)))
        conflict = strict_loads((FIXTURES/"recovery-retired-status-c8.json").read_bytes())
        with self.assertRaises(ValueError):
            status_chain(statuses + [conflict],m,head)
        # The public C8 admin signs a valid retirement and a forbidden reactivation.
        roots = root_keys(" ".join(["abandon"]*23+["art"]))
        key = SigningKey(roots["admin_seed"])
        self.assertEqual(b64(bytes(key.verify_key)),self.admin)
        retired = signed({**statuses[-1],"status_seq":statuses[-1]["status_seq"]+1,"state":"retired",
            "previous_status_hash":head,"replacement_set_id":None},key,b"PALLASYNC-RECOVERY-STATUS-v3\0")
        status_chain(statuses + [retired],m,head)
        with self.assertRaises(ValueError):
            status_chain(statuses,m,object_hash(retired))
        next_status = signed({**retired,"status_seq":retired["status_seq"]+1,"state":"active",
            "previous_status_hash":object_hash(retired),"replacement_set_id":None},key,b"PALLASYNC-RECOVERY-STATUS-v3\0")
        with self.assertRaises(ValueError):
            status_chain(statuses + [retired,next_status],m,head)

    def test_duplicate_physical_holder_and_unsigned_envelopes_are_not_extra_capacity(self):
        altered = copy.deepcopy(self.source)
        altered["manifest"]["holders"][1]["holder_instance_id"] = altered["manifest"]["holders"][0]["holder_instance_id"]
        with self.assertRaises(ValueError):
            package(altered,self.admin)
        altered = copy.deepcopy(self.source)
        altered["offline_key_envelope"] = {}
        with self.assertRaises(ValueError):
            package(altered,self.admin)
        altered = copy.deepcopy(self.source)
        altered["record"]["encrypted_share"] = b64(bytes(47))
        with self.assertRaises(ValueError):
            package(altered,self.admin)


if __name__ == "__main__":
    unittest.main()
