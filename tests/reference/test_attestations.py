import copy
import unittest
from pathlib import Path
from protocol import decode, strict_loads
import attestations as evidence

FIXTURES = Path(__file__).parent / "fixtures" / "attestations"


class AttestationVectors(unittest.TestCase):
    def test_c9_independent_data_transparency_and_signed_receipt(self):
        record, receipt, transparent = [strict_loads((FIXTURES / (name + ".json")).read_bytes())
                                        for name in ("record","receipt","transparency")]
        key = decode("T9CZzNR9eJPf6ewkQU7LDZtUICMqrTDZHEZb4zy-ZcQ",32)
        pin = evidence.Pin(record["chain_id"],receipt["log_id"],key)
        entry = {"relay_seq":7,"kind":"record","object":record,"received_at_ms":1791684000000}
        self.assertEqual(evidence.data_link(receipt["previous_head_hash"],entry),"9rmeVaK9mN98hMLU6FDa4ZGL77Mgrd5fwceAipags-o")
        zero = evidence.transparency_zero(pin.chain,transparent["transparency_id"],key)
        self.assertEqual(decode(zero,32).hex(),"6ee2c315ded34a8bb92f0ee5511c22c2e83c6d9b79fe2dc1560535274dd7f29d")
        self.assertEqual(decode(evidence.transparency_link(zero,transparent,pin),32).hex(),"450fe12939119e4befe02d7ed25a063c8e76323605f53b2d8ad016fe16d890de")
        evidence.receipt(receipt,record,entry,pin,transparent)
        for field in ("object_hash","previous_head_hash","transparency_hash","relay_seq","received_at_ms"):
            altered = copy.deepcopy(receipt)
            altered[field] = (altered[field] + 1) if type(altered[field]) is int else "A" + altered[field][1:]
            with self.assertRaises(Exception):
                evidence.receipt(altered,record,entry,pin,transparent)
        with self.assertRaises(Exception):
            evidence.receipt(receipt,record,{**entry,"received_at_ms":1791684000001},pin,transparent)


if __name__ == "__main__":
    unittest.main()
