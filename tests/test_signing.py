import unittest
import copy

from titmas_action_gate.signing import HmacRecordSigner


class TestHmacRecordSigner(unittest.TestCase):
    def setUp(self):
        self.valid_key = b"0123456789abcdef0123456789abcdef"
        self.payload = {"test": "data", "count": 1}

    def test_init_valid_key(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        self.assertEqual(signer._key, self.valid_key)
        self.assertEqual(signer.key_id, "test-key")

    def test_init_invalid_key(self):
        with self.assertRaises(ValueError) as ctx:
            HmacRecordSigner(b"too_short")
        self.assertIn("must be at least 32 bytes", str(ctx.exception))

    def test_sign(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        signature = signer.sign(self.payload)

        self.assertEqual(signature["algorithm"], "HMAC-SHA256-DEMO_ONLY")
        self.assertEqual(signature["key_id"], "test-key")
        self.assertIn("payload_sha256", signature)
        self.assertIn("value", signature)
        self.assertIsInstance(signature["value"], str)

    def test_verify_success(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        signature = signer.sign(self.payload)
        self.assertTrue(signer.verify(self.payload, signature))

    def test_verify_failure_tampered_payload(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        signature = signer.sign(self.payload)
        tampered_payload = {"test": "data", "count": 2}
        self.assertFalse(signer.verify(tampered_payload, signature))

    def test_verify_failure_tampered_signature_value(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        signature = signer.sign(self.payload)
        tampered_signature = copy.deepcopy(signature)
        tampered_signature["value"] = "0" * 64
        self.assertFalse(signer.verify(self.payload, tampered_signature))

    def test_verify_failure_different_key_id(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        signature = signer.sign(self.payload)
        tampered_signature = copy.deepcopy(signature)
        tampered_signature["key_id"] = "different-key"
        self.assertFalse(signer.verify(self.payload, tampered_signature))

    def test_verify_failure_different_algorithm(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        signature = signer.sign(self.payload)
        tampered_signature = copy.deepcopy(signature)
        tampered_signature["algorithm"] = "HMAC-SHA512"
        self.assertFalse(signer.verify(self.payload, tampered_signature))

    def test_verify_missing_fields(self):
        signer = HmacRecordSigner(self.valid_key, key_id="test-key")
        self.assertFalse(signer.verify(self.payload, {}))

if __name__ == '__main__':
    unittest.main()
