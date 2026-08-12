from __future__ import annotations

import unittest

from titmas_action_gate.canonical import (
    canonical_json_bytes,
    canonical_json_text,
    sha256_json,
)


class CanonicalTests(unittest.TestCase):
    def test_canonical_json_bytes_simple_dict(self) -> None:
        result = canonical_json_bytes({"b": 2, "a": 1})
        self.assertEqual(result, b'{"a":1,"b":2}')

    def test_canonical_json_bytes_empty_dict(self) -> None:
        result = canonical_json_bytes({})
        self.assertEqual(result, b"{}")

    def test_canonical_json_bytes_simple_types(self) -> None:
        self.assertEqual(canonical_json_bytes("test"), b'"test"')
        self.assertEqual(canonical_json_bytes(123), b"123")
        self.assertEqual(canonical_json_bytes(True), b"true")
        self.assertEqual(canonical_json_bytes(None), b"null")

    def test_canonical_json_text_simple_dict(self) -> None:
        result = canonical_json_text({"b": 2, "a": 1})
        self.assertEqual(result, '{"a":1,"b":2}')

    def test_canonical_json_text_empty_dict(self) -> None:
        result = canonical_json_text({})
        self.assertEqual(result, "{}")

    def test_canonical_json_text_simple_types(self) -> None:
        self.assertEqual(canonical_json_text("test"), '"test"')
        self.assertEqual(canonical_json_text(123), "123")
        self.assertEqual(canonical_json_text(True), "true")
        self.assertEqual(canonical_json_text(None), "null")

    def test_sha256_json(self) -> None:
        # sha256 of '{"a":1,"b":2}'
        # python3 -c 'import hashlib; print(hashlib.sha256(b"{\"a\":1,\"b\":2}").hexdigest())'
        # -> 43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777
        result = sha256_json({"b": 2, "a": 1})
        expected_hash = "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
        self.assertEqual(result, expected_hash)
