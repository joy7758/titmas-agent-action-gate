"""Payload signatures used by the local reference service."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any

from .canonical import sha256_json


class HmacRecordSigner:
    """Local reference signer; managed asymmetric signing is a deployment concern."""

    def __init__(self, key: bytes, *, key_id: str = "demo-gate-record-key"):
        if len(key) < 32:
            raise ValueError("record signing key must be at least 32 bytes")
        self._key = key
        self.key_id = key_id

    def sign(self, payload: dict[str, Any]) -> dict[str, str]:
        digest = sha256_json(payload)
        signature = hmac.new(self._key, digest.encode("ascii"), hashlib.sha256).hexdigest()
        return {
            "algorithm": "HMAC-SHA256-DEMO_ONLY",
            "key_id": self.key_id,
            "payload_sha256": digest,
            "value": signature,
        }

    def verify(self, payload: dict[str, Any], signature: dict[str, str]) -> bool:
        expected = self.sign(payload)
        return all(
            [
                signature.get("algorithm") == expected["algorithm"],
                signature.get("key_id") == expected["key_id"],
                signature.get("payload_sha256") == expected["payload_sha256"],
                hmac.compare_digest(signature.get("value", ""), expected["value"]),
            ]
        )
