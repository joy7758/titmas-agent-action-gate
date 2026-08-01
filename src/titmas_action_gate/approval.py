"""Scoped human approval records with local HMAC demo signatures."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Any

from .canonical import format_datetime, parse_datetime, request_binding, sha256_json, utc_now
from .contracts import validate_action_request, validate_bound_input


class ApprovalAuthority:
    """Demo signing boundary; production deployments should use managed asymmetric keys."""

    def __init__(self, key: bytes, *, key_id: str = "demo-human-approval-key"):
        if len(key) < 32:
            raise ValueError("approval key must be at least 32 bytes")
        self._key = key
        self.key_id = key_id

    def _signature(self, digest: str) -> str:
        return hmac.new(self._key, digest.encode("ascii"), hashlib.sha256).hexdigest()

    def create(
        self,
        request: dict[str, Any],
        policy: dict[str, Any],
        *,
        subject: str,
        identity_provider: str,
        status: str = "GRANTED",
        decided_at: datetime | None = None,
        ttl: timedelta = timedelta(minutes=15),
    ) -> dict[str, Any]:
        validate_action_request(request)
        validate_bound_input(request, policy, "policy_evaluation")
        decided = decided_at or utc_now()
        unsigned = {
            "schema_version": "0.1.0",
            "request_id": request["request_id"],
            "request_binding": request_binding(request),
            "policy_id": policy["policy_id"],
            "policy_version": policy["policy_version"],
            "ruleset_sha256": policy["ruleset_sha256"],
            "status": status,
            "approved_by": {
                "subject": subject,
                "identity_provider": identity_provider,
                "human_verified": True,
            },
            "decided_at": format_datetime(decided),
            "expires_at": format_datetime(decided + ttl),
        }
        digest = sha256_json(unsigned)
        approval = {
            **unsigned,
            "approval_id": f"approval-{digest[:24]}",
            "record_sha256": digest,
            "signature_ref": f"hmac-sha256:{self.key_id}:{self._signature(digest)}",
        }
        validate_bound_input(request, approval, "human_approval")
        return approval

    def verify(
        self,
        approval: dict[str, Any],
        request: dict[str, Any],
        policy: dict[str, Any],
        *,
        now: datetime | None = None,
    ) -> bool:
        try:
            validate_bound_input(request, approval, "human_approval")
        except Exception:
            return False
        unsigned = {key: value for key, value in approval.items() if key not in {"approval_id", "record_sha256", "signature_ref"}}
        digest = sha256_json(unsigned)
        expected_ref = f"hmac-sha256:{self.key_id}:{self._signature(digest)}"
        checked_at = now or utc_now()
        return all(
            [
                approval["status"] == "GRANTED",
                approval["record_sha256"] == digest,
                hmac.compare_digest(approval["signature_ref"], expected_ref),
                approval["policy_id"] == policy["policy_id"],
                approval["policy_version"] == policy["policy_version"],
                approval["ruleset_sha256"] == policy["ruleset_sha256"],
                parse_datetime(approval["decided_at"]) <= checked_at,
                checked_at < parse_datetime(approval["expires_at"]),
            ]
        )
