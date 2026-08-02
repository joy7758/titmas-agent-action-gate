from __future__ import annotations

import copy
import json
import unittest
from datetime import UTC, datetime

from scripts.capture_alibabacloud_ram_policy_observation import build_sanitized_observation
from titmas_action_gate.cloud_context import EXPECTED_READ_ONLY_POLICY_ACTIONS
from titmas_action_gate.contracts import validate_contract
from titmas_action_gate.errors import ContractValidationError


class RamPolicyObservationCaptureTests(unittest.TestCase):
    def fixtures(self) -> tuple[dict, dict, dict, dict]:
        actions = sorted(EXPECTED_READ_ONLY_POLICY_ACTIONS)
        policy = {"Policy": {"DefaultVersion": "v2"}, "RequestId": "policy-request"}
        version = {
            "PolicyVersion": {
                "PolicyDocument": json.dumps(
                    {"Version": "1", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}
                )
            },
            "RequestId": "version-request",
        }
        attachments = {
            "Policies": {
                "Policy": [{"PolicyType": "System", "PolicyName": "AliyunResourceCenterReadOnlyAccess"}]
            },
            "RequestId": "attachment-request",
        }
        identity = {
            "IdentityType": "AssumedRoleUser",
            "Arn": "acs:sts::opaque:assumed-role/titmas-read-only/session",
            "RequestId": "identity-request",
        }
        return policy, version, attachments, identity

    def test_builds_schema_valid_sanitized_observation(self) -> None:
        policy, version, attachments, identity = self.fixtures()
        observation = build_sanitized_observation(
            role_name="TITMAS-READ-ONLY",
            policy_payload=policy,
            policy_version_payload=version,
            attachments_payload=attachments,
            identity_payload=identity,
            observed_at=datetime(2026, 8, 2, tzinfo=UTC),
        )
        validate_contract("alibabacloud_ram_policy_observation", observation)
        self.assertEqual(observation["attachment"]["total_attachment_count"], 1)
        self.assertEqual(observation["attachment"]["unexpected_attachment_count"], 0)
        serialized = str(observation)
        self.assertNotIn("acs:sts::", serialized)
        self.assertNotIn("policy-request", serialized)

    def test_extra_attachment_fails_closed(self) -> None:
        policy, version, attachments, identity = self.fixtures()
        attachments = copy.deepcopy(attachments)
        attachments["Policies"]["Policy"].append({"PolicyType": "Custom", "PolicyName": "Unexpected"})
        with self.assertRaises(ContractValidationError):
            build_sanitized_observation(
                role_name="titmas-read-only",
                policy_payload=policy,
                policy_version_payload=version,
                attachments_payload=attachments,
                identity_payload=identity,
                observed_at=datetime(2026, 8, 2, tzinfo=UTC),
            )

if __name__ == "__main__":
    unittest.main()
