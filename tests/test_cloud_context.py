from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from scripts.capture_alibabacloud_ram_policy_observation import build_sanitized_observation
from titmas_action_gate.canonical import sha256_file, sha256_json
from titmas_action_gate.cloud_context import (
    OFFICIAL_ALIYUN_CLI_SHA256,
    OFFICIAL_RESOURCE_CENTER_ENDPOINT,
    OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256,
    OFFICIAL_USER_AGENT,
    AliyunCliReadOnlyExecutor,
    CliExecution,
    CloudContextInspector,
    CloudCredentialContext,
    credential_from_policy_observation,
    is_semantically_usable_cloud_context,
)
from titmas_action_gate.contracts import validate_contract
from titmas_action_gate.errors import ContractValidationError
from titmas_action_gate.service import ActionGateService

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_SKILL_ROOT = Path(
    os.environ.get(
        "TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH",
        Path.home() / ".local/share/titmas-agent-action-gate/external-skills/alibabacloud-resourcecenter-search",
    )
).resolve()
_ORIGINAL_EXTERNAL_SKILL_ENV: str | None = None


def setUpModule() -> None:
    global _ORIGINAL_EXTERNAL_SKILL_ENV
    _ORIGINAL_EXTERNAL_SKILL_ENV = os.environ.get("TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH")
    os.environ["TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH"] = str(EXTERNAL_SKILL_ROOT)


def tearDownModule() -> None:
    if _ORIGINAL_EXTERNAL_SKILL_ENV is None:
        os.environ.pop("TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH", None)
    else:
        os.environ["TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH"] = _ORIGINAL_EXTERNAL_SKILL_ENV


class FakeExecutor:
    def __init__(self, execution: CliExecution):
        self.execution = execution
        self.calls = 0

    def execute(self, query: dict, credential: CloudCredentialContext) -> CliExecution:
        self.calls += 1
        return self.execution


def confirmed_query(**overrides: object) -> dict:
    value = {
        "schema_version": "0.1.0",
        "operation": "resourcecenter.search-resources",
        "max_results": 1,
        "filters": {},
        "include_deleted_resources": False,
        "parameters_confirmed_by_user": True,
        "confirmation_ref": "confirmation:" + "a" * 64,
    }
    value.update(overrides)
    return value


def credential(*, verified: bool = True, observed_at: datetime | None = None) -> CloudCredentialContext:
    policy_observed_at = observed_at or datetime.now(UTC)
    return CloudCredentialContext(
        profile_name="secret-profile-name-never-retained",
        permission_identity="acs:ram::example:user/titmas-read-only",
        permission_role_ref="sha256:" + "c" * 64,
        permission_policy_ref="AliyunResourceCenterReadOnlyAccess",
        read_only_policy_verified=verified,
        policy_observation_freshness="FRESH",
        same_run_policy_readback_verified=True,
        policy_observation_observed_at=policy_observed_at,
    )


def available_execution() -> CliExecution:
    return CliExecution(
        status="CLOUD_CONTEXT_AVAILABLE",
        cli_version="3.3.4",
        exit_status=0,
        returned_resource_count=1,
        next_token_present=False,
        resource_type_count=1,
        region_count=1,
        request_id_ref="sha256:" + "b" * 64,
        step_trace=[{"step_id": "VERIFY_LIVE_CALLER_IDENTITY", "effect": "CLOUD_READ", "exit_status": 0}],
    )


class CloudContextBoundaryTests(unittest.TestCase):
    @staticmethod
    def _fresh_v02_policy_observation(run_id: str, observed_at: datetime) -> dict:
        actions = sorted(
            {
                "resourcecenter:ExecuteMultiAccountSQLQuery",
                "resourcecenter:ExecuteSQLQuery",
                "resourcecenter:Get*",
                "resourcecenter:List*",
                "resourcecenter:Search*",
                "tag:ListTag*",
            }
        )
        return build_sanitized_observation(
            run_id=run_id,
            capture_id="sha256:" + "e" * 64,
            started_at=observed_at,
            completed_at=observed_at,
            trace_observed_at=(observed_at, observed_at, observed_at, observed_at),
            role_name="test-role",
            policy_payload={"Policy": {"DefaultVersion": "v2"}, "RequestId": "policy-request"},
            policy_version_payload={
                "PolicyVersion": {
                    "PolicyDocument": {
                        "Version": "1",
                        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
                    }
                },
                "RequestId": "version-request",
            },
            attachments_payload={
                "Policies": {
                    "Policy": [{"PolicyType": "System", "PolicyName": "AliyunResourceCenterReadOnlyAccess"}]
                },
                "RequestId": "attachments-request",
            },
            identity_payload={
                "IdentityType": "AssumedRoleUser",
                "Arn": "acs:sts::opaque:assumed-role/test-role/session",
                "RequestId": "identity-request",
            },
        )

    def test_cli_command_pins_official_endpoint_and_runtime_profile(self) -> None:
        argv = AliyunCliReadOnlyExecutor._search_argv("/usr/local/bin/aliyun", confirmed_query(), credential())
        self.assertEqual(argv[:3], ["/usr/local/bin/aliyun", "resourcecenter", "search-resources"])
        self.assertIn("--endpoint", argv)
        self.assertEqual(argv[argv.index("--endpoint") + 1], OFFICIAL_RESOURCE_CENTER_ENDPOINT)
        self.assertEqual(argv[argv.index("--user-agent") + 1], OFFICIAL_USER_AGENT)
        self.assertEqual(argv[argv.index("--profile") + 1], "secret-profile-name-never-retained")

    @staticmethod
    def _resource_search_execution(
        payload: object,
        *,
        returncode: int = 0,
        stderr: str = "",
    ) -> CliExecution:
        arn = "acs:sts::opaque:assumed-role/test-role/session"
        bound_credential = CloudCredentialContext(
            profile_name="runtime-profile",
            permission_identity="sha256:" + hashlib.sha256(f"identity:{arn}".encode()).hexdigest(),
            permission_role_ref="sha256:" + hashlib.sha256(b"role:test-role").hexdigest(),
            permission_policy_ref="sha256:" + "d" * 64,
            read_only_policy_verified=True,
        )

        class ScriptedExecutor(AliyunCliReadOnlyExecutor):
            def _run(self, argv: list[str]) -> CompletedProcess[str]:
                if argv[1:] == ["version"]:
                    return CompletedProcess(argv, 0, stdout="aliyun version 3.4.11", stderr="")
                if argv[1:3] == ["sts", "GetCallerIdentity"]:
                    return CompletedProcess(
                        argv,
                        0,
                        stdout=json.dumps({"IdentityType": "AssumedRoleUser", "Arn": arn}),
                        stderr="",
                    )
                if argv[1:3] == ["resourcecenter", "search-resources"]:
                    return CompletedProcess(argv, returncode, stdout=json.dumps(payload), stderr=stderr)
                return CompletedProcess(argv, 0, stdout="", stderr="")

        def pinned_digest(path: Path) -> str:
            return OFFICIAL_ALIYUN_CLI_SHA256 if path.name == "fake-aliyun" else OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256

        with (
            patch("titmas_action_gate.cloud_context.shutil.which", return_value="/tmp/fake-aliyun"),
            patch("titmas_action_gate.cloud_context.Path.is_file", return_value=True),
            patch("titmas_action_gate.cloud_context.sha256_file", side_effect=pinned_digest),
        ):
            return ScriptedExecutor().execute(confirmed_query(), bound_credential)

    def test_resources_null_is_rejected(self) -> None:
        result = self._resource_search_execution({"Resources": None})
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_resources_string_is_rejected(self) -> None:
        result = self._resource_search_execution({"Resources": "not-a-resource-list"})
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_resources_with_non_object_item_is_rejected(self) -> None:
        result = self._resource_search_execution({"Resources": ["not-a-resource-object"]})
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_empty_resource_object_is_rejected(self) -> None:
        result = self._resource_search_execution({"Resources": [{}]})
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_empty_resources_remain_a_valid_empty_result(self) -> None:
        result = self._resource_search_execution({"Resources": [], "RequestId": "opaque"})
        self.assertEqual(result.status, "NOT_ASSESSED_NO_VISIBLE_RESOURCE")
        self.assertEqual(result.returned_resource_count, 0)
        observed = CloudContextInspector(ROOT, FakeExecutor(result)).inspect(
            "aar-cloud-context-empty-result",
            confirmed_query(),
            credential(),
        )
        self.assertEqual(observed["invocation"]["result_class"], "EMPTY_RESULT")

    def test_successful_resource_data_containing_forbidden_remains_successful(self) -> None:
        result = self._resource_search_execution(
            {
                "Resources": [
                    {
                        "ResourceId": "i-visible-001",
                        "ResourceName": "Forbidden is ordinary resource data",
                        "ResourceType": "ACS::ECS::Instance",
                        "RegionId": "cn-test",
                        "Tags": [{"Key": "note", "Value": "AccessDenied is also ordinary data"}],
                    }
                ]
            }
        )
        self.assertEqual(result.status, "CLOUD_CONTEXT_AVAILABLE")
        self.assertEqual(result.returned_resource_count, 1)

    def test_resource_id_must_be_a_nonempty_string(self) -> None:
        missing = object()
        for value in (missing, None, "", "   ", 7):
            with self.subTest(value=value):
                resource = {"ResourceType": "ACS::ECS::Instance"}
                if value is not missing:
                    resource["ResourceId"] = value
                result = self._resource_search_execution({"Resources": [resource]})
                self.assertEqual(result.status, "INVOCATION_FAILED")
                self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_resource_type_must_be_a_nonempty_string(self) -> None:
        missing = object()
        for value in (missing, None, "", "   ", 7):
            with self.subTest(value=value):
                resource = {"ResourceId": "i-visible-001"}
                if value is not missing:
                    resource["ResourceType"] = value
                result = self._resource_search_execution({"Resources": [resource]})
                self.assertEqual(result.status, "INVOCATION_FAILED")
                self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_valid_resource_identity_and_type_is_accepted(self) -> None:
        result = self._resource_search_execution(
            {"Resources": [{"ResourceId": "i-visible-001", "ResourceType": "ACS::ECS::Instance"}]}
        )
        self.assertEqual(result.status, "CLOUD_CONTEXT_AVAILABLE")
        self.assertEqual(result.returned_resource_count, 1)

    def test_lower_camel_resource_identity_and_type_are_accepted(self) -> None:
        result = self._resource_search_execution(
            {"Resources": [{"resourceId": "i-visible-001", "resourceType": "ACS::ECS::Instance"}]}
        )
        self.assertEqual(result.status, "CLOUD_CONTEXT_AVAILABLE")

    def test_invalid_canonical_resource_identity_is_not_masked_by_alias(self) -> None:
        result = self._resource_search_execution(
            {
                "Resources": [
                    {
                        "ResourceId": " ",
                        "resourceId": "i-visible-001",
                        "ResourceType": "ACS::ECS::Instance",
                    }
                ]
            }
        )
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_RESPONSE_INVALID_RESOURCES",))

    def test_structured_access_denied_provider_error_remains_permission_denied(self) -> None:
        result = self._resource_search_execution(
            {"Code": "AccessDenied", "Message": "redacted"},
            returncode=1,
        )
        self.assertEqual(result.status, "NOT_ASSESSED_PERMISSION_DENIED")
        self.assertEqual(result.uncertainty, ("RAM_PERMISSION_DENIED",))

    def test_non_permission_provider_failure_remains_generic_invocation_failure(self) -> None:
        result = self._resource_search_execution(
            {"Code": "Throttling", "Message": "ordinary provider failure"},
            returncode=1,
        )
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_SEARCH_FAILED_REDACTED",))

    def test_policy_observation_rejects_extra_attachment(self) -> None:
        observation = json.loads((ROOT / "governance/alibabacloud-ram-policy-observation-20260802.json").read_text(encoding="utf-8"))
        observation["attachment"]["total_attachment_count"] = 2
        observation["attachment"]["unexpected_attachment_count"] = 1
        with tempfile.TemporaryDirectory(prefix="titmas-policy-observation-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            with self.assertRaises(ContractValidationError):
                credential_from_policy_observation("runtime-profile", path)

    def test_policy_observation_requires_each_readback_operation_once(self) -> None:
        observation = json.loads((ROOT / "governance/alibabacloud-ram-policy-observation-20260802.json").read_text(encoding="utf-8"))
        observation["read_trace"][-1]["operation"] = "ram.GetPolicy"
        with tempfile.TemporaryDirectory(prefix="titmas-policy-observation-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            with self.assertRaises(ValueError):
                credential_from_policy_observation("runtime-profile", path)

    def test_stale_policy_observation_fails_closed_before_provider_call(self) -> None:
        path = ROOT / "governance/alibabacloud-ram-policy-observation-20260802.json"
        assessed_at = datetime(2026, 8, 2, 7, 4, 43, tzinfo=UTC)
        cloud_credential, _ = credential_from_policy_observation(
            "runtime-profile",
            path,
            assessed_at=assessed_at,
            expected_run_id="run-native-alibaba-cloud-20260802-001",
        )
        cloud_credential = replace(cloud_credential, read_only_policy_verified=False)
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-stale-policy",
            confirmed_query(),
            cloud_credential,
            observed_at=assessed_at,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED_POLICY_OBSERVATION_STALE")
        self.assertIn("POLICY_OBSERVATION_MAXIMUM_AGE_EXCEEDED", result["uncertainty"])
        self.assertEqual(executor.calls, 0)

    def test_future_dated_policy_observation_fails_closed_before_provider_call(self) -> None:
        path = ROOT / "governance/alibabacloud-ram-policy-observation-20260802.json"
        assessed_at = datetime(2026, 8, 2, 6, 49, 41, tzinfo=UTC)
        cloud_credential, _ = credential_from_policy_observation(
            "runtime-profile",
            path,
            assessed_at=assessed_at,
            expected_run_id="run-native-alibaba-cloud-20260802-001",
        )
        cloud_credential = replace(cloud_credential, read_only_policy_verified=False)
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-future-policy",
            confirmed_query(),
            cloud_credential,
            observed_at=assessed_at,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED_POLICY_OBSERVATION_STALE")
        self.assertIn("POLICY_OBSERVATION_FUTURE_DATED", result["uncertainty"])
        self.assertEqual(executor.calls, 0)

    def test_fresh_different_run_policy_observation_fails_closed_before_provider_call(self) -> None:
        assessed_at = datetime(2026, 8, 2, 6, 49, 43, tzinfo=UTC)
        observation = self._fresh_v02_policy_observation("run-policy-source-001", assessed_at)
        with tempfile.TemporaryDirectory(prefix="titmas-different-run-policy-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            cloud_credential, _ = credential_from_policy_observation(
                "runtime-profile",
                path,
                assessed_at=assessed_at,
                expected_run_id="run-different-preflight-001",
            )
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-different-run-policy",
            confirmed_query(),
            cloud_credential,
            observed_at=assessed_at,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertIn("POLICY_OBSERVATION_NOT_SAME_RUN", result["uncertainty"])
        self.assertEqual(executor.calls, 0)

    def test_policy_observation_freshness_is_rechecked_at_invocation(self) -> None:
        policy_time = datetime(2026, 8, 2, 6, 49, 42, tzinfo=UTC)
        observation = self._fresh_v02_policy_observation("run-policy-aging-test-001", policy_time)
        with tempfile.TemporaryDirectory(prefix="titmas-aging-policy-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            cloud_credential, _ = credential_from_policy_observation(
                "runtime-profile",
                path,
                assessed_at=datetime(2026, 8, 2, 6, 49, 43, tzinfo=UTC),
                expected_run_id=observation["capture"]["run_id"],
            )
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-aged-before-use",
            confirmed_query(),
            cloud_credential,
            observed_at=datetime(2026, 8, 2, 7, 4, 43, tzinfo=UTC),
        )
        self.assertEqual(result["status"], "NOT_ASSESSED_POLICY_OBSERVATION_STALE")
        self.assertEqual(executor.calls, 0)

    def test_historical_policy_observation_is_reviewable_but_release_ineligible(self) -> None:
        observation = json.loads(
            (ROOT / "governance/alibabacloud-ram-policy-observation-20260802.json").read_text(encoding="utf-8")
        )
        validate_contract("alibabacloud_ram_policy_observation_v01", observation)
        historical = json.loads(
            (ROOT / "demo/evidence/agentteams-native-alibabacloud-skill-20260802.json").read_text(encoding="utf-8")
        )["cloud_context"]
        validate_contract("cloud_context_result_v01", historical)
        self.assertFalse(is_semantically_usable_cloud_context(historical))

    def test_fresh_same_run_policy_readback_can_satisfy_freshness_checks(self) -> None:
        assessed_at = datetime(2026, 8, 2, 6, 49, 43, tzinfo=UTC)
        observation = self._fresh_v02_policy_observation("run-fresh-policy-readback-001", assessed_at)
        with tempfile.TemporaryDirectory(prefix="titmas-fresh-policy-observation-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            cloud_credential, _ = credential_from_policy_observation(
                "runtime-profile",
                path,
                assessed_at=assessed_at,
                expected_run_id=observation["capture"]["run_id"],
            )
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-fresh-policy",
            confirmed_query(),
            cloud_credential,
            observed_at=assessed_at,
        )
        self.assertEqual(result["status"], "CLOUD_CONTEXT_AVAILABLE")
        self.assertEqual(executor.calls, 1)
        self.assertTrue(is_semantically_usable_cloud_context(result))

    def test_unverified_read_only_policy_fails_closed_before_provider_call(self) -> None:
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-policy-not-verified",
            confirmed_query(),
            credential(verified=False),
        )
        self.assertEqual(result["status"], "NOT_ASSESSED_POLICY_NOT_VERIFIED")
        self.assertEqual(
            result["checks"],
            [
                {"check_id": "CREDENTIAL_REFERENCE_PRESENT", "passed": True},
                {"check_id": "READ_ONLY_POLICY_REFERENCE", "passed": False},
                {"check_id": "POLICY_OBSERVATION_FRESH", "passed": True},
                {"check_id": "SAME_RUN_POLICY_READBACK", "passed": True},
            ],
        )
        self.assertEqual(result["uncertainty"], ["READ_ONLY_POLICY_VERIFICATION_FAILED"])
        self.assertEqual(result["credential"]["read_only_policy_verified"], "FAIL")
        self.assertFalse(result["skill"]["runtime_invoked"])
        self.assertFalse(result["invocation"]["invoked"])
        self.assertEqual(result["invocation"]["result_class"], "NOT_INVOKED")
        self.assertEqual(result["invocation"]["steps"], [])
        self.assertEqual(result["resourcecenter_write_api_calls"], 0)
        self.assertEqual(executor.calls, 0)
        self.assertFalse(is_semantically_usable_cloud_context(result))

    def test_fresh_policy_without_timestamp_fails_closed_before_provider_call(self) -> None:
        cloud_credential = replace(credential(), policy_observation_observed_at=None)
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-policy-timestamp-missing",
            confirmed_query(),
            cloud_credential,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertEqual(result["uncertainty"], ["POLICY_OBSERVATION_TIMESTAMP_MISSING"])
        self.assertFalse(result["skill"]["runtime_invoked"])
        self.assertFalse(result["invocation"]["invoked"])
        self.assertEqual(result["invocation"]["result_class"], "NOT_INVOKED")
        self.assertEqual(result["resourcecenter_write_api_calls"], 0)
        self.assertEqual(executor.calls, 0)

    def test_fresh_policy_with_naive_timestamp_fails_closed_before_provider_call(self) -> None:
        cloud_credential = credential(observed_at=datetime(2026, 8, 2, 6, 49, 43))
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-policy-timestamp-naive",
            confirmed_query(),
            cloud_credential,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertEqual(result["uncertainty"], ["POLICY_OBSERVATION_TIMESTAMP_TIMEZONE_MISSING"])
        self.assertFalse(result["skill"]["runtime_invoked"])
        self.assertFalse(result["invocation"]["invoked"])
        self.assertEqual(result["resourcecenter_write_api_calls"], 0)
        self.assertEqual(executor.calls, 0)

    def test_relabelled_legacy_observation_is_rejected(self) -> None:
        observation = json.loads(
            (ROOT / "governance/alibabacloud-ram-policy-observation-20260802.json").read_text(encoding="utf-8")
        )
        observation.update(
            {
                "$schema": "../schemas/alibabacloud-ram-policy-observation.v0.2.schema.json",
                "schema_version": "0.2.0",
            }
        )
        with tempfile.TemporaryDirectory(prefix="titmas-relabeled-policy-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            with self.assertRaises(ContractValidationError):
                credential_from_policy_observation(
                    "runtime-profile",
                    path,
                    assessed_at=datetime(2026, 8, 2, 6, 49, 43, tzinfo=UTC),
                    expected_run_id="run-relabeled-policy-001",
                )

    def test_recombined_capture_trace_is_rejected(self) -> None:
        assessed_at = datetime(2026, 8, 2, 6, 49, 43, tzinfo=UTC)
        observation = self._fresh_v02_policy_observation("run-recombined-policy-001", assessed_at)
        observation["read_trace"][2]["capture_id"] = "sha256:" + "f" * 64
        with tempfile.TemporaryDirectory(prefix="titmas-recombined-policy-") as tempdir:
            path = Path(tempdir) / "observation.json"
            path.write_text(json.dumps(observation), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "POLICY_OBSERVATION_CAPTURE_INVALID"):
                credential_from_policy_observation(
                    "runtime-profile",
                    path,
                    assessed_at=assessed_at,
                    expected_run_id=observation["capture"]["run_id"],
                )

    def test_unassessed_policy_context_never_invokes_provider(self) -> None:
        cloud_credential = CloudCredentialContext(
            profile_name="runtime-profile",
            permission_identity="sha256:" + "a" * 64,
            permission_role_ref="sha256:" + "b" * 64,
            permission_policy_ref="sha256:" + "c" * 64,
            read_only_policy_verified=True,
        )
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-policy-unassessed",
            confirmed_query(),
            cloud_credential,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertIn("POLICY_OBSERVATION_NOT_ASSESSED", result["uncertainty"])
        self.assertEqual(executor.calls, 0)

    def test_live_profile_identity_mismatch_blocks_before_resource_search(self) -> None:
        class ScriptedExecutor(AliyunCliReadOnlyExecutor):
            def __init__(self) -> None:
                super().__init__()
                self.argv: list[list[str]] = []

            def _run(self, argv: list[str]) -> CompletedProcess[str]:
                self.argv.append(argv)
                index = len(self.argv)
                if index == 3:
                    return CompletedProcess(argv, 0, stdout="aliyun version 3.4.11", stderr="")
                if index == 5:
                    return CompletedProcess(
                        argv,
                        0,
                        stdout=json.dumps(
                            {
                                "IdentityType": "AssumedRoleUser",
                                "Arn": "acs:sts::opaque:assumed-role/different-role/session",
                            }
                        ),
                        stderr="",
                    )
                return CompletedProcess(argv, 0, stdout="", stderr="")

        executor = ScriptedExecutor()

        def pinned_digest(path: Path) -> str:
            return OFFICIAL_ALIYUN_CLI_SHA256 if path.name == "fake-aliyun" else OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256

        with (
            patch("titmas_action_gate.cloud_context.shutil.which", return_value="/tmp/fake-aliyun"),
            patch("titmas_action_gate.cloud_context.Path.is_file", return_value=True),
            patch("titmas_action_gate.cloud_context.sha256_file", side_effect=pinned_digest),
        ):
            result = executor.execute(confirmed_query(), credential())
        self.assertEqual(result.status, "NOT_ASSESSED")
        self.assertEqual(result.uncertainty, ("LIVE_READ_ONLY_IDENTITY_BINDING_MISMATCH",))
        self.assertFalse(any(argv[1:3] == ["resourcecenter", "search-resources"] for argv in executor.argv))

    def test_plugin_change_before_search_fails_closed(self) -> None:
        result, argv = self._plugin_change_execution(change_on_plugin_check=2)
        self.assertEqual(result.status, "NOT_ASSESSED")
        self.assertEqual(result.uncertainty, ("RESOURCE_CENTER_PLUGIN_PIN_CHANGED_BEFORE_QUERY",))
        self.assertFalse(any(item[1:3] == ["resourcecenter", "search-resources"] for item in argv))

    def test_plugin_change_during_search_invalidates_result(self) -> None:
        result, argv = self._plugin_change_execution(change_on_plugin_check=3)
        self.assertEqual(result.status, "INVOCATION_FAILED")
        self.assertEqual(result.uncertainty, ("RESOURCE_CENTER_PLUGIN_PIN_CHANGED_DURING_INVOCATION",))
        self.assertTrue(any(item[1:3] == ["resourcecenter", "search-resources"] for item in argv))

    @staticmethod
    def _plugin_change_execution(change_on_plugin_check: int) -> tuple[CliExecution, list[list[str]]]:
        arn = "acs:sts::opaque:assumed-role/test-role/session"
        bound_credential = CloudCredentialContext(
            profile_name="runtime-profile",
            permission_identity="sha256:" + hashlib.sha256(f"identity:{arn}".encode()).hexdigest(),
            permission_role_ref="sha256:" + hashlib.sha256(b"role:test-role").hexdigest(),
            permission_policy_ref="sha256:" + "d" * 64,
            read_only_policy_verified=True,
        )

        class ScriptedExecutor(AliyunCliReadOnlyExecutor):
            def __init__(self) -> None:
                super().__init__()
                self.argv: list[list[str]] = []

            def _run(self, argv: list[str]) -> CompletedProcess[str]:
                self.argv.append(argv)
                if argv[1:] == ["version"]:
                    return CompletedProcess(argv, 0, stdout="aliyun version 3.4.11", stderr="")
                if argv[1:3] == ["sts", "GetCallerIdentity"]:
                    return CompletedProcess(
                        argv,
                        0,
                        stdout=json.dumps({"IdentityType": "AssumedRoleUser", "Arn": arn}),
                        stderr="",
                    )
                if argv[1:3] == ["resourcecenter", "search-resources"]:
                    return CompletedProcess(argv, 0, stdout=json.dumps({"Resources": [], "RequestId": "opaque"}), stderr="")
                return CompletedProcess(argv, 0, stdout="", stderr="")

        plugin_checks = 0

        def changing_digest(path: Path) -> str:
            nonlocal plugin_checks
            if path.name == "fake-aliyun":
                return OFFICIAL_ALIYUN_CLI_SHA256
            plugin_checks += 1
            if plugin_checks >= change_on_plugin_check:
                return "0" * 64
            return OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256

        executor = ScriptedExecutor()
        with (
            patch("titmas_action_gate.cloud_context.shutil.which", return_value="/tmp/fake-aliyun"),
            patch("titmas_action_gate.cloud_context.Path.is_file", return_value=True),
            patch("titmas_action_gate.cloud_context.sha256_file", side_effect=changing_digest),
        ):
            result = executor.execute(confirmed_query(), bound_credential)
        return result, executor.argv

    def test_valid_result_is_sanitized_and_has_no_gate_authority(self) -> None:
        assessed_at = datetime(2026, 8, 2, tzinfo=UTC)
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-test-001",
            confirmed_query(filters={"resource_type": "ACS::ECS::Instance"}),
            credential(observed_at=assessed_at),
            observed_at=assessed_at,
        )
        self.assertEqual(result["status"], "CLOUD_CONTEXT_AVAILABLE")
        self.assertTrue(is_semantically_usable_cloud_context(result))
        self.assertEqual(executor.calls, 1)
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("secret-profile-name-never-retained", serialized)
        self.assertNotIn("acs:ram::example", serialized)
        self.assertNotIn("AliyunResourceCenterReadOnlyAccess", serialized)
        self.assertNotIn("ALLOW", result)
        self.assertNotIn("BLOCK", result)
        self.assertNotIn("REQUIRE_APPROVAL", result)
        self.assertEqual(result["resourcecenter_write_api_calls"], 0)

    def test_write_operation_is_blocked_before_executor(self) -> None:
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-test-002",
            confirmed_query(operation="resourcecenter.disable-resource-center"),
            credential(),
        )
        self.assertEqual(result["status"], "BLOCKED_BY_SKILL_BOUNDARY")
        self.assertEqual(executor.calls, 0)
        self.assertFalse(result["invocation"]["invoked"])
        self.assertEqual(result["query"]["operation"], "REJECTED")

    def test_rejected_query_does_not_retain_caller_text(self) -> None:
        executor = FakeExecutor(available_execution())
        marker = "SENSITIVE_MARKER_SHOULD_NOT_PERSIST"
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-test-002a",
            confirmed_query(operation=marker, confirmation_ref=marker),
            credential(),
        )
        self.assertEqual(result["status"], "BLOCKED_BY_SKILL_BOUNDARY")
        self.assertNotIn(marker, json.dumps(result))
        self.assertEqual(executor.calls, 0)

    def test_paginated_result_is_not_semantically_usable(self) -> None:
        paginated = replace(
            available_execution(),
            next_token_present=True,
            uncertainty=("SINGLE_PAGE_OBSERVATION_NOT_COMPLETE_INVENTORY",),
        )
        result = CloudContextInspector(ROOT, FakeExecutor(paginated)).inspect(
            "aar-cloud-context-test-002b",
            confirmed_query(),
            credential(),
        )
        self.assertEqual(result["status"], "CLOUD_CONTEXT_AVAILABLE")
        self.assertFalse(is_semantically_usable_cloud_context(result))

    def test_zero_visible_resources_is_not_semantically_usable(self) -> None:
        empty = replace(
            available_execution(),
            status="NOT_ASSESSED_NO_VISIBLE_RESOURCE",
            returned_resource_count=0,
            resource_type_count=0,
            region_count=0,
            uncertainty=("ZERO_RESULTS_ONLY_MEAN_NO_RESOURCES_VISIBLE_TO_THIS_BOUNDED_IDENTITY",),
        )
        result = CloudContextInspector(ROOT, FakeExecutor(empty)).inspect(
            "aar-cloud-context-test-002c",
            confirmed_query(),
            credential(),
        )
        self.assertEqual(result["status"], "NOT_ASSESSED_NO_VISIBLE_RESOURCE")
        self.assertEqual(result["invocation"]["result_class"], "EMPTY_RESULT")
        self.assertFalse(is_semantically_usable_cloud_context(result))

    def test_missing_credential_is_not_assessed(self) -> None:
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(
            "aar-cloud-context-test-003",
            confirmed_query(),
            None,
        )
        self.assertEqual(result["status"], "NOT_ASSESSED")
        self.assertEqual(executor.calls, 0)

    def test_permission_denied_is_not_assessed_permission_denied(self) -> None:
        denied = replace(available_execution(), status="NOT_ASSESSED_PERMISSION_DENIED", exit_status=1, returned_resource_count=None)
        result = CloudContextInspector(ROOT, FakeExecutor(denied)).inspect(
            "aar-cloud-context-test-004",
            confirmed_query(),
            credential(),
        )
        self.assertEqual(result["status"], "NOT_ASSESSED_PERMISSION_DENIED")
        self.assertFalse(is_semantically_usable_cloud_context(result))

    def test_tampered_official_skill_hash_rejects_load(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-cloud-skill-tamper-") as tempdir:
            target = Path(tempdir) / "repo"
            external = Path(tempdir) / "external-skill"
            (target / "governance").mkdir(parents=True)
            shutil.copy2(
                ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json",
                target / "governance/alibabacloud-resourcecenter-search-source-lock.json",
            )
            shutil.copytree(EXTERNAL_SKILL_ROOT, external)
            skill_path = external / "SKILL.md"
            skill_path.write_text(skill_path.read_text(encoding="utf-8") + "\ntampered\n", encoding="utf-8")
            executor = FakeExecutor(available_execution())
            result = CloudContextInspector(target, executor, external_skill_path=external).inspect(
                "aar-cloud-context-test-005",
                confirmed_query(),
                credential(),
            )
        self.assertEqual(result["status"], "SKILL_LOAD_REJECTED")
        self.assertEqual(executor.calls, 0)

    def test_tampered_skill_and_source_lock_hash_are_both_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-cloud-skill-lock-tamper-") as tempdir:
            target = Path(tempdir) / "repo"
            external = Path(tempdir) / "external-skill"
            (target / "governance").mkdir(parents=True)
            lock_path = target / "governance/alibabacloud-resourcecenter-search-source-lock.json"
            lock = json.loads((ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json").read_text(encoding="utf-8"))
            shutil.copytree(EXTERNAL_SKILL_ROOT, external)
            skill_path = external / "SKILL.md"
            skill_path.write_text(skill_path.read_text(encoding="utf-8") + "\ntampered-with-lock\n", encoding="utf-8")
            lock["files"][0]["sha256"] = sha256_file(skill_path)
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            executor = FakeExecutor(available_execution())
            result = CloudContextInspector(target, executor, external_skill_path=external).inspect(
                "aar-cloud-context-test-005b",
                confirmed_query(),
                credential(),
            )
        self.assertEqual(result["status"], "SKILL_LOAD_REJECTED")
        self.assertEqual(executor.calls, 0)


class CloudContextEvidencePathTests(unittest.TestCase):
    def test_typed_cloud_receipt_enters_agent_evidence_and_release_gate(self) -> None:
        request = {
            "schema_version": "0.1.0",
            "request_id": "aar-cloud-release-test-001",
            "created_at": "2026-08-02T00:00:00Z",
            "requested_by": {"agent_id": "release-steward", "team_id": "titmas-action-gate"},
            "action": "github.release.create",
            "target": {
                "provider": "github",
                "repository": "joy7758/action-gate-demo",
                "resource_ref": "release/v0.2.0-demo",
            },
            "parameters": {"tag": "v0.2.0-demo", "draft": True},
            "parameters_sha256": "",
            "evidence_requirements": ["SOURCE_PIN", "TEST_RESULT", "TAG_STATE", "RELEASE_MANIFEST", "CLOUD_CONTEXT"],
            "uncertainty": ["No release, deployment, or cloud write is authorized by this preflight."],
            "idempotency_key": "cloud-release-test-001",
        }
        request["parameters_sha256"] = sha256_json(request["parameters"])
        executor = FakeExecutor(available_execution())
        result = CloudContextInspector(ROOT, executor).inspect(request["request_id"], confirmed_query(), credential())
        with tempfile.TemporaryDirectory(prefix="titmas-cloud-evidence-") as state_dir:
            service = ActionGateService.demo(state_dir)
            service.submit_action_request(request, caller_token="titmas-demo-caller-token", actor="release-steward")
            retained = service.record_cloud_context_preflight(
                request["request_id"],
                result,
                caller_token="titmas-demo-caller-token",
                actor="cloud-context-inspector",
            )
            self.assertTrue(retained["semantically_usable"])
            self.assertEqual(retained["agent_evidence_receipt"]["status"], "VALID")
            profile = service.generate_evidence_profile(
                request["request_id"],
                actor="release-steward",
                phase="pre-release",
                operation_status="succeeded",
                output={"tests": "passed", "release_created": False},
                evidence_types=request["evidence_requirements"],
            )
            path = service.evidence.write_profile(profile, "cloud-release-final.json")
            service.attach_evidence(
                request["request_id"],
                path,
                request["evidence_requirements"],
                caller_token="titmas-demo-caller-token",
                actor="release-steward",
            )
            verified = service.verify_evidence(
                request["request_id"],
                caller_token="titmas-demo-caller-token",
                actor="evidence-verifier",
            )
            decision = service.evaluate_action_gate(
                request["request_id"],
                caller_token="titmas-demo-caller-token",
                actor="release-steward",
            )["payload"]
            self.assertEqual(verified["status"], "VALID")
            self.assertEqual(decision["outcome"], "REQUIRE_APPROVAL")
            self.assertEqual(decision["reason_codes"], ["HUMAN_APPROVAL_REQUIRED"])
            self.assertEqual(service.store.verify_chain(), [])


if __name__ == "__main__":
    unittest.main()
