"""Typed, read-only adapter for the pinned Alibaba Cloud Resource Center Skill.

The Agent never receives credential bytes or arbitrary CLI access.  This module
accepts one schema-validated query plan and constructs one fixed
``resourcecenter search-resources`` command with ``shell=False``.  Raw provider
stdout and stderr are parsed in memory and are never returned in evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from .canonical import format_datetime, sha256_file, sha256_json, utc_now
from .contracts import validate_contract

OFFICIAL_SKILL_NAME = "alibabacloud-resourcecenter-search"
OFFICIAL_SKILL_REPOSITORY = "https://github.com/aliyun/alibabacloud-aiops-skills"
OFFICIAL_SKILL_REVISION = "92bd723f7cc217b252feab574c1883fa0aa46b3c"
OFFICIAL_SKILL_GIT_TREE = "aa1ffc6bf879686490646e607c4c59cd1d499b11"
OFFICIAL_SKILL_FILE_HASHES = {
    "SKILL.md": "6f6290be0a9f0c6ad93a3a1e3a8be5bee5eee07ce3f13c89a89f2a7b6258eddd",
    "references/acceptance-criteria.md": "7620dac51436387d516e376cae61ecf4678dddec5724703e9f7215f3b0999904",
    "references/cli-installation-guide.md": "93abdd4f4a067822cca6894aa890855a50e723a6f6243f208887f171d6635170",
    "references/error-codes.md": "041376693feaf36f1ca18c31d64c718734b66c1550cdcc82ca9e67de0800859b",
    "references/ram-policies.md": "84facc0bd85656e8862d93383a359c27255be972f4bd1323f39500f6d8221e3a",
    "references/related-apis.md": "f33c2e947b0346c250ca46ab93c282ca5f973cfbd194a87ea9a345331c7962fe",
    "references/verification-method.md": "f2b2d03a26d322f059c45f055eefe8cdc0bb64e5724561d33657f30a21ff6add",
    "scripts/query-resource-types.py": "2f4ee2deb67e886ad6d0c1ac984dd5e5a96d116fecfc4d851fcb580b89cf448b",
}
OFFICIAL_USER_AGENT = "AlibabaCloud-Agent-Skills/alibabacloud-resourcecenter-search"
# SearchResources uses ResourceCenter/2022-12-01.  The official CLI plugin's
# public endpoint map names this host; keeping it fixed prevents an Agent from
# choosing an arbitrary endpoint and avoids a missing regional registry entry.
OFFICIAL_RESOURCE_CENTER_ENDPOINT = "resourcecenter.aliyuncs.com"
OFFICIAL_RESOURCE_CENTER_PLUGIN_VERSION = "0.7.0"
OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256 = "5a18d50b91c10a8db1c603aa28b86b69bb1a6614921ef06198a186862261a145"
OFFICIAL_ALIYUN_CLI_VERSION = "3.4.11"
OFFICIAL_ALIYUN_CLI_SHA256 = "7a418ea428dcbfeaab2af8760938aeda8d2f16bd77b586cbe4c75b07034df8fb"
SOURCE_LOCK_PATH = "governance/alibabacloud-resourcecenter-search-source-lock.json"
EXTERNAL_SKILL_PATH_ENV = "TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH"
EXTERNAL_SKILL_PATH_REFERENCE = "external://titmas/skills/alibabacloud-resourcecenter-search"
ALLOWED_OPERATION = "resourcecenter.search-resources"
PERMISSION_DENIED_CODES = {
    "AccessDenied",
    "Forbidden",
    "NoPermission",
    "NoPermission.AccountScope",
    "NoPermission.ResourceDirectory.MemberAccount",
    "Unauthorized",
}
WRITE_OPERATION_MARKERS = ("create", "delete", "disable", "enable", "modify", "set", "update", "write")
MINIMUM_CLI_VERSION = (3, 3, 3)
EXPECTED_READ_ONLY_POLICY_ACTIONS = {
    "resourcecenter:ExecuteMultiAccountSQLQuery",
    "resourcecenter:ExecuteSQLQuery",
    "resourcecenter:Get*",
    "resourcecenter:List*",
    "resourcecenter:Search*",
    "tag:ListTag*",
}


@dataclass(frozen=True)
class CloudCredentialContext:
    """Non-secret references for one externally configured CLI profile."""

    profile_name: str
    permission_identity: str
    permission_role_ref: str
    permission_policy_ref: str
    read_only_policy_verified: bool

    @property
    def credential_ref(self) -> str:
        return _opaque_ref(f"profile:{self.profile_name}")

    @property
    def permission_identity_ref(self) -> str:
        if re.fullmatch(r"sha256:[a-f0-9]{64}", self.permission_identity):
            return self.permission_identity
        return _opaque_ref(f"identity:{self.permission_identity}")

    @property
    def permission_policy_opaque_ref(self) -> str:
        if re.fullmatch(r"sha256:[a-f0-9]{64}", self.permission_policy_ref):
            return self.permission_policy_ref
        return _opaque_ref(f"policy:{self.permission_policy_ref}")

    @property
    def permission_role_opaque_ref(self) -> str:
        if re.fullmatch(r"sha256:[a-f0-9]{64}", self.permission_role_ref):
            return self.permission_role_ref
        return _opaque_ref(f"role:{self.permission_role_ref.lower()}")


def credential_from_policy_observation(profile_name: str, observation_path: str | Path) -> tuple[CloudCredentialContext, dict[str, Any]]:
    """Build a credential reference only from a schema-valid provider readback."""

    path = Path(observation_path).resolve()
    observation = json.loads(path.read_text(encoding="utf-8"))
    validate_contract("alibabacloud_ram_policy_observation", observation)
    policy = observation["policy"]
    attachment = observation["attachment"]
    identity = observation["identity"]
    expected_operations = {
        "ram.GetPolicy",
        "ram.GetPolicyVersion",
        "ram.ListPoliciesForRole",
        "sts.GetCallerIdentity",
    }
    observed_operations = [item["operation"] for item in observation["read_trace"]]
    if (
        set(policy["allow_actions"]) != EXPECTED_READ_ONLY_POLICY_ACTIONS
        or policy["write_operation_marker_count"] != 0
        or attachment["total_attachment_count"] != 1
        or attachment["system_policy_count"] != 1
        or attachment["custom_policy_count"] != 0
        or attachment["matching_attachment_count"] != 1
        or attachment["unexpected_attachment_count"] != 0
        or identity["type"] != "AssumedRoleUser"
        or identity["role_ref"] != attachment["role_ref"]
        or len(observed_operations) != len(expected_operations)
        or set(observed_operations) != expected_operations
        or any(item["exit_status"] != 0 for item in observation["read_trace"])
    ):
        raise ValueError("READ_ONLY_POLICY_OBSERVATION_INVALID")
    credential = CloudCredentialContext(
        profile_name=profile_name,
        permission_identity=identity["identity_ref"],
        permission_role_ref=identity["role_ref"],
        permission_policy_ref="sha256:" + sha256_file(path),
        read_only_policy_verified=True,
    )
    return credential, observation


@dataclass(frozen=True)
class CliExecution:
    status: str
    cli_version: str | None
    exit_status: int | None
    returned_resource_count: int | None
    next_token_present: bool | None
    resource_type_count: int | None
    region_count: int | None
    request_id_ref: str | None
    uncertainty: tuple[str, ...] = ()
    step_trace: list[dict[str, Any]] = field(default_factory=list)
    argv_template_sha256: str | None = None


class CloudQueryExecutor(Protocol):
    def execute(self, query: dict[str, Any], credential: CloudCredentialContext) -> CliExecution: ...


def _opaque_ref(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _null_invocation() -> dict[str, Any]:
    return {
        "invoked": False,
        "result_class": "NOT_INVOKED",
        "cli_version": None,
        "command": None,
        "user_agent": None,
        "exit_status": None,
        "returned_resource_count": None,
        "next_token_present": None,
        "resource_type_count": None,
        "region_count": None,
        "request_id_ref": None,
        "argv_template_sha256": None,
        "provider_http_attempts": "NOT_ASSESSED",
        "steps": [],
    }


def _permission_code(stdout: str, stderr: str) -> str | None:
    for candidate in (stdout, stderr):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            parsed = {}
        code = parsed.get("Code") or parsed.get("code")
        if isinstance(code, str) and (code in PERMISSION_DENIED_CODES or "permission" in code.lower()):
            return code
    combined = f"{stdout}\n{stderr}".lower()
    if any(marker.lower() in combined for marker in PERMISSION_DENIED_CODES):
        return "PERMISSION_DENIED_REDACTED"
    return None


def _parse_cli_version(output: str) -> tuple[str | None, tuple[int, int, int] | None]:
    match = re.search(r"(?<!\d)(\d+)\.(\d+)\.(\d+)(?!\d)", output)
    if match is None:
        return None, None
    parts = tuple(int(value) for value in match.groups())
    return ".".join(str(value) for value in parts), parts


def _resource_list(payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("Resources", "resources"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _role_ref_from_assumed_role_arn(arn: str) -> str | None:
    """Derive an opaque normalized role reference without retaining the ARN."""

    parts = arn.split("/")
    if len(parts) < 3 or not parts[-2]:
        return None
    return _opaque_ref(f"role:{parts[-2].lower()}")


class AliyunCliReadOnlyExecutor:
    """Execute the exact official read operation and return only aggregates."""

    def __init__(self, *, timeout_seconds: int = 60):
        self.timeout_seconds = timeout_seconds

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            argv,
            check=False,
            capture_output=True,
            text=True,
            timeout=self.timeout_seconds,
        )

    @staticmethod
    def _search_argv(binary: str, query: dict[str, Any], credential: CloudCredentialContext) -> list[str]:
        argv = [binary, "resourcecenter", "search-resources"]
        filters = []
        if "resource_type" in query["filters"]:
            filters.append({"Key": "ResourceType", "MatchType": "Equals", "Value": [query["filters"]["resource_type"]]})
        if "region_id" in query["filters"]:
            filters.append({"Key": "RegionId", "MatchType": "Equals", "Value": [query["filters"]["region_id"]]})
        if filters:
            argv.extend(["--filter", json.dumps(filters, separators=(",", ":"), ensure_ascii=False)])
        argv.extend(["--max-results", str(query["max_results"])])
        argv.append(f"--include-deleted-resources={'true' if query['include_deleted_resources'] else 'false'}")
        argv.extend(
            [
                "--endpoint",
                OFFICIAL_RESOURCE_CENTER_ENDPOINT,
                "--profile",
                credential.profile_name,
                "--user-agent",
                OFFICIAL_USER_AGENT,
            ]
        )
        return argv

    def execute(self, query: dict[str, Any], credential: CloudCredentialContext) -> CliExecution:
        trace: list[dict[str, Any]] = []
        binary = shutil.which("aliyun")
        if binary is None:
            return CliExecution(
                "NOT_ASSESSED",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                ("ALIYUN_CLI_NOT_INSTALLED",),
                trace,
            )

        binary_path = Path(binary).resolve()
        if not binary_path.is_file() or sha256_file(binary_path) != OFFICIAL_ALIYUN_CLI_SHA256:
            return CliExecution(
                "NOT_ASSESSED",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                ("ALIYUN_CLI_PIN_MISMATCH",),
                trace,
            )
        binary = str(binary_path)
        trace.append({"step_id": "VERIFY_PINNED_ALIYUN_CLI", "effect": "LOCAL_READ", "exit_status": 0})

        plugin = Path.home() / ".aliyun/plugins/aliyun-cli-resourcecenter/aliyun-cli-resourcecenter"
        if not plugin.is_file() or sha256_file(plugin) != OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256:
            return CliExecution(
                "NOT_ASSESSED",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                ("RESOURCE_CENTER_PLUGIN_PIN_MISMATCH",),
                trace,
            )
        trace.append(
            {
                "step_id": "VERIFY_PINNED_RESOURCECENTER_PLUGIN",
                "effect": "LOCAL_READ",
                "exit_status": 0,
            }
        )

        ai_mode_enabled = False
        version_text: str | None = None
        try:
            enabled = self._run([binary, "configure", "ai-mode", "enable"])
            trace.append({"step_id": "ENABLE_AI_MODE", "effect": "LOCAL_CONFIG_WRITE", "exit_status": enabled.returncode})
            if enabled.returncode != 0:
                return CliExecution("INVOCATION_FAILED", None, enabled.returncode, None, None, None, None, None, ("AI_MODE_ENABLE_FAILED",), trace)
            ai_mode_enabled = True
            set_agent = self._run([binary, "configure", "ai-mode", "set-user-agent", "--user-agent", OFFICIAL_USER_AGENT])
            trace.append({"step_id": "SET_FIXED_USER_AGENT", "effect": "LOCAL_CONFIG_WRITE", "exit_status": set_agent.returncode})
            if set_agent.returncode != 0:
                return CliExecution("INVOCATION_FAILED", None, set_agent.returncode, None, None, None, None, None, ("AI_MODE_USER_AGENT_FAILED",), trace)
            version_result = self._run([binary, "version"])
            trace.append({"step_id": "VERIFY_CLI_VERSION", "effect": "LOCAL_READ", "exit_status": version_result.returncode})
            version_text, version = _parse_cli_version(f"{version_result.stdout}\n{version_result.stderr}")
            if version_result.returncode != 0 or version is None or version < MINIMUM_CLI_VERSION or version_text != OFFICIAL_ALIYUN_CLI_VERSION:
                return CliExecution(
                    "NOT_ASSESSED", version_text, version_result.returncode, None, None, None, None, None, ("ALIYUN_CLI_VERSION_UNSUPPORTED",), trace
                )
            credential_check = self._run([binary, "configure", "list", "--profile", credential.profile_name])
            trace.append({"step_id": "VERIFY_PROFILE_CONFIGURATION", "effect": "LOCAL_READ", "exit_status": credential_check.returncode})
            if credential_check.returncode != 0:
                return CliExecution(
                    "NOT_ASSESSED",
                    version_text,
                    credential_check.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("CREDENTIAL_PROFILE_UNAVAILABLE",),
                    trace,
                )

            identity_result = self._run(
                [
                    binary,
                    "sts",
                    "GetCallerIdentity",
                    "--profile",
                    credential.profile_name,
                    "--user-agent",
                    OFFICIAL_USER_AGENT,
                ]
            )
            trace.append({"step_id": "VERIFY_LIVE_CALLER_IDENTITY", "effect": "CLOUD_READ", "exit_status": identity_result.returncode})
            denied = _permission_code(identity_result.stdout, identity_result.stderr)
            if denied is not None:
                return CliExecution(
                    "NOT_ASSESSED_PERMISSION_DENIED",
                    version_text,
                    identity_result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RAM_IDENTITY_PERMISSION_DENIED",),
                    trace,
                )
            try:
                identity_payload = json.loads(identity_result.stdout)
            except json.JSONDecodeError:
                identity_payload = {}
            arn = identity_payload.get("Arn") if isinstance(identity_payload, dict) else None
            identity_type = identity_payload.get("IdentityType") if isinstance(identity_payload, dict) else None
            live_identity_ref = _opaque_ref(f"identity:{arn}") if isinstance(arn, str) and arn else None
            live_role_ref = _role_ref_from_assumed_role_arn(arn) if isinstance(arn, str) else None
            if (
                identity_result.returncode != 0
                or identity_type != "AssumedRoleUser"
                or live_identity_ref != credential.permission_identity_ref
                or live_role_ref != credential.permission_role_opaque_ref
            ):
                return CliExecution(
                    "NOT_ASSESSED",
                    version_text,
                    identity_result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("LIVE_READ_ONLY_IDENTITY_BINDING_MISMATCH",),
                    trace,
                )

            if sha256_file(binary_path) != OFFICIAL_ALIYUN_CLI_SHA256:
                return CliExecution(
                    "NOT_ASSESSED",
                    version_text,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("ALIYUN_CLI_PIN_CHANGED_DURING_INVOCATION",),
                    trace,
                )
            if not plugin.is_file() or sha256_file(plugin) != OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256:
                return CliExecution(
                    "NOT_ASSESSED",
                    version_text,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RESOURCE_CENTER_PLUGIN_PIN_CHANGED_BEFORE_QUERY",),
                    trace,
                )
            trace.append(
                {
                    "step_id": "REVERIFY_PINNED_RESOURCECENTER_PLUGIN_BEFORE_QUERY",
                    "effect": "LOCAL_READ",
                    "exit_status": 0,
                }
            )

            search_argv = self._search_argv(binary, query, credential)
            sanitized_argv = ["aliyun" if item == binary else "<runtime-profile>" if item == credential.profile_name else item for item in search_argv]
            argv_template_sha256 = sha256_json(sanitized_argv)
            result = self._run(search_argv)
            trace.append({"step_id": "RESOURCECENTER_SEARCH_RESOURCES", "effect": "CLOUD_READ", "exit_status": result.returncode})
            if not plugin.is_file() or sha256_file(plugin) != OFFICIAL_RESOURCE_CENTER_PLUGIN_SHA256:
                return CliExecution(
                    "INVOCATION_FAILED",
                    version_text,
                    result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RESOURCE_CENTER_PLUGIN_PIN_CHANGED_DURING_INVOCATION",),
                    trace,
                    argv_template_sha256,
                )
            trace.append(
                {
                    "step_id": "REVERIFY_PINNED_RESOURCECENTER_PLUGIN_AFTER_QUERY",
                    "effect": "LOCAL_READ",
                    "exit_status": 0,
                }
            )
            denied = _permission_code(result.stdout, result.stderr)
            if denied is not None:
                return CliExecution(
                    "NOT_ASSESSED_PERMISSION_DENIED",
                    version_text,
                    result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RAM_PERMISSION_DENIED",),
                    trace,
                    argv_template_sha256,
                )
            if result.returncode != 0:
                return CliExecution(
                    "INVOCATION_FAILED",
                    version_text,
                    result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RESOURCE_SEARCH_FAILED_REDACTED",),
                    trace,
                    argv_template_sha256,
                )
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                return CliExecution(
                    "INVOCATION_FAILED",
                    version_text,
                    result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RESOURCE_SEARCH_RESPONSE_NOT_JSON",),
                    trace,
                    argv_template_sha256,
                )
            if not isinstance(payload, dict):
                return CliExecution(
                    "INVOCATION_FAILED",
                    version_text,
                    result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RESOURCE_SEARCH_RESPONSE_INVALID",),
                    trace,
                    argv_template_sha256,
                )
            if not any(key in payload for key in ("Resources", "resources")):
                return CliExecution(
                    "INVOCATION_FAILED",
                    version_text,
                    result.returncode,
                    None,
                    None,
                    None,
                    None,
                    None,
                    ("RESOURCE_SEARCH_RESPONSE_MISSING_RESOURCES",),
                    trace,
                    argv_template_sha256,
                )
            resources = _resource_list(payload)
            resource_types = {item.get("ResourceType") or item.get("resourceType") for item in resources}
            regions = {item.get("RegionId") or item.get("regionId") for item in resources}
            request_id = payload.get("RequestId") or payload.get("requestId")
            next_token = payload.get("NextToken") or payload.get("nextToken")
            uncertainty: tuple[str, ...] = ()
            if next_token:
                uncertainty += ("SINGLE_PAGE_OBSERVATION_NOT_COMPLETE_INVENTORY",)
            if not resources:
                uncertainty += ("ZERO_RESULTS_ONLY_MEAN_NO_RESOURCES_VISIBLE_TO_THIS_BOUNDED_IDENTITY",)
            return CliExecution(
                "CLOUD_CONTEXT_AVAILABLE" if resources else "NOT_ASSESSED_NO_VISIBLE_RESOURCE",
                version_text,
                result.returncode,
                len(resources),
                bool(next_token),
                len(resource_types - {None}),
                len(regions - {None}),
                _opaque_ref(f"request:{request_id}") if request_id else None,
                uncertainty,
                trace,
                argv_template_sha256,
            )
        except subprocess.TimeoutExpired:
            return CliExecution("INVOCATION_FAILED", version_text, None, None, None, None, None, None, ("CLI_TIMEOUT",), trace)
        finally:
            if ai_mode_enabled:
                disabled = self._run([binary, "configure", "ai-mode", "disable"])
                trace.append({"step_id": "DISABLE_AI_MODE", "effect": "LOCAL_CONFIG_WRITE", "exit_status": disabled.returncode})
                if disabled.returncode != 0:
                    raise RuntimeError("AI_MODE_DISABLE_FAILED")


class CloudContextInspector:
    """Verify the Skill and produce a decision-free sanitized preflight result."""

    def __init__(
        self,
        root: str | Path,
        executor: CloudQueryExecutor | None = None,
        *,
        external_skill_path: str | Path | None = None,
    ):
        self.root = Path(root).resolve()
        self.executor = executor or AliyunCliReadOnlyExecutor()
        configured = external_skill_path or os.environ.get(EXTERNAL_SKILL_PATH_ENV)
        self.external_skill_path = Path(configured).expanduser().resolve() if configured else None

    def _resolve_external_skill_path(self, lock: dict[str, Any]) -> Path:
        installation = lock.get("installation", {})
        if installation.get("path_reference") != EXTERNAL_SKILL_PATH_REFERENCE:
            raise ValueError("SKILL_EXTERNAL_PATH_REFERENCE_MISMATCH")
        if installation.get("path_configuration_env") != EXTERNAL_SKILL_PATH_ENV:
            raise ValueError("SKILL_EXTERNAL_PATH_CONFIGURATION_MISMATCH")
        if self.external_skill_path is None or not self.external_skill_path.is_dir():
            raise ValueError("SKILL_EXTERNAL_PATH_UNAVAILABLE")
        try:
            self.external_skill_path.relative_to(self.root)
        except ValueError:
            return self.external_skill_path
        raise ValueError("SKILL_PATH_MUST_BE_EXTERNAL_TO_REPOSITORY")

    def verify_skill_source(self) -> dict[str, Any]:
        lock_path = self.root / SOURCE_LOCK_PATH
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        if (
            lock["skill"]["revision"] != OFFICIAL_SKILL_REVISION
            or lock["skill"]["git_tree"] != OFFICIAL_SKILL_GIT_TREE
            or lock["skill"]["name"] != OFFICIAL_SKILL_NAME
        ):
            raise ValueError("SKILL_DIGEST_MISMATCH")
        skill_root = self._resolve_external_skill_path(lock)
        expected = {item["path"]: item["sha256"] for item in lock["files"]}
        if expected != OFFICIAL_SKILL_FILE_HASHES:
            raise ValueError("SKILL_DIGEST_MISMATCH")
        observed_paths = {path.relative_to(skill_root).as_posix() for path in skill_root.rglob("*") if path.is_file()}
        if observed_paths != set(expected):
            raise ValueError("SKILL_DIGEST_MISMATCH")
        for relative, digest in expected.items():
            if sha256_file(skill_root / relative) != digest:
                raise ValueError("SKILL_DIGEST_MISMATCH")
        return {
            "name": OFFICIAL_SKILL_NAME,
            "repository": OFFICIAL_SKILL_REPOSITORY,
            "revision": OFFICIAL_SKILL_REVISION,
            "source_lock_sha256": sha256_file(lock_path),
            "external_path_reference": EXTERNAL_SKILL_PATH_REFERENCE,
            "discovered": True,
            "loaded": True,
            "load_scope": "EXTERNAL_SKILL_SOURCE_VERIFICATION",
            "native_agentteams_loaded": False,
            "runtime_load_result": "SOURCE_VERIFIED_NOT_NATIVE_LOADED",
            "invocation_scope": "SKILL_BOUND_ADAPTER",
        }

    def _interpret_read_only_invocation_boundary(self) -> None:
        """Interpret the verified upstream instructions without returning their bytes."""

        lock = json.loads((self.root / SOURCE_LOCK_PATH).read_text(encoding="utf-8"))
        skill_root = self._resolve_external_skill_path(lock)
        skill_text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
        related_apis = (skill_root / "references/related-apis.md").read_text(encoding="utf-8")
        required_markers = (
            "AliyunResourceCenterReadOnlyAccess",
            "`search-resources`",
            "aliyun configure ai-mode enable",
            "aliyun configure ai-mode disable",
        )
        excluded_scope_markers = (
            "`enable-resource-center`",
            "`disable-resource-center`",
            "`enable-multi-account-resource-center`",
            "AliyunResourceCenterFullAccess",
        )
        if not all(marker in skill_text for marker in required_markers):
            raise ValueError("SKILL_READ_ONLY_BOUNDARY_UNAVAILABLE")
        if not all(marker in skill_text or marker.strip("`") in related_apis for marker in excluded_scope_markers):
            raise ValueError("SKILL_EXCLUDED_SCOPE_UNAVAILABLE")
        if "### search-resources" not in related_apis:
            raise ValueError("SKILL_READ_ONLY_OPERATION_UNAVAILABLE")

    def load_external_skill(self, *, native_agentteams_runtime: bool = False) -> dict[str, str]:
        """Return the minimal source-bound load receipt exposed to a native Worker."""

        verified = self.verify_skill_source()
        self._interpret_read_only_invocation_boundary()
        return {
            "skill_name": verified["name"],
            "external_path_reference": verified["external_path_reference"],
            "revision": verified["revision"],
            "digest": verified["source_lock_sha256"],
            "runtime_load_result": (
                "LOADED_READ_ONLY_RESOURCECENTER_SEARCH_ONLY" if native_agentteams_runtime else "SOURCE_VERIFIED_THROUGH_AUTHENTICATED_MCP"
            ),
        }

    @staticmethod
    def _query_summary(query: dict[str, Any]) -> dict[str, Any]:
        mapping = {"resource_type": "ResourceType", "region_id": "RegionId"}
        raw_max = query.get("max_results", 1)
        max_results = raw_max if isinstance(raw_max, int) and not isinstance(raw_max, bool) and 1 <= raw_max <= 100 else 1
        filters = query.get("filters", {}) if isinstance(query.get("filters", {}), dict) else {}
        confirmation_ref = query.get("confirmation_ref")
        return {
            "operation": ALLOWED_OPERATION if query.get("operation") == ALLOWED_OPERATION else "REJECTED",
            "max_results": max_results,
            "filter_keys": sorted(mapping[key] for key in filters if key in mapping),
            "include_deleted_resources": bool(query.get("include_deleted_resources", False)),
            "confirmation_ref": (
                confirmation_ref if isinstance(confirmation_ref, str) and re.fullmatch(r"confirmation:[a-f0-9]{64}", confirmation_ref) else "NOT_CONFIRMED"
            ),
        }

    def _base_result(
        self,
        request_id: str,
        query: dict[str, Any],
        *,
        status: str,
        skill: dict[str, Any],
        credential: CloudCredentialContext | None,
        invocation: dict[str, Any],
        checks: list[dict[str, Any]],
        uncertainty: list[str],
        observed_at: datetime,
    ) -> dict[str, Any]:
        material = {"request_id": request_id, "query": query, "observed_at": format_datetime(observed_at)}
        result = {
            "schema_version": "0.1.0",
            "preflight_id": f"cloud-preflight-{sha256_json(material)[:32]}",
            "request_id": request_id,
            "status": status,
            "observed_at": format_datetime(observed_at),
            "skill": skill,
            "query": self._query_summary(query),
            "credential": {
                "credential_ref": credential.credential_ref if credential else None,
                "permission_identity_ref": credential.permission_identity_ref if credential else None,
                "permission_role_ref": credential.permission_role_opaque_ref if credential else None,
                "permission_policy_ref": credential.permission_policy_opaque_ref if credential else None,
                "read_only_policy_verified": "PASS" if credential and credential.read_only_policy_verified else "NOT_ASSESSED",
            },
            "invocation": invocation,
            "checks": checks,
            "resourcecenter_write_api_calls": 0,
            "uncertainty": uncertainty,
        }
        validate_contract("cloud_context_result", result)
        return result

    def inspect(
        self,
        request_id: str,
        query: dict[str, Any],
        credential: CloudCredentialContext | None,
        *,
        observed_at: datetime | None = None,
        native_agentteams_loaded: bool = False,
    ) -> dict[str, Any]:
        checked_at = observed_at or utc_now()
        try:
            skill = {**self.verify_skill_source(), "runtime_invoked": False}
        except (OSError, ValueError, KeyError, json.JSONDecodeError):
            result = self._base_result(
                request_id,
                query,
                status="SKILL_LOAD_REJECTED",
                skill={
                    "name": OFFICIAL_SKILL_NAME,
                    "repository": OFFICIAL_SKILL_REPOSITORY,
                    "revision": OFFICIAL_SKILL_REVISION,
                    "source_lock_sha256": "0" * 64,
                    "external_path_reference": EXTERNAL_SKILL_PATH_REFERENCE,
                    "discovered": False,
                    "loaded": False,
                    "load_scope": "EXTERNAL_SKILL_SOURCE_VERIFICATION",
                    "native_agentteams_loaded": False,
                    "runtime_load_result": "LOAD_REJECTED",
                    "runtime_invoked": False,
                    "invocation_scope": "SKILL_BOUND_ADAPTER",
                },
                credential=credential,
                invocation=_null_invocation(),
                checks=[{"check_id": "SKILL_SOURCE_HASH", "passed": False}],
                uncertainty=["OFFICIAL_SKILL_SOURCE_OR_HASH_NOT_VERIFIED"],
                observed_at=checked_at,
            )
            return result

        try:
            validate_contract("cloud_context_query", query)
        except Exception:
            return self._base_result(
                request_id,
                query,
                status="BLOCKED_BY_SKILL_BOUNDARY",
                skill=skill,
                credential=credential,
                invocation=_null_invocation(),
                checks=[{"check_id": "TYPED_QUERY_SCHEMA", "passed": False}],
                uncertainty=["QUERY_REJECTED_BEFORE_PROCESS_OR_NETWORK"],
                observed_at=checked_at,
            )

        operation = query["operation"]
        boundary_ok = operation == ALLOWED_OPERATION and not any(marker in operation.lower() for marker in WRITE_OPERATION_MARKERS)
        if not boundary_ok or query["include_deleted_resources"]:
            return self._base_result(
                request_id,
                query,
                status="BLOCKED_BY_SKILL_BOUNDARY",
                skill=skill,
                credential=credential,
                invocation=_null_invocation(),
                checks=[{"check_id": "READ_ONLY_OPERATION_ALLOWLIST", "passed": False}],
                uncertainty=["QUERY_REJECTED_BEFORE_PROCESS_OR_NETWORK"],
                observed_at=checked_at,
            )
        if not query["parameters_confirmed_by_user"]:
            return self._base_result(
                request_id,
                query,
                status="NOT_ASSESSED",
                skill=skill,
                credential=credential,
                invocation=_null_invocation(),
                checks=[{"check_id": "USER_PARAMETER_CONFIRMATION", "passed": False}],
                uncertainty=["QUERY_PARAMETERS_NOT_CONFIRMED"],
                observed_at=checked_at,
            )
        if credential is None:
            return self._base_result(
                request_id,
                query,
                status="NOT_ASSESSED",
                skill=skill,
                credential=None,
                invocation=_null_invocation(),
                checks=[{"check_id": "CREDENTIAL_REFERENCE_PRESENT", "passed": False}],
                uncertainty=["READ_ONLY_CREDENTIAL_NOT_AVAILABLE"],
                observed_at=checked_at,
            )

        skill["native_agentteams_loaded"] = native_agentteams_loaded
        skill["runtime_load_result"] = "LOADED_READ_ONLY_RESOURCECENTER_SEARCH_ONLY" if native_agentteams_loaded else "SOURCE_VERIFIED_NOT_NATIVE_LOADED"
        execution = self.executor.execute(query, credential)
        skill["runtime_invoked"] = execution.status in {
            "CLOUD_CONTEXT_AVAILABLE",
            "NOT_ASSESSED_NO_VISIBLE_RESOURCE",
            "NOT_ASSESSED_PERMISSION_DENIED",
            "INVOCATION_FAILED",
        }
        skill["invocation_scope"] = "SKILL_BOUND_ADAPTER"
        filter_placeholder = " --filter <confirmed-filter-json>" if query["filters"] else ""
        invocation = {
            "invoked": skill["runtime_invoked"],
            "result_class": (
                "EMPTY_RESULT"
                if execution.status == "NOT_ASSESSED_NO_VISIBLE_RESOURCE"
                else "NONEMPTY_RESULT"
                if execution.status == "CLOUD_CONTEXT_AVAILABLE"
                else "FAILED"
            ),
            "cli_version": execution.cli_version,
            "command": (
                "aliyun resourcecenter search-resources"
                f"{filter_placeholder} --max-results {query['max_results']} --include-deleted-resources=false"
                f" --endpoint {OFFICIAL_RESOURCE_CENTER_ENDPOINT}"
                " --profile <runtime-profile>"
                f" --user-agent {OFFICIAL_USER_AGENT}"
            ),
            "user_agent": OFFICIAL_USER_AGENT,
            "exit_status": execution.exit_status,
            "returned_resource_count": execution.returned_resource_count,
            "next_token_present": execution.next_token_present,
            "resource_type_count": execution.resource_type_count,
            "region_count": execution.region_count,
            "request_id_ref": execution.request_id_ref,
            "argv_template_sha256": execution.argv_template_sha256,
            "provider_http_attempts": "NOT_ASSESSED",
            "steps": execution.step_trace,
        }
        sanitized = execution.status in {"CLOUD_CONTEXT_AVAILABLE", "NOT_ASSESSED_NO_VISIBLE_RESOURCE"}
        checks = [
            {"check_id": "SKILL_SOURCE_HASH", "passed": True},
            {"check_id": "READ_ONLY_OPERATION_ALLOWLIST", "passed": True},
            {"check_id": "USER_PARAMETER_CONFIRMATION", "passed": True},
            {"check_id": "CREDENTIAL_REFERENCE_PRESENT", "passed": True},
            {"check_id": "READ_ONLY_POLICY_REFERENCE", "passed": credential.read_only_policy_verified},
            {
                "check_id": "LIVE_READ_ONLY_IDENTITY_BINDING",
                "passed": any(item["step_id"] == "VERIFY_LIVE_CALLER_IDENTITY" and item["exit_status"] == 0 for item in execution.step_trace)
                and not any(item == "LIVE_READ_ONLY_IDENTITY_BINDING_MISMATCH" for item in execution.uncertainty),
            },
            {"check_id": "CLI_EXIT_STATUS_ZERO", "passed": execution.exit_status == 0},
            {"check_id": "PAGINATION_COMPLETE", "passed": execution.next_token_present is False},
            {
                "check_id": "NONEMPTY_VISIBLE_RESULT",
                "passed": isinstance(execution.returned_resource_count, int) and execution.returned_resource_count > 0,
            },
            {"check_id": "SANITIZED_OUTPUT_ONLY", "passed": sanitized},
        ]
        return self._base_result(
            request_id,
            query,
            status=execution.status,
            skill=skill,
            credential=credential,
            invocation=invocation,
            checks=checks,
            uncertainty=list(execution.uncertainty),
            observed_at=checked_at,
        )


def is_semantically_usable_cloud_context(result: dict[str, Any]) -> bool:
    """Only this condition allows the receipt to satisfy CLOUD_CONTEXT evidence."""

    validate_contract("cloud_context_result", result)
    required = {
        "SKILL_SOURCE_HASH",
        "READ_ONLY_OPERATION_ALLOWLIST",
        "USER_PARAMETER_CONFIRMATION",
        "CREDENTIAL_REFERENCE_PRESENT",
        "READ_ONLY_POLICY_REFERENCE",
        "LIVE_READ_ONLY_IDENTITY_BINDING",
        "CLI_EXIT_STATUS_ZERO",
        "PAGINATION_COMPLETE",
        "NONEMPTY_VISIBLE_RESULT",
        "SANITIZED_OUTPUT_ONLY",
    }
    checks = {item["check_id"]: item["passed"] for item in result["checks"]}
    return (
        result["status"] == "CLOUD_CONTEXT_AVAILABLE"
        and result["skill"]["loaded"]
        and result["skill"]["runtime_invoked"]
        and result["invocation"]["invoked"]
        and result["invocation"]["exit_status"] == 0
        and result["invocation"]["next_token_present"] is False
        and result["resourcecenter_write_api_calls"] == 0
        and all(checks.get(item) is True for item in required)
    )
