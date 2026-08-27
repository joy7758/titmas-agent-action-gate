"""Bound one pull-request check to tests, evidence, policy, and approval.

This module is an adapter around the existing deterministic ``ActionGate``.  It
does not create a second authorization authority: all passing and non-passing
public states are projections of an ``ALLOW``, ``BLOCK``, or
``REQUIRE_APPROVAL`` decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO
from urllib.parse import urlsplit

import yaml

from .approval import ApprovalAuthority
from .canonical import (
    ExclusiveOutput,
    UnsafePathError,
    _open_directory_no_follow,
    canonical_json_bytes,
    format_datetime,
    request_binding,
    sha256_json,
    utc_now,
)
from .contracts import validate_action_request, validate_contract
from .errors import ActionGateError
from .evidence import AGENT_EVIDENCE_VERSION, AGENT_EVIDENCE_WHEEL_SHA256, AgentEvidenceAdapter
from .gate import ActionGate
from .policy import PolicyEngine

PUBLIC_EXIT_CODES = {
    "PASS": 0,
    "FAIL": 1,
    "INCOMPLETE": 2,
    "REVIEW_REQUIRED": 3,
}
DEFAULT_OUTPUT_DIRECTORY = Path("artifacts/titmas")
TEST_TIMEOUT_SECONDS = 900
MAX_TOTAL_TEST_OUTPUT_BYTES = 1024 * 1024
# Backward-compatible alias for callers that imported the earlier name.  The
# limit is now one aggregate server-owned budget shared by both output streams.
TEST_OUTPUT_LIMIT_BYTES = MAX_TOTAL_TEST_OUTPUT_BYTES
TEST_ENVIRONMENT_POLICY_VERSION = "minimal-v1"
_SHA_PATTERN = re.compile(r"^[a-f0-9]{40}$")
_UNAVAILABLE_APPROVAL_KEY = b"unavailable-approval-verifier-key"
_TEST_ENVIRONMENT_ALLOWLIST = ("PATH", "LANG", "LC_ALL")


@dataclass(frozen=True)
class PullRequestContext:
    repository: str
    pull_request: int | None
    head_sha: str
    execution_identity: str


@dataclass(frozen=True)
class FrozenJsonInput:
    role: str
    path: Path
    reference: str
    raw_bytes: bytes | None
    canonical_bytes: bytes | None
    sha256: str | None
    canonical_sha256: str | None
    device: int | None
    inode: int | None
    missing: bool
    allowed_root: Path | None
    ancestor_identities: tuple[tuple[str, int, int], ...]

    def payload(self) -> dict[str, Any]:
        if self.canonical_bytes is None:
            return {}
        value = json.loads(self.canonical_bytes)
        if not isinstance(value, dict):
            raise ActionGateError("JSON_ROOT_NOT_OBJECT", f"{self.role} must be a JSON object.")
        return value


@dataclass(frozen=True)
class GitSnapshot:
    available: bool = False
    head_sha: str | None = None
    head_tree_sha: str | None = None
    index_tree_sha: str | None = None
    symbolic_head: str | None = None
    repository_identity_matches: bool | None = None
    tracked_index_clean: bool = False
    tracked_worktree_clean: bool = False
    submodules_clean: bool = False
    unexpected_untracked_count: int = 0
    local_config_sha256: str | None = None
    effective_config_sha256: str | None = None
    config_source_categories: tuple[str, ...] = ()
    index_sha256: str | None = None
    worktree_diff_sha256: str | None = None
    status_sha256: str | None = None
    state_sha256: str | None = None
    credential_risks: tuple[str, ...] = ()
    submodule_count: int = 0
    submodule_paths: tuple[str, ...] = ()
    submodule_config_sha256: str | None = None
    submodule_state_sha256: str | None = None
    submodule_credential_risks: tuple[str, ...] = ()
    submodule_config_source_categories: tuple[str, ...] = ()


@dataclass(frozen=True)
class _EffectiveGitConfig:
    sha256: str
    source_categories: tuple[str, ...]
    risk_categories: tuple[str, ...]


@dataclass(frozen=True)
class FrozenActionConfiguration:
    path: Path | None
    reference: str | None
    sha256: str | None
    device: int | None
    inode: int | None
    allowed_root: Path | None
    ancestor_identities: tuple[tuple[str, int, int], ...]


@dataclass(frozen=True)
class FrozenExecutable:
    path: Path
    sha256: str
    device: int
    inode: int


@dataclass
class _StreamObservation:
    sha256: str
    observed_bytes: int
    limit_exceeded: bool


class _SharedOutputBudget:
    """Atomically allocate one bounded capture budget across both pipes."""

    def __init__(self, limit: int):
        self.limit = limit
        self._observed_bytes = 0
        self._lock = threading.Lock()

    def claim(self, chunk: bytes) -> tuple[bytes, bool]:
        with self._lock:
            remaining = self.limit - self._observed_bytes
            accepted = chunk[: max(remaining, 0)]
            self._observed_bytes += len(accepted)
            exceeded = len(accepted) < len(chunk)
            return accepted, exceeded

    @property
    def observed_bytes(self) -> int:
        with self._lock:
            return self._observed_bytes


def _tool_version() -> str:
    try:
        return version("titmas-agent-action-gate")
    except PackageNotFoundError:
        return "0.2.0a0"


def _read_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("JSON_ROOT_NOT_OBJECT")
    return payload


def _bounded_path(path: str | Path, *, workspace: Path | None, enforce_workspace: bool) -> tuple[Path, Path | None]:
    raw_workspace = workspace.expanduser() if workspace is not None else None
    workspace_lexical = raw_workspace if raw_workspace is None or raw_workspace.is_absolute() else Path.cwd() / raw_workspace
    if workspace_lexical is not None:
        workspace_lexical = Path(os.path.abspath(workspace_lexical))
        if _path_has_symlink_component(workspace_lexical):
            raise ActionGateError("SYMLINK_ANCESTOR_NOT_ALLOWED", "The trusted workspace may not contain symbolic links.")
        try:
            root_observation = workspace_lexical.lstat()
        except OSError as exc:
            raise ActionGateError("INPUT_PATH_OUT_OF_SCOPE", "The trusted workspace is unavailable.") from exc
        if not stat.S_ISDIR(root_observation.st_mode):
            raise ActionGateError("PATH_COMPONENT_NOT_TRUSTED_DIRECTORY", "The trusted workspace must be a real directory.")
    root = workspace_lexical
    raw_candidate = Path(path).expanduser()
    if not str(raw_candidate) or any(part in {".", ".."} for part in raw_candidate.parts):
        raise ActionGateError("PATH_ESCAPES_REPOSITORY_ROOT", "Gate input paths may not contain dot traversal components.")
    candidate = raw_candidate if raw_candidate.is_absolute() else (workspace_lexical or Path.cwd()) / raw_candidate
    candidate = Path(os.path.abspath(candidate))
    if enforce_workspace:
        if root is None:
            raise ActionGateError("INPUT_PATH_OUT_OF_SCOPE", "A trusted workspace is required for GitHub input paths.")
        try:
            relative = candidate.relative_to(root)
        except ValueError as exc:
            raise ActionGateError("PATH_ESCAPES_REPOSITORY_ROOT", "Gate input path escapes the trusted workspace.") from exc
        candidate = root / relative
    if _path_has_symlink_component(candidate):
        raise ActionGateError("SYMLINK_ANCESTOR_NOT_ALLOWED", "Gate input paths may not contain symbolic links.")
    return candidate, root


def _read_regular_bytes(
    path: str | Path,
    *,
    workspace: Path | None,
    enforce_workspace: bool,
    allow_missing: bool,
) -> tuple[Path, bytes | None, os.stat_result | None, tuple[tuple[str, int, int], ...]]:
    candidate, _ = _bounded_path(path, workspace=workspace, enforce_workspace=enforce_workspace)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    parent_descriptor: int | None = None
    descriptor: int | None = None
    try:
        try:
            parent_descriptor, ancestor_identities = _open_directory_no_follow(candidate.parent, create=False)
            descriptor = os.open(candidate.name, flags, dir_fd=parent_descriptor)
        except FileNotFoundError:
            if allow_missing:
                return candidate, None, None, ()
            raise ActionGateError("INPUT_MISSING", "A required gate input is missing.") from None
        except UnsafePathError as exc:
            raise ActionGateError(exc.code, "A gate input path could not be opened without following links.") from exc
        except OSError as exc:
            raise ActionGateError("INPUT_NOT_READABLE", "A gate input could not be opened safely.") from exc
        try:
            observed = os.fstat(descriptor)
            if not stat.S_ISREG(observed.st_mode):
                raise ActionGateError("INPUT_NOT_REGULAR", "Gate inputs must be regular files.")
            chunks: list[bytes] = []
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return candidate, b"".join(chunks), observed, ancestor_identities
        except ActionGateError:
            raise
        except OSError as exc:
            raise ActionGateError("INPUT_NOT_READABLE", "A gate input could not be read safely.") from exc
        finally:
            if descriptor is not None:
                _close_owned_input_descriptor(descriptor)
    finally:
        if parent_descriptor is not None:
            _close_owned_input_descriptor(parent_descriptor)


def _close_owned_input_descriptor(descriptor: int) -> None:
    """Close one input-owned descriptor once, failing closed on uncertainty."""

    try:
        os.close(descriptor)
    except OSError as exc:
        raise ActionGateError(
            "INPUT_PATH_RESOURCE_CLEANUP_FAILED",
            "An input path resource could not be closed safely.",
        ) from exc


def _freeze_executable(name: str, environment: Mapping[str, str]) -> FrozenExecutable:
    resolved = shutil.which(name, path=environment.get("PATH"))
    if resolved is None:
        raise ActionGateError("TRUSTED_EXECUTABLE_UNAVAILABLE", f"The required {name} executable was not found.")
    resolved_path = Path(resolved).absolute()
    if _path_has_symlink_component(resolved_path):
        resolved_path = resolved_path.resolve(strict=True)
    candidate, raw_bytes, observed, _ = _read_regular_bytes(
        resolved_path,
        workspace=None,
        enforce_workspace=False,
        allow_missing=False,
    )
    if raw_bytes is None or observed is None or not os.access(candidate, os.X_OK):
        raise ActionGateError("TRUSTED_EXECUTABLE_INVALID", f"The required {name} executable is not a regular executable file.")
    return FrozenExecutable(
        path=candidate,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        device=observed.st_dev,
        inode=observed.st_ino,
    )


def _executable_unchanged(frozen: FrozenExecutable) -> bool:
    try:
        _, raw_bytes, observed, _ = _read_regular_bytes(
            frozen.path,
            workspace=None,
            enforce_workspace=False,
            allow_missing=False,
        )
    except ActionGateError:
        return False
    return bool(
        raw_bytes is not None
        and observed is not None
        and (observed.st_dev, observed.st_ino) == (frozen.device, frozen.inode)
        and hashlib.sha256(raw_bytes).hexdigest() == frozen.sha256
    )


def _freeze_json_input(
    role: str,
    path: str | Path,
    *,
    workspace: Path | None,
    enforce_workspace: bool,
    allow_missing: bool = False,
) -> FrozenJsonInput:
    candidate, raw_bytes, observed, ancestor_identities = _read_regular_bytes(
        path,
        workspace=workspace,
        enforce_workspace=enforce_workspace,
        allow_missing=allow_missing,
    )
    if raw_bytes is None:
        return FrozenJsonInput(
            role,
            candidate,
            candidate.name,
            None,
            None,
            None,
            None,
            None,
            None,
            True,
            Path(os.path.abspath(workspace)) if workspace else None,
            ancestor_identities,
        )
    try:
        payload = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ActionGateError("INPUT_INVALID_JSON", f"{role} is not valid UTF-8 JSON.") from exc
    if not isinstance(payload, dict):
        raise ActionGateError("JSON_ROOT_NOT_OBJECT", f"{role} must be a JSON object.")
    canonical = canonical_json_bytes(payload)
    return FrozenJsonInput(
        role=role,
        path=candidate,
        reference=candidate.name,
        raw_bytes=raw_bytes,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        canonical_sha256=hashlib.sha256(canonical).hexdigest(),
        device=observed.st_dev if observed else None,
        inode=observed.st_ino if observed else None,
        missing=False,
        allowed_root=Path(os.path.abspath(workspace)) if enforce_workspace and workspace else None,
        ancestor_identities=ancestor_identities,
    )


def _freeze_action_configuration(
    path: str | Path | None,
    *,
    trusted_root: str | Path | None = None,
    require_trusted_root: bool = False,
) -> FrozenActionConfiguration:
    if path is None:
        return FrozenActionConfiguration(None, None, None, None, None, None, ())
    root: Path | None = None
    if trusted_root is not None:
        raw_root = Path(trusted_root).expanduser()
        if not str(raw_root) or any(part in {".", ".."} for part in raw_root.parts):
            raise ActionGateError("PATH_ESCAPES_REPOSITORY_ROOT", "The Action installation root may not contain dot traversal components.")
        root_candidate = Path(os.path.abspath(raw_root))
        if _path_has_symlink_component(root_candidate):
            raise ActionGateError("SYMLINK_ANCESTOR_NOT_ALLOWED", "The Action installation root may not contain symbolic links.")
        try:
            root_observation = root_candidate.lstat()
        except OSError as exc:
            raise ActionGateError("ACTION_CONFIGURATION_ROOT_INVALID", "The Action installation root is unavailable.") from exc
        if not stat.S_ISDIR(root_observation.st_mode):
            raise ActionGateError("ACTION_CONFIGURATION_ROOT_INVALID", "The Action installation root must be a directory.")
        root = root_candidate
    elif require_trusted_root:
        raise ActionGateError("ACTION_CONFIGURATION_ROOT_REQUIRED", "GitHub enforcement requires a trusted Action installation root.")
    raw_candidate_path = Path(path).expanduser()
    if not str(raw_candidate_path) or any(part in {".", ".."} for part in raw_candidate_path.parts):
        raise ActionGateError("PATH_ESCAPES_REPOSITORY_ROOT", "The Action configuration path may not contain dot traversal components.")
    candidate_path = Path(os.path.abspath(raw_candidate_path))
    if _path_has_symlink_component(candidate_path):
        raise ActionGateError("SYMLINK_ANCESTOR_NOT_ALLOWED", "The Action configuration path may not contain symbolic links.")
    if root is not None and candidate_path != root / "action.yml":
        raise ActionGateError("ACTION_CONFIGURATION_PATH_MISMATCH", "The Action configuration must be action.yml under the trusted installation root.")
    candidate, raw_bytes, observed, ancestor_identities = _read_regular_bytes(
        candidate_path,
        workspace=root,
        enforce_workspace=root is not None,
        allow_missing=False,
    )
    try:
        payload = yaml.safe_load(raw_bytes)
    except yaml.YAMLError as exc:
        raise ActionGateError("ACTION_CONFIGURATION_INVALID", "The Action configuration is not valid YAML.") from exc
    runs = payload.get("runs") if isinstance(payload, dict) else None
    steps = runs.get("steps") if isinstance(runs, dict) else None
    verify_step = next((step for step in steps or [] if isinstance(step, dict) and step.get("id") == "verify"), None)
    required_inputs = {"task", "evidence", "policy", "test-command", "execution-identity"}
    required_environment = {
        "TITMAS_CURRENT_REPOSITORY",
        "TITMAS_CURRENT_PULL_REQUEST",
        "TITMAS_CURRENT_HEAD_SHA",
        "TITMAS_CURRENT_EVENT_NAME",
        "TITMAS_WORKSPACE",
        "TITMAS_ACTION_CONFIG_PATH",
        "TITMAS_ACTION_ROOT",
    }
    verify_run = verify_step.get("run", "") if isinstance(verify_step, dict) else ""
    structurally_valid = bool(
        isinstance(payload, dict)
        and payload.get("name") == "TITMAS Evidence Gate"
        and isinstance(runs, dict)
        and runs.get("using") == "composite"
        and isinstance(payload.get("inputs"), dict)
        and required_inputs.issubset(payload["inputs"])
        and isinstance(verify_step, dict)
        and isinstance(verify_step.get("env"), dict)
        and required_environment.issubset(verify_step["env"])
        and all(flag in verify_run for flag in ("--task", "--evidence", "--policy", "--test-command", "--workspace", "--action-configuration", "--action-root"))
    )
    if not structurally_valid:
        raise ActionGateError("ACTION_CONFIGURATION_INVALID", "The Action configuration does not match the bounded composite Action.")
    return FrozenActionConfiguration(
        path=candidate,
        reference=candidate.name,
        sha256=hashlib.sha256(raw_bytes or b"").hexdigest(),
        device=observed.st_dev if observed else None,
        inode=observed.st_ino if observed else None,
        allowed_root=root,
        ancestor_identities=ancestor_identities,
    )


def _path_has_symlink_component(path: Path) -> bool:
    """Return true when any existing component redirects path resolution."""

    candidate = path.expanduser().absolute()
    current = Path(candidate.anchor)
    for part in candidate.parts[1:]:
        current = current / part
        try:
            observed = current.lstat()
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(observed.st_mode):
            return True
    return False


def _ancestor_identities_unchanged(identities: tuple[tuple[str, int, int], ...]) -> bool:
    for path_text, expected_device, expected_inode in identities:
        try:
            observed = Path(path_text).lstat()
        except OSError:
            return False
        if stat.S_ISLNK(observed.st_mode) or not stat.S_ISDIR(observed.st_mode) or (observed.st_dev, observed.st_ino) != (expected_device, expected_inode):
            return False
    return True


def _post_input_observation(frozen: FrozenJsonInput) -> dict[str, Any]:
    try:
        candidate, raw_bytes, observed, ancestor_identities = _read_regular_bytes(
            frozen.path,
            workspace=frozen.allowed_root,
            enforce_workspace=frozen.allowed_root is not None,
            allow_missing=True,
        )
    except ActionGateError as exc:
        return {"sha256": None, "identity_changed": True, "mutated": True, "error": exc.code}
    digest = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes is not None else None
    ancestors_changed = not _ancestor_identities_unchanged(frozen.ancestor_identities) or (
        raw_bytes is not None and ancestor_identities != frozen.ancestor_identities
    )
    identity_changed = bool(
        ancestors_changed
        or frozen.missing != (raw_bytes is None)
        or observed is not None
        and (observed.st_dev, observed.st_ino) != (frozen.device, frozen.inode)
    )
    return {
        "sha256": digest,
        "identity_changed": identity_changed,
        "mutated": identity_changed or digest != frozen.sha256,
        "reference": candidate.name,
    }


def _input_ancestor_check_id(role: str) -> str:
    return f"{role.upper()}_PATH_ANCESTOR_MUTATED_DURING_TEST"


def _post_action_configuration_observation(frozen: FrozenActionConfiguration) -> dict[str, Any]:
    if frozen.path is None:
        return {"sha256": None, "identity_changed": False, "mutated": False}
    try:
        _, raw_bytes, observed, ancestor_identities = _read_regular_bytes(
            frozen.path,
            workspace=frozen.allowed_root,
            enforce_workspace=frozen.allowed_root is not None,
            allow_missing=True,
        )
    except ActionGateError as exc:
        return {"sha256": None, "identity_changed": True, "mutated": True, "error": exc.code}
    digest = hashlib.sha256(raw_bytes).hexdigest() if raw_bytes is not None else None
    identity_changed = bool(
        not _ancestor_identities_unchanged(frozen.ancestor_identities)
        or ancestor_identities != frozen.ancestor_identities
        or observed is None
        or (observed.st_dev, observed.st_ino) != (frozen.device, frozen.inode)
    )
    return {"sha256": digest, "identity_changed": identity_changed, "mutated": identity_changed or digest != frozen.sha256}


def _pull_request_from_event(environment: Mapping[str, str]) -> int | None:
    event_path = environment.get("GITHUB_EVENT_PATH")
    if not event_path:
        return None
    try:
        payload = _read_json_object(Path(event_path))
        value = payload["pull_request"]["number"]
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def resolve_pull_request_context(
    *,
    repository: str | None = None,
    pull_request: int | None = None,
    head_sha: str | None = None,
    execution_identity: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> PullRequestContext:
    env = environment if environment is not None else os.environ
    raw_pull_request = pull_request
    if raw_pull_request is None:
        configured = env.get("TITMAS_CURRENT_PULL_REQUEST")
        raw_pull_request = int(configured) if configured and configured.isdecimal() else _pull_request_from_event(env)
    return PullRequestContext(
        repository=repository or env.get("TITMAS_CURRENT_REPOSITORY") or env.get("GITHUB_REPOSITORY", ""),
        pull_request=raw_pull_request,
        head_sha=head_sha or env.get("TITMAS_CURRENT_HEAD_SHA") or env.get("GITHUB_SHA", ""),
        execution_identity=execution_identity or env.get("TITMAS_EXECUTION_IDENTITY", ""),
    )


def _git_command(git_executable: FrozenExecutable, workspace: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            str(git_executable.path),
            "-C",
            str(workspace),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "submodule.recurse=false",
            "-c",
            "diff.ignoreSubmodules=none",
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=10,
        env={
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        },
    )


def _repository_slug(value: str) -> str | None:
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("git@github.com:"):
        path = candidate.split(":", 1)[1]
    else:
        parsed = urlsplit(candidate)
        if parsed.hostname != "github.com" or parsed.username or parsed.password:
            return None
        path = parsed.path.lstrip("/")
    return path.removesuffix(".git") or None


def _git_config_records(config_bytes: bytes) -> list[tuple[str, str, str, str]]:
    """Parse ``--show-scope --show-origin --null --list`` without values leaking."""

    fields = config_bytes.split(b"\0")
    if fields and fields[-1] == b"":
        fields.pop()
    if not fields or len(fields) % 3 != 0 or any(not field for field in fields):
        raise ActionGateError("GIT_CONFIG_PARSE_FAILED", "The effective Git configuration output was incomplete.")
    records: list[tuple[str, str, str, str]] = []
    for offset in range(0, len(fields), 3):
        try:
            scope = fields[offset].decode("utf-8", "strict")
            origin = fields[offset + 1].decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ActionGateError("GIT_CONFIG_PARSE_FAILED", "The effective Git configuration metadata was invalid.") from exc
        key_bytes, separator, value_bytes = fields[offset + 2].partition(b"\n")
        if not separator or not key_bytes:
            raise ActionGateError("GIT_CONFIG_PARSE_FAILED", "The effective Git configuration record was incomplete.")
        try:
            key = key_bytes.decode("utf-8", "strict").lower()
            value = value_bytes.decode("utf-8", "strict")
        except UnicodeDecodeError as exc:
            raise ActionGateError("GIT_CONFIG_PARSE_FAILED", "The effective Git configuration record was invalid.") from exc
        records.append((scope, origin, key, value))
    return records


def _git_config_source_category(scope: str, origin: str) -> str:
    if scope == "worktree":
        return "WORKTREE"
    if scope == "local":
        return "REPOSITORY"
    if origin.startswith("command line:"):
        return "COMMAND"
    return scope.upper() or "UNKNOWN"


def _git_credential_risks(config_bytes: bytes) -> tuple[str, ...]:
    risks: set[str] = set()
    for _scope, _origin, key, value in _git_config_records(config_bytes):
        if key.startswith("http.") and key.endswith(".extraheader"):
            risks.add("HTTP_EXTRAHEADER")
        elif key == "http.proxy" or key.startswith("http.") and key.endswith(".proxy"):
            risks.add("HTTP_PROXY_CONFIGURATION")
        elif key == "http.cookiefile" or key.startswith("http.") and key.endswith(".cookiefile"):
            risks.add("HTTP_COOKIE_FILE")
        elif (
            key in {"http.sslkey", "http.sslcert"}
            or key.startswith("http.")
            and key.rsplit(".", 1)[-1]
            in {
                "sslkey",
                "sslcert",
            }
        ):
            risks.add("HTTP_CLIENT_CREDENTIAL_FILE")
        elif key == "credential.helper" or key.startswith("credential."):
            risks.add("CREDENTIAL_CONFIGURATION")
        elif key in {"core.sshcommand", "core.askpass", "core.gitproxy"}:
            risks.add("SSH_COMMAND")
        elif key == "include.path" or key.startswith("includeif."):
            risks.add("CONFIG_INCLUDE")
        elif key.startswith("url.") and (key.endswith(".insteadof") or key.endswith(".pushinsteadof")):
            risks.add("URL_REWRITE")
        elif key.startswith("remote.") and (key.endswith(".url") or key.endswith(".pushurl")):
            parsed = urlsplit(value)
            if parsed.username or parsed.password:
                risks.add("AUTHENTICATED_REMOTE_URL")
        elif key.startswith("remote.") and key.endswith(".proxy"):
            risks.add("REMOTE_PROXY_COMMAND")
        elif key.startswith("filter.") and key.rsplit(".", 1)[-1] in {"clean", "smudge", "process"}:
            risks.add("GIT_FILTER_COMMAND")
        elif key == "diff.external" or key.startswith("diff.") and key.rsplit(".", 1)[-1] in {"command", "textconv"}:
            risks.add("GIT_DIFF_COMMAND")
    return tuple(sorted(risks))


def _untracked_paths(status_bytes: bytes) -> tuple[str, ...]:
    paths: list[str] = []
    for record in status_bytes.split(b"\0"):
        if record.startswith(b"?? "):
            paths.append(record[3:].decode("utf-8", "surrogateescape"))
    return tuple(paths)


def _capture_effective_git_config(
    git_executable: FrozenExecutable,
    repository: Path,
) -> _EffectiveGitConfig:
    """Hash all effective local/worktree/include config without retaining values."""

    config = _git_command(
        git_executable,
        repository,
        "config",
        "--includes",
        "--show-origin",
        "--show-scope",
        "--null",
        "--list",
    )
    extensions = _git_command(
        git_executable,
        repository,
        "config",
        "--local",
        "--bool",
        "--get",
        "extensions.worktreeConfig",
    )
    if config.returncode != 0:
        raise ActionGateError("GIT_CONFIG_AUDIT_UNAVAILABLE", "The effective Git configuration could not be read.")
    if extensions.returncode == 1 and not extensions.stdout.strip():
        worktree_config_enabled = False
    elif extensions.returncode == 0:
        extension_value = extensions.stdout.strip()
        if extension_value == b"true":
            worktree_config_enabled = True
        elif extension_value == b"false":
            worktree_config_enabled = False
        else:
            raise ActionGateError(
                "WORKTREE_CONFIG_EXTENSION_VALUE_INVALID",
                "The worktree configuration extension value was invalid.",
            )
    elif extensions.returncode == 1:
        raise ActionGateError(
            "WORKTREE_CONFIG_EXTENSION_VALUE_INVALID",
            "The worktree configuration extension value was invalid.",
        )
    else:
        raise ActionGateError("GIT_CONFIG_AUDIT_UNAVAILABLE", "The worktree configuration extension could not be read.")
    config_bytes = config.stdout
    if worktree_config_enabled:
        worktree_path = _git_command(
            git_executable,
            repository,
            "rev-parse",
            "--path-format=absolute",
            "--git-path",
            "config.worktree",
        )
        if worktree_path.returncode != 0:
            raise ActionGateError("GIT_CONFIG_AUDIT_UNAVAILABLE", "The worktree configuration location was unavailable.")
        try:
            worktree_config_path = Path(worktree_path.stdout.decode("utf-8", "strict").strip())
            worktree_observation = worktree_config_path.lstat()
        except FileNotFoundError:
            worktree_observation = None
        except (UnicodeDecodeError, OSError) as exc:
            raise ActionGateError("GIT_CONFIG_AUDIT_UNAVAILABLE", "The worktree configuration location was invalid.") from exc
        if worktree_observation is not None:
            if stat.S_ISLNK(worktree_observation.st_mode) or not stat.S_ISREG(worktree_observation.st_mode):
                raise ActionGateError("GIT_CONFIG_AUDIT_UNAVAILABLE", "The worktree configuration was not a regular file.")
            worktree_config = _git_command(
                git_executable,
                repository,
                "config",
                "--worktree",
                "--show-origin",
                "--show-scope",
                "--null",
                "--list",
            )
            if worktree_config.returncode != 0:
                raise ActionGateError("GIT_CONFIG_AUDIT_UNAVAILABLE", "The worktree Git configuration could not be read.")
            config_bytes += worktree_config.stdout
    records = _git_config_records(config_bytes)
    return _EffectiveGitConfig(
        sha256=hashlib.sha256(config_bytes).hexdigest(),
        source_categories=tuple(sorted({_git_config_source_category(scope, origin) for scope, origin, _key, _value in records})),
        risk_categories=_git_credential_risks(config_bytes),
    )


def _gitlink_entries(index_bytes: bytes) -> tuple[tuple[str, str], ...]:
    """Return safe stage-zero gitlinks from ``ls-files --stage -z`` output."""

    entries: list[tuple[str, str]] = []
    for raw_record in index_bytes.split(b"\0"):
        if not raw_record:
            continue
        metadata, separator, raw_path = raw_record.partition(b"\t")
        fields = metadata.split(b" ")
        if not separator or len(fields) != 3:
            raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "The Git index record was incomplete.")
        mode, raw_sha, stage = fields
        if mode != b"160000":
            continue
        try:
            expected_sha = raw_sha.decode("ascii", "strict")
            path_text = raw_path.decode("utf-8", "surrogateescape")
        except (UnicodeDecodeError, UnicodeError) as exc:
            raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule index record was invalid.") from exc
        relative = PurePosixPath(path_text)
        if (
            stage != b"0"
            or _SHA_PATTERN.fullmatch(expected_sha) is None
            or relative.is_absolute()
            or not relative.parts
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule index path or binding was unsafe.")
        entries.append((path_text, expected_sha))
    return tuple(entries)


def _capture_initialized_submodule(
    *,
    git_executable: FrozenExecutable,
    workspace: Path,
    repository: Path,
    prefix: PurePosixPath,
    local_path: str,
    expected_sha: str,
    visited: set[tuple[int, int]],
    depth: int,
) -> tuple[dict[str, Any], ...]:
    relative = prefix / PurePosixPath(local_path)
    submodule_path = repository.joinpath(*PurePosixPath(local_path).parts)
    if _path_has_symlink_component(submodule_path):
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "An initialized submodule path contained a symbolic link.")
    try:
        path_observation = submodule_path.lstat()
    except FileNotFoundError:
        return (
            {
                "path": str(relative),
                "expected_head_sha": expected_sha,
                "present": False,
                "initialized": False,
            },
        )
    if not stat.S_ISDIR(path_observation.st_mode):
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule worktree path was not a directory.")
    git_marker = submodule_path / ".git"
    try:
        git_marker_observation = git_marker.lstat()
    except FileNotFoundError:
        raise ActionGateError(
            "SUBMODULE_GIT_CONFIG_UNAUDITABLE",
            "A present submodule worktree could not be proven initialized or bound to its gitlink.",
        ) from None
    except OSError as exc:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule Git directory was unavailable.") from exc
    if stat.S_ISLNK(git_marker_observation.st_mode) or not (stat.S_ISREG(git_marker_observation.st_mode) or stat.S_ISDIR(git_marker_observation.st_mode)):
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule Git directory binding was unsafe.")
    top_level = _git_command(git_executable, submodule_path, "rev-parse", "--show-toplevel")
    if top_level.returncode != 0:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "An initialized submodule could not be inspected.")
    try:
        observed_top_level = Path(os.path.abspath(top_level.stdout.decode("utf-8", "strict").strip()))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule worktree could not be classified.") from exc
    if observed_top_level != submodule_path:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "A submodule worktree root was not exact.")
    identity = (path_observation.st_dev, path_observation.st_ino)
    if identity in visited:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "An initialized submodule cycle was detected.")
    visited.add(identity)
    try:
        audit = _capture_effective_git_config(git_executable, submodule_path)
    except ActionGateError as exc:
        raise ActionGateError(
            "SUBMODULE_GIT_CONFIG_UNAUDITABLE",
            "An initialized submodule Git configuration could not be audited.",
        ) from exc
    record: dict[str, Any] = {
        "path": str(relative),
        "expected_head_sha": expected_sha,
        "present": True,
        "initialized": True,
        "directory_identity": [path_observation.st_dev, path_observation.st_ino],
        "config_sha256": audit.sha256,
        "config_source_categories": list(audit.source_categories),
        "credential_risk_categories": list(audit.risk_categories),
    }
    if audit.risk_categories:
        record["clean"] = False
        return (record,)
    head = _git_command(git_executable, submodule_path, "rev-parse", "--verify", "HEAD^{commit}")
    head_tree = _git_command(git_executable, submodule_path, "rev-parse", "--verify", "HEAD^{tree}")
    index_tree = _git_command(git_executable, submodule_path, "write-tree")
    index_result = _git_command(git_executable, submodule_path, "ls-files", "--stage", "-z")
    staged_diff = _git_command(
        git_executable,
        submodule_path,
        "diff",
        "--cached",
        "--quiet",
        "--no-ext-diff",
        "--no-textconv",
        "HEAD",
        "--",
    )
    worktree_clean = _git_command(
        git_executable,
        submodule_path,
        "diff",
        "--quiet",
        "--no-ext-diff",
        "--no-textconv",
        "--",
    )
    status_result = _git_command(
        git_executable,
        submodule_path,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
    )
    required = (head, head_tree, index_tree, index_result, status_result)
    if any(result.returncode != 0 for result in required) or staged_diff.returncode not in {0, 1} or worktree_clean.returncode not in {0, 1}:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "An initialized submodule state could not be read.")
    head_sha = head.stdout.decode("ascii", "strict").strip()
    head_tree_sha = head_tree.stdout.decode("ascii", "strict").strip()
    index_tree_sha = index_tree.stdout.decode("ascii", "strict").strip()
    if any(_SHA_PATTERN.fullmatch(value) is None for value in (head_sha, head_tree_sha, index_tree_sha)):
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "An initialized submodule Git object identifier was invalid.")
    nested = _capture_initialized_submodules(
        git_executable=git_executable,
        workspace=workspace,
        repository=submodule_path,
        prefix=relative,
        index_bytes=index_result.stdout,
        visited=visited,
        depth=depth + 1,
    )
    record.update(
        {
            "head_sha": head_sha,
            "head_tree_sha": head_tree_sha,
            "index_tree_sha": index_tree_sha,
            "index_sha256": hashlib.sha256(index_result.stdout).hexdigest(),
            "status_sha256": hashlib.sha256(status_result.stdout).hexdigest(),
            "clean": bool(
                head_sha == expected_sha
                and head_tree_sha == index_tree_sha
                and staged_diff.returncode == 0
                and worktree_clean.returncode == 0
                and not status_result.stdout
                and all(item.get("clean", True) for item in nested)
            ),
        }
    )
    return (record, *nested)


def _capture_initialized_submodules(
    *,
    git_executable: FrozenExecutable,
    workspace: Path,
    repository: Path,
    prefix: PurePosixPath,
    index_bytes: bytes,
    visited: set[tuple[int, int]],
    depth: int = 0,
) -> tuple[dict[str, Any], ...]:
    if depth > 16:
        raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "The initialized submodule nesting limit was exceeded.")
    records: list[dict[str, Any]] = []
    for local_path, expected_sha in _gitlink_entries(index_bytes):
        if len(records) + len(visited) >= 64:
            raise ActionGateError("SUBMODULE_GIT_CONFIG_UNAUDITABLE", "The initialized submodule count limit was exceeded.")
        submodule_records = _capture_initialized_submodule(
            git_executable=git_executable,
            workspace=workspace,
            repository=repository,
            prefix=prefix,
            local_path=local_path,
            expected_sha=expected_sha,
            visited=visited,
            depth=depth,
        )
        records.extend(submodule_records)
    return tuple(records)


def _summarize_submodule_state(submodule_records: tuple[dict[str, Any], ...]) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
    submodule_config_projection = [
        {
            "path": record["path"],
            "initialized": record["initialized"],
            "config_sha256": record.get("config_sha256"),
            "config_source_categories": record.get("config_source_categories", []),
            "credential_risk_categories": record.get("credential_risk_categories", []),
        }
        for record in submodule_records
    ]
    submodule_config_sha256 = sha256_json(submodule_config_projection)
    submodule_state_sha256 = sha256_json(list(submodule_records))
    submodule_risks = tuple(sorted(f"{record['path']}:{risk}" for record in submodule_records for risk in record.get("credential_risk_categories", [])))
    submodule_sources = tuple(sorted(f"{record['path']}:{source}" for record in submodule_records for source in record.get("config_source_categories", [])))
    return submodule_config_sha256, submodule_state_sha256, submodule_risks, submodule_sources


def _decode_git_object_identifiers(
    head: subprocess.CompletedProcess[bytes],
    head_tree: subprocess.CompletedProcess[bytes],
    index_tree: subprocess.CompletedProcess[bytes],
) -> tuple[str, str, str]:
    try:
        head_sha = head.stdout.decode("ascii", "strict").strip()
        head_tree_sha = head_tree.stdout.decode("ascii", "strict").strip()
        index_tree_sha = index_tree.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError as exc:
        raise ActionGateError("GIT_STATE_UNAVAILABLE", "A repository Git object identifier was invalid.") from exc
    if any(_SHA_PATTERN.fullmatch(value) is None for value in (head_sha, head_tree_sha, index_tree_sha)):
        raise ActionGateError("GIT_STATE_UNAVAILABLE", "A repository Git object identifier was incomplete.")
    return head_sha, head_tree_sha, index_tree_sha


def _capture_git_snapshot(
    workspace: Path | None,
    expected_repository: str,
    git_executable: FrozenExecutable | None,
    *,
    allowed_untracked_paths: frozenset[Path] = frozenset(),
) -> GitSnapshot:
    if workspace is None:
        return GitSnapshot()
    if git_executable is None or not _executable_unchanged(git_executable):
        raise ActionGateError("TRUSTED_GIT_EXECUTABLE_CHANGED", "The frozen Git executable is unavailable or changed.")
    inside = _git_command(git_executable, workspace, "rev-parse", "--is-inside-work-tree")
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        return GitSnapshot()
    main_config = _capture_effective_git_config(git_executable, workspace)
    credential_risks = main_config.risk_categories
    head = _git_command(git_executable, workspace, "rev-parse", "--verify", "HEAD^{commit}")
    head_tree = _git_command(git_executable, workspace, "rev-parse", "--verify", "HEAD^{tree}")
    index_tree = _git_command(git_executable, workspace, "write-tree")
    symbolic = _git_command(git_executable, workspace, "symbolic-ref", "-q", "HEAD")
    remote = _git_command(git_executable, workspace, "remote", "get-url", "origin")
    index_result = _git_command(git_executable, workspace, "ls-files", "--stage", "-z")
    if credential_risks:
        staged_diff = subprocess.CompletedProcess([], 1, b"", b"")
        worktree_clean = subprocess.CompletedProcess([], 1, b"", b"")
        worktree_diff = subprocess.CompletedProcess([], 0, b"", b"")
        status_result = subprocess.CompletedProcess([], 0, b"", b"")
        submodule_records: tuple[dict[str, Any], ...] = ()
    else:
        if index_result.returncode != 0:
            raise ActionGateError("GIT_STATE_UNAVAILABLE", "The repository index could not be read.")
        root_observation = workspace.lstat()
        submodule_records = _capture_initialized_submodules(
            git_executable=git_executable,
            workspace=workspace,
            repository=workspace,
            prefix=PurePosixPath(),
            index_bytes=index_result.stdout,
            visited={(root_observation.st_dev, root_observation.st_ino)},
        )
        staged_diff = _git_command(git_executable, workspace, "diff", "--cached", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--")
        worktree_clean = _git_command(git_executable, workspace, "diff", "--quiet", "--no-ext-diff", "--no-textconv", "--")
        worktree_diff = _git_command(git_executable, workspace, "diff", "--no-ext-diff", "--no-textconv", "--binary", "HEAD", "--")
        status_result = _git_command(git_executable, workspace, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    required = (head, head_tree, index_tree, index_result, worktree_diff, status_result)
    if any(result.returncode != 0 for result in required) or staged_diff.returncode not in {0, 1} or worktree_clean.returncode not in {0, 1}:
        raise ActionGateError("GIT_STATE_UNAVAILABLE", "The repository HEAD, index, worktree, or local configuration could not be read.")
    head_sha, head_tree_sha, index_tree_sha = _decode_git_object_identifiers(head, head_tree, index_tree)
    unexpected_untracked = tuple(path for path in _untracked_paths(status_result.stdout) if (workspace / path).absolute() not in allowed_untracked_paths)
    observed_repository = _repository_slug(remote.stdout.decode("utf-8", "replace")) if remote.returncode == 0 else None
    worktree_diff_sha256 = hashlib.sha256(worktree_diff.stdout).hexdigest()
    status_sha256 = hashlib.sha256(status_result.stdout).hexdigest()
    index_sha256 = hashlib.sha256(index_result.stdout).hexdigest()
    submodule_config_sha256, submodule_state_sha256, submodule_risks, submodule_sources = _summarize_submodule_state(submodule_records)
    state_sha256 = sha256_json(
        {
            "head_sha": head_sha,
            "head_tree_sha": head_tree_sha,
            "index_tree_sha": index_tree_sha,
            "symbolic_head": symbolic.stdout.decode("utf-8", "replace").strip() if symbolic.returncode == 0 else None,
            "effective_config_sha256": main_config.sha256,
            "index_sha256": index_sha256,
            "worktree_diff_sha256": worktree_diff_sha256,
            "status_sha256": status_sha256,
            "submodule_config_sha256": submodule_config_sha256,
            "submodule_state_sha256": submodule_state_sha256,
        }
    )
    return GitSnapshot(
        available=True,
        head_sha=head_sha,
        head_tree_sha=head_tree_sha,
        index_tree_sha=index_tree_sha,
        symbolic_head=symbolic.stdout.decode("utf-8", "replace").strip() if symbolic.returncode == 0 else None,
        repository_identity_matches=observed_repository == expected_repository,
        tracked_index_clean=staged_diff.returncode == 0 and index_tree_sha == head_tree_sha,
        tracked_worktree_clean=worktree_clean.returncode == 0,
        submodules_clean=not submodule_risks and all(record.get("clean", True) for record in submodule_records),
        unexpected_untracked_count=len(unexpected_untracked),
        local_config_sha256=main_config.sha256,
        effective_config_sha256=main_config.sha256,
        config_source_categories=main_config.source_categories,
        index_sha256=index_sha256,
        worktree_diff_sha256=worktree_diff_sha256,
        status_sha256=status_sha256,
        state_sha256=state_sha256,
        credential_risks=credential_risks,
        submodule_count=sum(1 for record in submodule_records if record["initialized"]),
        submodule_paths=tuple(record["path"] for record in submodule_records),
        submodule_config_sha256=submodule_config_sha256,
        submodule_state_sha256=submodule_state_sha256,
        submodule_credential_risks=submodule_risks,
        submodule_config_source_categories=submodule_sources,
    )


def _git_post_checks(
    before: GitSnapshot,
    workspace: Path | None,
    expected_repository: str,
    git_executable: FrozenExecutable | None,
    *,
    allowed_untracked_paths: frozenset[Path] = frozenset(),
) -> list[dict[str, Any]]:
    if not before.available:
        return []
    after = _capture_git_snapshot(workspace, expected_repository, git_executable, allowed_untracked_paths=allowed_untracked_paths)
    return [
        _check("CURRENT_HEAD_CHANGED_DURING_TEST", after.available and after.head_sha == before.head_sha),
        _check("GIT_SYMBOLIC_HEAD_UNCHANGED", after.available and after.symbolic_head == before.symbolic_head),
        _check("GIT_SECURITY_CONFIGURATION_MUTATED_DURING_TEST", after.available and after.effective_config_sha256 == before.effective_config_sha256),
        _check(
            "SUBMODULE_GIT_CONFIG_MUTATED",
            after.available and after.submodule_config_sha256 == before.submodule_config_sha256,
        ),
        _check(
            "SUBMODULE_STATE_CHANGED_DURING_TEST",
            after.available and after.submodule_paths == before.submodule_paths and after.submodule_state_sha256 == before.submodule_state_sha256,
        ),
        _check("GIT_INDEX_UNCHANGED_DURING_TEST", after.available and after.index_sha256 == before.index_sha256),
        _check("GIT_WORKTREE_UNCHANGED_DURING_TEST", after.available and after.worktree_diff_sha256 == before.worktree_diff_sha256),
        _check("GIT_STATUS_UNCHANGED_DURING_TEST", after.available and after.status_sha256 == before.status_sha256),
        _check("GIT_STATE_UNCHANGED_DURING_TEST", after.available and after.state_sha256 == before.state_sha256),
        _check("GIT_REPOSITORY_IDENTITY_UNCHANGED", after.available and after.repository_identity_matches == before.repository_identity_matches),
    ]


def _execution_preflight_checks(environment: Mapping[str, str], context: PullRequestContext, git_snapshot: GitSnapshot) -> list[dict[str, Any]]:
    event_name = environment.get("TITMAS_CURRENT_EVENT_NAME") or environment.get("GITHUB_EVENT_NAME")
    github_mode = environment.get("GITHUB_ACTIONS", "").lower() == "true" or event_name is not None
    checks = [
        _check("TRUSTED_EVENT_TYPE", not github_mode or event_name == "pull_request", event_name or "LOCAL_READ_ONLY"),
        _check("PERSISTED_GIT_CREDENTIAL_DETECTED", not git_snapshot.credential_risks, list(git_snapshot.credential_risks)),
        _check(
            "SUBMODULE_GIT_CREDENTIAL_DETECTED",
            not git_snapshot.submodule_credential_risks,
            list(git_snapshot.submodule_credential_risks),
        ),
    ]
    if github_mode:
        checks.extend(
            [
                _check("GIT_WORKTREE_AVAILABLE", git_snapshot.available),
                _check("ACTUAL_HEAD_SHA_MATCH", git_snapshot.available and git_snapshot.head_sha == context.head_sha),
                _check(
                    "HEAD_EXECUTION_BASELINE_MISMATCH",
                    git_snapshot.available and git_snapshot.head_sha == context.head_sha and git_snapshot.head_tree_sha == git_snapshot.index_tree_sha,
                ),
                _check(
                    "DIRTY_TRACKED_EXECUTION_BASELINE",
                    git_snapshot.available and git_snapshot.tracked_index_clean and git_snapshot.tracked_worktree_clean and git_snapshot.submodules_clean,
                ),
                _check("UNDECLARED_UNTRACKED_EXECUTION_INPUTS", git_snapshot.unexpected_untracked_count == 0),
                _check("ACTUAL_REPOSITORY_IDENTITY_MATCH", git_snapshot.repository_identity_matches is True),
            ]
        )
    return checks


def _check(check_id: str, passed: bool, observed: Any = None) -> dict[str, Any]:
    result: dict[str, Any] = {"check_id": check_id, "passed": bool(passed)}
    if observed is not None:
        result["observed"] = observed
    return result


def _safe_task_summary(request: dict[str, Any]) -> dict[str, Any]:
    target = request.get("target") if isinstance(request.get("target"), dict) else {}
    return {
        "request_id": request.get("request_id"),
        "action": request.get("action"),
        "repository": target.get("repository"),
        "resource_ref": target.get("resource_ref"),
        "parameters_sha256": request.get("parameters_sha256"),
    }


def _validate_runtime_binding(
    request: dict[str, Any],
    context: PullRequestContext,
    command: list[str],
) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    try:
        validate_action_request(request)
    except Exception as exc:
        return [_check("TASK_CONTRACT_VALID", False, getattr(exc, "code", type(exc).__name__))]

    checks.append(_check("TASK_CONTRACT_VALID", True))
    parameters = request["parameters"]
    target = request["target"]
    task_pull_request = parameters.get("pull_request")
    task_head_sha = parameters.get("head_sha")
    task_identity = parameters.get("execution_identity")
    task_command = parameters.get("test_command")
    pull_number_valid = isinstance(task_pull_request, int) and not isinstance(task_pull_request, bool) and task_pull_request > 0
    current_pull_number_valid = isinstance(context.pull_request, int) and not isinstance(context.pull_request, bool) and context.pull_request > 0
    head_sha_valid = isinstance(task_head_sha, str) and _SHA_PATTERN.fullmatch(task_head_sha) is not None
    current_head_sha_valid = isinstance(context.head_sha, str) and _SHA_PATTERN.fullmatch(context.head_sha) is not None
    command_valid = isinstance(task_command, list) and bool(task_command) and all(isinstance(item, str) and bool(item) for item in task_command)
    expected_ref = f"refs/pull/{task_pull_request}/head@{task_head_sha}" if pull_number_valid and head_sha_valid else None
    checks.extend(
        [
            _check("MERGE_ACTION_BOUND", request["action"] == "github.pull_request.merge"),
            _check("REPOSITORY_MATCH", bool(context.repository) and target["repository"] == context.repository),
            _check("PULL_REQUEST_NUMBER_VALID", pull_number_valid),
            _check("CURRENT_PULL_REQUEST_NUMBER_VALID", current_pull_number_valid),
            _check("PULL_REQUEST_MATCH", pull_number_valid and current_pull_number_valid and task_pull_request == context.pull_request),
            _check("HEAD_SHA_FORMAT_VALID", head_sha_valid),
            _check("CURRENT_HEAD_SHA_FORMAT_VALID", current_head_sha_valid),
            _check("HEAD_SHA_MATCH", head_sha_valid and current_head_sha_valid and task_head_sha == context.head_sha),
            _check("RESOURCE_REF_MATCH", expected_ref is not None and target["resource_ref"] == expected_ref),
            _check("EXECUTION_IDENTITY_MATCH", isinstance(task_identity, str) and bool(task_identity) and task_identity == context.execution_identity),
            _check("TEST_COMMAND_BOUND", command_valid and task_command == command),
        ]
    )
    return checks


def _missing_evidence_result(request: dict[str, Any], *, checked_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "request_id": request["request_id"],
        "request_binding": request_binding(request),
        "verifier": {
            "name": "agent-evidence",
            "version": AGENT_EVIDENCE_VERSION,
            "distribution_sha256": AGENT_EVIDENCE_WHEEL_SHA256,
        },
        "status": "MISSING",
        "bundle_sha256": None,
        "evidence_types": [],
        "checks": [],
        "verified_at": format_datetime(checked_at),
    }


def _invalid_evidence_result(request: dict[str, Any], digest: str | None, *, checked_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": "0.1.0",
        "request_id": request["request_id"],
        "request_binding": request_binding(request),
        "verifier": {
            "name": "agent-evidence",
            "version": AGENT_EVIDENCE_VERSION,
            "distribution_sha256": AGENT_EVIDENCE_WHEEL_SHA256,
        },
        "status": "INVALID",
        "bundle_sha256": digest,
        "evidence_types": [],
        "checks": [{"check_id": "VERIFIER_EXECUTION", "passed": False}],
        "verified_at": format_datetime(checked_at),
    }


def _verify_frozen_evidence(request: dict[str, Any], evidence: FrozenJsonInput, *, checked_at: datetime) -> dict[str, Any]:
    if evidence.missing or evidence.raw_bytes is None or evidence.sha256 is None:
        return _missing_evidence_result(request, checked_at=checked_at)
    try:
        with tempfile.TemporaryDirectory(prefix="titmas-evidence-adapter-") as directory:
            adapter = AgentEvidenceAdapter(directory)
            profile_path = Path(directory) / "frozen-profile.json"
            profile_path.write_bytes(evidence.raw_bytes)
            try:
                return adapter.verify_profile(
                    request,
                    profile_path.name,
                    evidence_types=request["evidence_requirements"],
                    expected_sha256=evidence.sha256,
                    verified_at=checked_at,
                )
            finally:
                profile_path.unlink(missing_ok=True)
    except Exception:
        return _invalid_evidence_result(request, evidence.sha256, checked_at=checked_at)


def _test_environment(environment: Mapping[str, str], *, home: Path, temporary_directory: Path) -> tuple[dict[str, str], dict[str, Any]]:
    child = {key: environment[key] for key in _TEST_ENVIRONMENT_ALLOWLIST if isinstance(environment.get(key), str)}
    child.update(
        {
            "CI": "true",
            "HOME": str(home),
            "TMPDIR": str(temporary_directory),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
        }
    )
    removed_names = sorted(key for key in environment if key not in _TEST_ENVIRONMENT_ALLOWLIST)
    metadata = {
        "policy_version": TEST_ENVIRONMENT_POLICY_VERSION,
        "allowed_parent_names": list(_TEST_ENVIRONMENT_ALLOWLIST),
        "removed_names": removed_names,
        "removed_count": len(removed_names),
        "fresh_home": True,
        "fresh_tmpdir": True,
    }
    return child, metadata


def _terminate_process_group(process: subprocess.Popen[bytes]) -> bool:
    if not hasattr(os, "killpg"):
        return process.poll() is not None
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            return False
        time.sleep(0.01)
    return False


def _observe_stream(stream: BinaryIO, exceeded: threading.Event, budget: _SharedOutputBudget) -> _StreamObservation:
    digest = hashlib.sha256()
    observed_bytes = 0
    limit_exceeded = False
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        accepted, claim_exceeded = budget.claim(chunk)
        digest.update(accepted)
        observed_bytes += len(accepted)
        if claim_exceeded:
            limit_exceeded = True
            exceeded.set()
            break
    return _StreamObservation(digest.hexdigest(), observed_bytes, limit_exceeded)


def _run_test(
    command: list[str],
    *,
    execute: bool,
    environment: Mapping[str, str],
    workspace: Path | None,
) -> dict[str, Any]:
    if not execute:
        return {
            "executed": False,
            "exit_code": None,
            "command_sha256": sha256_json(command),
            "stdout_sha256": None,
            "stderr_sha256": None,
            "duration_ms": 0,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "combined_output_bytes": 0,
            "max_total_output_bytes": MAX_TOTAL_TEST_OUTPUT_BYTES,
            "output_limit_exceeded": False,
            "timed_out": False,
            "process_group_cleanup": "NOT_STARTED",
            "environment": {
                "policy_version": TEST_ENVIRONMENT_POLICY_VERSION,
                "allowed_parent_names": list(_TEST_ENVIRONMENT_ALLOWLIST),
                "removed_names": [],
                "removed_count": 0,
                "fresh_home": False,
                "fresh_tmpdir": False,
            },
        }
    started = time.monotonic()
    timed_out = False
    output_limit_event = threading.Event()
    output_budget = _SharedOutputBudget(MAX_TOTAL_TEST_OUTPUT_BYTES)
    cleanup = "NOT_STARTED"
    exit_code = 127
    observations: dict[str, _StreamObservation] = {}
    threads: list[threading.Thread] = []

    def observe(name: str, stream: BinaryIO) -> None:
        observations[name] = _observe_stream(stream, output_limit_event, output_budget)

    with tempfile.TemporaryDirectory(prefix="titmas-test-environment-", ignore_cleanup_errors=True) as directory:
        temporary_root = Path(directory)
        home = temporary_root / "home"
        temporary = temporary_root / "tmp"
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        child_environment, environment_metadata = _test_environment(environment, home=home, temporary_directory=temporary)
        process: subprocess.Popen[bytes] | None = None
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(workspace) if workspace is not None else None,
                env=child_environment,
                start_new_session=True,
                close_fds=True,
                bufsize=0,
            )
            if process.stdout is None or process.stderr is None:
                raise OSError("TEST_OUTPUT_PIPE_UNAVAILABLE")
            threads = [
                threading.Thread(target=observe, args=("stdout", process.stdout), daemon=True),
                threading.Thread(target=observe, args=("stderr", process.stderr), daemon=True),
            ]
            for thread in threads:
                thread.start()
            while process.poll() is None:
                if output_limit_event.is_set():
                    _terminate_process_group(process)
                    break
                if time.monotonic() - started >= TEST_TIMEOUT_SECONDS:
                    timed_out = True
                    _terminate_process_group(process)
                    break
                time.sleep(0.01)
            try:
                exit_code = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                _terminate_process_group(process)
                try:
                    exit_code = process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    exit_code = 124
            cleaned = process.poll() is not None and _terminate_process_group(process)
            cleanup = "COMPLETE" if cleaned else "FAILED"
        except OSError:
            if process is None:
                cleanup = "NOT_STARTED"
                exit_code = 127
            else:
                cleanup = "FAILED"
        finally:
            for thread in threads:
                thread.join(timeout=2)
            if any(thread.is_alive() for thread in threads):
                cleanup = "FAILED"
            if process is not None:
                if process.poll() is None:
                    group_cleaned = _terminate_process_group(process)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                    cleanup = "COMPLETE" if group_cleaned and process.poll() is not None else "FAILED"
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
    empty_digest = hashlib.sha256(b"").hexdigest()
    stdout_observation = observations.get("stdout", _StreamObservation(empty_digest, 0, False))
    stderr_observation = observations.get("stderr", _StreamObservation(empty_digest, 0, False))
    output_limit_exceeded = output_limit_event.is_set() or stdout_observation.limit_exceeded or stderr_observation.limit_exceeded
    if timed_out:
        exit_code = 124
    elif output_limit_exceeded:
        exit_code = 125
    return {
        "executed": True,
        "exit_code": exit_code,
        "command_sha256": sha256_json(command),
        "stdout_sha256": stdout_observation.sha256,
        "stderr_sha256": stderr_observation.sha256,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "stdout_bytes": stdout_observation.observed_bytes,
        "stderr_bytes": stderr_observation.observed_bytes,
        "combined_output_bytes": output_budget.observed_bytes,
        "max_total_output_bytes": MAX_TOTAL_TEST_OUTPUT_BYTES,
        "output_limit_exceeded": output_limit_exceeded,
        "timed_out": timed_out,
        "process_group_cleanup": cleanup,
        "environment": environment_metadata,
    }


def _load_frozen_approval(approval: FrozenJsonInput | None) -> tuple[dict[str, Any] | None, str | None]:
    if approval is None or approval.missing:
        return None, None
    try:
        payload = approval.payload()
        validate_contract("human_approval", payload)
        return payload, None
    except Exception as exc:
        return {}, getattr(exc, "code", type(exc).__name__)


def _approval_authority(environment: Mapping[str, str], approval: dict[str, Any] | None) -> tuple[ApprovalAuthority, bool]:
    material = environment.get("TITMAS_APPROVAL_HMAC_KEY")
    available = approval is None or isinstance(material, str) and len(material.encode("utf-8")) >= 32
    key = material.encode("utf-8") if available and material is not None else _UNAVAILABLE_APPROVAL_KEY
    return ApprovalAuthority(key), available


def _public_projection(
    decision: dict[str, Any],
    runtime_checks: list[dict[str, Any]],
    test_result: dict[str, Any],
    evidence_result: dict[str, Any] | None,
) -> tuple[str, list[str]]:
    failed_checks = {item["check_id"] for item in runtime_checks if not item["passed"]}
    if test_result.get("output_limit_exceeded"):
        return "FAIL", ["TEST_OUTPUT_LIMIT_EXCEEDED"]
    reason_priority = [
        "POST_TEST_SECURITY_RECHECK_INCOMPLETE",
        "POST_TEST_GIT_RECHECK_FAILED",
        "POST_TEST_STATE_UNKNOWN",
        "CURRENT_HEAD_CHANGED_DURING_TEST",
        "RESERVED_OUTPUT_CONTENT_MUTATED",
        "RESERVED_OUTPUT_IDENTITY_CHANGED",
        "GATE_OUTPUT_PATH_MUTATED_DURING_TEST",
        "GATE_OUTPUT_PATH_PREEXISTED",
        "PERSISTED_GIT_CREDENTIAL_DETECTED",
        "SUBMODULE_GIT_CREDENTIAL_DETECTED",
        "SUBMODULE_GIT_CONFIG_UNAUDITABLE",
        "SUBMODULE_GIT_CONFIG_MUTATED",
        "SUBMODULE_STATE_CHANGED_DURING_TEST",
        "GIT_SECURITY_CONFIGURATION_MUTATED_DURING_TEST",
        "GIT_STATE_CHANGED_DURING_TEST",
        "DIRTY_TRACKED_EXECUTION_BASELINE",
        "UNDECLARED_UNTRACKED_EXECUTION_INPUTS",
        "HEAD_EXECUTION_BASELINE_MISMATCH",
        "PATH_ANCESTOR_MUTATED_DURING_TEST",
        "GATE_INPUT_MUTATED_DURING_TEST",
        "ACTION_CONFIGURATION_REQUIRED",
        "ACTION_CONFIGURATION_ROOT_REQUIRED",
        "ACTION_CONFIGURATION_ROOT_INVALID",
        "ACTION_CONFIGURATION_PATH_MISMATCH",
        "ACTION_CONFIGURATION_INVALID",
        "SYMLINK_ANCESTOR_NOT_ALLOWED",
        "OUTPUT_PATH_SYMLINK_NOT_ALLOWED",
        "PATH_COMPONENT_NOT_TRUSTED_DIRECTORY",
        "PATH_ESCAPES_REPOSITORY_ROOT",
        "INPUT_PATH_OUT_OF_SCOPE",
        "INPUT_PATH_RESOURCE_CLEANUP_FAILED",
        "UNTRUSTED_EVENT_TYPE",
        "UNSAFE_TEST_CREDENTIAL_CONTEXT",
    ]
    normalized_failed = set(failed_checks)
    if "TRUSTED_EVENT_TYPE" in normalized_failed:
        normalized_failed.add("UNTRUSTED_EVENT_TYPE")
    if {
        "GIT_INDEX_UNCHANGED_DURING_TEST",
        "GIT_WORKTREE_UNCHANGED_DURING_TEST",
        "GIT_STATUS_UNCHANGED_DURING_TEST",
        "GIT_STATE_UNCHANGED_DURING_TEST",
        "SUBMODULE_GIT_CONFIG_MUTATED",
        "SUBMODULE_STATE_CHANGED_DURING_TEST",
    } & normalized_failed:
        normalized_failed.add("GIT_STATE_CHANGED_DURING_TEST")
    if any(reason.endswith("_PATH_ANCESTOR_MUTATED_DURING_TEST") for reason in normalized_failed):
        normalized_failed.add("PATH_ANCESTOR_MUTATED_DURING_TEST")
    for reason in reason_priority:
        if reason in normalized_failed:
            return "FAIL", [reason]
    if "HEAD_SHA_MATCH" in failed_checks or "RESOURCE_REF_MATCH" in failed_checks:
        return "FAIL", ["EVIDENCE_SUBJECT_MISMATCH"]
    if "TASK_CONTRACT_VALID" in failed_checks:
        return "FAIL", ["INPUT_INVALID"]
    if failed_checks:
        return "FAIL", sorted(failed_checks)
    if test_result["executed"] and test_result["exit_code"] != 0:
        return "FAIL", ["TEST_COMMAND_FAILED"]
    if decision["outcome"] == "ALLOW":
        return "PASS", list(decision["reason_codes"])
    if decision["outcome"] == "REQUIRE_APPROVAL":
        return "REVIEW_REQUIRED", list(decision["reason_codes"])
    if evidence_result is not None and evidence_result["status"] == "MISSING" and decision["reason_codes"] == ["EVIDENCE_MISSING"]:
        return "INCOMPLETE", ["EVIDENCE_MISSING"]
    evidence_checks = {item["check_id"] for item in (evidence_result or {}).get("checks", []) if not item["passed"]}
    if {"SUBJECT_ID", "SUBJECT_LOCATOR", "SUBJECT_DIGEST"} & evidence_checks:
        return "FAIL", ["EVIDENCE_SUBJECT_MISMATCH"]
    return "FAIL", list(decision["reason_codes"])


def _receipt_summary(receipt: dict[str, Any]) -> str:
    state = receipt["final_state"]
    consequence = {
        "PASS": "This check exits 0. GitHub may evaluate the repository's other required checks.",
        "FAIL": "This check exits nonzero and blocks merge when configured as required.",
        "INCOMPLETE": "Required evidence is missing; this check exits nonzero and blocks merge when configured as required.",
        "REVIEW_REQUIRED": "Verified approval is still required; this check exits nonzero and blocks merge when configured as required.",
    }[state]
    test = receipt["test_result"]
    evidence = receipt["evidence"]
    decision = receipt["decision"]
    reasons = ", ".join(receipt["reason_codes"])
    return (
        "# TITMAS evidence gate\n\n"
        f"**{state}** — {reasons}\n\n"
        f"{consequence}\n\n"
        "| Binding | Observed |\n"
        "|---|---|\n"
        f"| Repository | `{receipt['repository']}` |\n"
        f"| Pull request | `{receipt['pull_request']}` |\n"
        f"| Exact head | `{receipt['commit_sha']}` |\n"
        f"| Test exit | `{test['exit_code']}` |\n"
        f"| Evidence status | `{evidence['status']}` |\n"
        f"| Evidence SHA-256 | `{evidence['bundle_sha256']}` |\n"
        f"| Internal decision | `{decision['outcome']}` |\n"
        f"| Risk class | `{receipt['risk_class']}` |\n"
    )


def _private_output_directory() -> tuple[Path, tuple[tuple[str, int, int], ...]]:
    """Create one server-owned private output directory without resolving links."""

    configured = os.environ.get("RUNNER_TEMP")
    candidates = [Path(configured)] if configured else []
    candidates.append(Path("/private/tmp") if Path("/private/tmp").is_dir() else Path(tempfile.gettempdir()))
    for parent in candidates:
        descriptor: int | None = None
        try:
            lexical_parent = Path(os.path.abspath(parent))
            descriptor, parent_identities = _open_directory_no_follow(lexical_parent, create=False)
            for _attempt in range(128):
                name = f"titmas-gate-output-{secrets.token_hex(16)}"
                try:
                    os.mkdir(name, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    continue
                flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
                child = os.open(name, flags, dir_fd=descriptor)
                try:
                    observation = os.fstat(child)
                    if not stat.S_ISDIR(observation.st_mode):
                        raise UnsafePathError("PRIVATE_OUTPUT_DIRECTORY_UNAVAILABLE")
                    output = lexical_parent / name
                    identities = (*parent_identities, (str(output), observation.st_dev, observation.st_ino))
                    return output, identities
                finally:
                    os.close(child)
        except (OSError, UnsafePathError):
            continue
        finally:
            if descriptor is not None:
                os.close(descriptor)
    raise UnsafePathError("PRIVATE_OUTPUT_DIRECTORY_UNAVAILABLE")


def _evaluate_pull_request(
    *,
    task_path: str | Path,
    evidence_path: str | Path,
    policy_path: str | Path,
    test_command: str,
    approval_path: str | Path | None = None,
    repository: str | None = None,
    pull_request: int | None = None,
    head_sha: str | None = None,
    execution_identity: str | None = None,
    environment: Mapping[str, str] | None = None,
    workspace: str | Path | None = None,
    action_configuration_path: str | Path | None = None,
    action_configuration_root: str | Path | None = None,
    output_preflight_safe: bool = True,
    output_preflight_reason: str = "GATE_OUTPUT_PATH_PREEXISTED",
    output_integrity_check: Callable[[], str] | None = None,
    declared_output_paths: tuple[Path, ...] = (),
) -> tuple[dict[str, Any], dict[str, Any]]:
    env = dict(environment if environment is not None else os.environ)
    started_at = utc_now()
    configured_workspace = workspace or env.get("TITMAS_WORKSPACE") or env.get("GITHUB_WORKSPACE")
    workspace_boundary: Path | None = None
    workspace_path: Path | None = None
    workspace_error: Exception | None = None
    if configured_workspace:
        try:
            raw_workspace = Path(configured_workspace).expanduser()
            if not str(raw_workspace) or any(part in {".", ".."} for part in raw_workspace.parts):
                raise ActionGateError(
                    "PATH_ESCAPES_REPOSITORY_ROOT",
                    "The trusted workspace may not contain dot traversal components.",
                )
            workspace_boundary = Path(os.path.abspath(raw_workspace))
            if _path_has_symlink_component(workspace_boundary):
                raise ActionGateError(
                    "SYMLINK_ANCESTOR_NOT_ALLOWED",
                    "The trusted workspace may not contain symbolic links.",
                )
            workspace_observation = workspace_boundary.lstat()
            if not stat.S_ISDIR(workspace_observation.st_mode):
                raise ActionGateError(
                    "PATH_COMPONENT_NOT_TRUSTED_DIRECTORY",
                    "The trusted workspace must be a real directory.",
                )
            workspace_path = workspace_boundary
        except (OSError, ActionGateError) as exc:
            workspace_error = exc
    github_mode = (
        env.get("GITHUB_ACTIONS", "").lower() == "true" or env.get("TITMAS_CURRENT_EVENT_NAME") is not None or env.get("GITHUB_EVENT_NAME") is not None
    )
    context = resolve_pull_request_context(
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        execution_identity=execution_identity,
        environment=env,
    )
    request: dict[str, Any] = {}
    runtime_checks: list[dict[str, Any]] = []
    evidence_result: dict[str, Any] | None = None
    policy_evaluation: dict[str, Any] = {}
    test_result = {
        "executed": False,
        "exit_code": None,
        "command_sha256": None,
        "stdout_sha256": None,
        "stderr_sha256": None,
        "duration_ms": 0,
    }
    approval: dict[str, Any] | None = None
    approval_load_error: str | None = None
    command: list[str] = []
    frozen_inputs: dict[str, FrozenJsonInput] = {}
    post_input_observations: dict[str, dict[str, Any]] = {}
    frozen_action_configuration = FrozenActionConfiguration(None, None, None, None, None, None, ())
    post_action_configuration = {"sha256": None, "identity_changed": False, "mutated": False}
    git_snapshot = GitSnapshot()
    git_executable: FrozenExecutable | None = None
    git_executable_unchanged_after_test: bool | None = None
    allowed_untracked_paths: frozenset[Path] = frozenset()
    post_test_review_completed = False

    try:
        if isinstance(workspace_error, ActionGateError):
            raise workspace_error
        if workspace_error is not None or github_mode and workspace_path is None:
            raise ActionGateError("INPUT_PATH_OUT_OF_SCOPE", "GitHub enforcement requires an existing trusted workspace.")
        task = _freeze_json_input(
            "task",
            task_path,
            workspace=workspace_boundary,
            enforce_workspace=github_mode,
        )
        policy = _freeze_json_input(
            "policy",
            policy_path,
            workspace=workspace_boundary,
            enforce_workspace=github_mode,
        )
        evidence = _freeze_json_input(
            "evidence",
            evidence_path,
            workspace=workspace_boundary,
            enforce_workspace=github_mode,
            allow_missing=True,
        )
        frozen_inputs = {"task": task, "policy": policy, "evidence": evidence}
        frozen_approval: FrozenJsonInput | None = None
        if approval_path is not None:
            frozen_approval = _freeze_json_input(
                "approval",
                approval_path,
                workspace=workspace_boundary,
                enforce_workspace=github_mode,
                allow_missing=True,
            )
            frozen_inputs["approval"] = frozen_approval
        configured_action = action_configuration_path or env.get("TITMAS_ACTION_CONFIG_PATH")
        configured_action_root = action_configuration_root or env.get("TITMAS_ACTION_ROOT")
        if github_mode and configured_action is None:
            raise ActionGateError("ACTION_CONFIGURATION_REQUIRED", "GitHub enforcement requires a frozen composite Action configuration.")
        frozen_action_configuration = _freeze_action_configuration(
            configured_action,
            trusted_root=configured_action_root,
            require_trusted_root=github_mode,
        )

        request = task.payload()
        allowed_untracked_paths = frozenset(value.path.absolute() for value in frozen_inputs.values() if value.path is not None) | frozenset(
            path.absolute() for path in declared_output_paths
        )
        command = shlex.split(test_command)
        if not command:
            raise ActionGateError("TEST_COMMAND_EMPTY", "The task-bound test command is empty.")
        runtime_checks = _validate_runtime_binding(request, context, command)
        if workspace_path is not None:
            git_executable = _freeze_executable("git", env)
        git_snapshot = _capture_git_snapshot(
            workspace_path,
            context.repository,
            git_executable,
            allowed_untracked_paths=allowed_untracked_paths,
        )
        runtime_checks.extend(_execution_preflight_checks(env, context, git_snapshot))
        runtime_checks.append(_check(output_preflight_reason, output_preflight_safe))
        task_valid = bool(runtime_checks) and runtime_checks[0]["passed"]
        if task_valid:
            verification_at = utc_now()
            policy_payload = policy.payload()
            validate_contract("github_merge_gate_policy", policy_payload)
            policy_evaluation = PolicyEngine(policy=policy_payload).evaluate(request, evaluated_at=verification_at)
            evidence_result = _verify_frozen_evidence(request, evidence, checked_at=verification_at)
            approval, approval_load_error = _load_frozen_approval(frozen_approval)
            runtime_checks.append(_check("APPROVAL_CONTRACT_VALID", approval_load_error is None, approval_load_error))
            preflight_passed = all(item["passed"] for item in runtime_checks)
            test_result = _run_test(command, execute=preflight_passed, environment=env, workspace=workspace_path)
            if test_result["executed"]:
                try:
                    runtime_checks.append(_check("TEST_PROCESS_GROUP_CLEANUP", test_result["process_group_cleanup"] == "COMPLETE"))
                    post_input_observations = {role: _post_input_observation(value) for role, value in frozen_inputs.items()}
                    post_action_configuration = _post_action_configuration_observation(frozen_action_configuration)
                    for role, observation in post_input_observations.items():
                        runtime_checks.append(_check(_input_ancestor_check_id(role), not observation["identity_changed"]))
                    runtime_checks.append(
                        _check(
                            "ACTION_CONFIGURATION_PATH_ANCESTOR_MUTATED_DURING_TEST",
                            not post_action_configuration["identity_changed"],
                        )
                    )
                    mutated = any(item["mutated"] for item in post_input_observations.values()) or post_action_configuration["mutated"]
                    runtime_checks.append(_check("GATE_INPUT_MUTATED_DURING_TEST", not mutated))
                    runtime_checks.extend(
                        _git_post_checks(
                            git_snapshot,
                            workspace_path,
                            context.repository,
                            git_executable,
                            allowed_untracked_paths=allowed_untracked_paths,
                        )
                    )
                    git_executable_unchanged_after_test = _executable_unchanged(git_executable) if git_executable is not None else None
                    runtime_checks.append(
                        _check(
                            "TRUSTED_GIT_EXECUTABLE_UNCHANGED_DURING_TEST",
                            git_executable_unchanged_after_test is not False,
                        )
                    )
                    output_state = output_integrity_check() if output_integrity_check is not None else "PRISTINE"
                    if output_state not in {"PRISTINE", "IDENTITY_CHANGED", "CONTENT_MUTATED"}:
                        raise ActionGateError(
                            "POST_TEST_STATE_UNKNOWN",
                            "The reserved output post-test state was unknown.",
                        )
                    runtime_checks.extend(
                        [
                            _check("RESERVED_OUTPUT_IDENTITY_CHANGED", output_state != "IDENTITY_CHANGED"),
                            _check("RESERVED_OUTPUT_CONTENT_MUTATED", output_state != "CONTENT_MUTATED"),
                        ]
                    )
                    post_test_review_completed = True
                except Exception as exc:
                    stable_category = getattr(exc, "code", type(exc).__name__)
                    git_category = isinstance(exc, (subprocess.TimeoutExpired, ActionGateError)) and (
                        stable_category.startswith("GIT_")
                        or stable_category.startswith("SUBMODULE_GIT_")
                        or stable_category.startswith("TRUSTED_GIT_")
                        or isinstance(exc, subprocess.TimeoutExpired)
                    )
                    runtime_checks.append(
                        _check(
                            "POST_TEST_GIT_RECHECK_FAILED" if git_category else "POST_TEST_SECURITY_RECHECK_INCOMPLETE",
                            False,
                            "GIT_RECHECK_UNAVAILABLE" if git_category else "SECURITY_RECHECK_UNAVAILABLE",
                        )
                    )
    except Exception as exc:  # fail closed and retain a receipt for malformed or unavailable inputs
        error_code = getattr(exc, "code", type(exc).__name__)
        if runtime_checks:
            runtime_checks.append(_check(error_code, False))
            runtime_checks.append(_check("INPUT_LOADING_AND_POLICY_EVALUATION", False, error_code))
        else:
            runtime_checks = [_check(error_code, False), _check("TASK_CONTRACT_VALID", False, error_code)]

    # This is the single fail-closed transition before the deterministic gate.
    # The public projection never invents authorization: incomplete runtime or
    # post-test observations convert the frozen policy fact to DENY, and the
    # existing ActionGate remains the only ALLOW/BLOCK/REQUIRE_APPROVAL authority.
    runtime_failed = not runtime_checks or any(not item["passed"] for item in runtime_checks)
    test_failed = bool(test_result.get("executed") and test_result.get("exit_code") != 0)
    post_test_incomplete = bool(test_result.get("executed") and not post_test_review_completed)
    if policy_evaluation and (runtime_failed or test_failed or post_test_incomplete):
        policy_evaluation = deepcopy(policy_evaluation)
        policy_evaluation["effect"] = "DENY"

    authority, approval_verifier_available = _approval_authority(env, approval)
    gate = ActionGate(authority)
    decision_at = utc_now()
    decision = gate.evaluate(request, policy_evaluation, evidence_result or {}, approval, decided_at=decision_at)
    state, reasons = _public_projection(decision, runtime_checks, test_result, evidence_result)
    approval_verified = bool(
        approval and approval_verifier_available and policy_evaluation and authority.verify(approval, request, policy_evaluation, now=decision_at)
    )
    finished_at = utc_now()
    task_digest = frozen_inputs.get("task").sha256 if frozen_inputs.get("task") else None
    policy_digest = frozen_inputs.get("policy").sha256 if frozen_inputs.get("policy") else None
    evidence_summary = evidence_result or {
        "status": "NOT_VERIFIED",
        "bundle_sha256": None,
        "verifier": {"name": "agent-evidence", "version": AGENT_EVIDENCE_VERSION},
        "checks": [],
    }
    receipt = {
        "schema_version": "0.1.0",
        "repository": context.repository or None,
        "pull_request": context.pull_request,
        "commit_sha": context.head_sha or None,
        "task": {
            **_safe_task_summary(request),
            "sha256": task_digest,
        },
        "execution_identity": {
            "reference": context.execution_identity or None,
            "matches_task": any(item["check_id"] == "EXECUTION_IDENTITY_MATCH" and item["passed"] for item in runtime_checks),
        },
        "test_result": test_result,
        "execution_mode": "GITHUB_PULL_REQUEST" if github_mode else "LOCAL_READ_ONLY",
        "negative_checks": runtime_checks,
        "authorization_scope": {
            "action": request.get("action"),
            "target": request.get("target"),
            "parameters_sha256": request.get("parameters_sha256"),
            "policy_effect": policy_evaluation.get("effect"),
            "context_bound": bool(runtime_checks) and all(item["passed"] for item in runtime_checks),
        },
        "evidence": {
            "reference": Path(evidence_path).name,
            "status": evidence_summary["status"],
            "bundle_sha256": evidence_summary["bundle_sha256"],
            "verifier": evidence_summary["verifier"],
            "checks": evidence_summary["checks"],
        },
        "risk_class": policy_evaluation.get("risk_class"),
        "approval": {
            "reference": approval.get("approval_id") if approval else None,
            "verified": approval_verified,
            "verifier_available": approval_verifier_available,
            "load_error": approval_load_error,
        },
        "decision": decision,
        "final_state": state,
        "reason_codes": reasons,
        "started_at": format_datetime(started_at),
        "finished_at": format_datetime(finished_at),
        "tool": {
            "name": "titmas-action-gate",
            "version": _tool_version(),
            "engine_version": ActionGate.ENGINE_VERSION,
        },
        "policy": {
            "reference": frozen_inputs.get("policy").reference if frozen_inputs.get("policy") else Path(policy_path).name,
            "sha256": policy_digest,
            "policy_id": policy_evaluation.get("policy_id"),
            "version": policy_evaluation.get("policy_version"),
            "ruleset_sha256": policy_evaluation.get("ruleset_sha256"),
        },
        "frozen_inputs": {
            role: {
                "reference": value.reference,
                "sha256": value.sha256,
                "canonical_sha256": value.canonical_sha256,
                "missing": value.missing,
                "post_test_sha256": post_input_observations.get(role, {}).get("sha256"),
                "identity_changed": post_input_observations.get(role, {}).get("identity_changed", False),
                "mutated_during_test": post_input_observations.get(role, {}).get("mutated", False),
            }
            for role, value in frozen_inputs.items()
        },
        "action_configuration": {
            "reference": frozen_action_configuration.reference,
            "sha256": frozen_action_configuration.sha256,
            "post_test_sha256": post_action_configuration.get("sha256"),
            "identity_changed": post_action_configuration.get("identity_changed", False),
            "mutated_during_test": post_action_configuration.get("mutated", False),
        },
        "git_binding": {
            "available": git_snapshot.available,
            "head_sha": git_snapshot.head_sha,
            "head_matches_context": git_snapshot.head_sha == context.head_sha if git_snapshot.available else None,
            "repository_identity_matches": git_snapshot.repository_identity_matches,
            "local_config_sha256": git_snapshot.local_config_sha256,
            "effective_config_sha256": git_snapshot.effective_config_sha256,
            "config_source_categories": list(git_snapshot.config_source_categories),
            "head_tree_sha": git_snapshot.head_tree_sha,
            "index_tree_sha": git_snapshot.index_tree_sha,
            "tracked_index_clean": git_snapshot.tracked_index_clean,
            "tracked_worktree_clean": git_snapshot.tracked_worktree_clean,
            "submodules_clean": git_snapshot.submodules_clean,
            "submodule_count": git_snapshot.submodule_count,
            "submodule_paths": list(git_snapshot.submodule_paths),
            "submodule_config_sha256": git_snapshot.submodule_config_sha256,
            "submodule_state_sha256": git_snapshot.submodule_state_sha256,
            "submodule_config_source_categories": list(git_snapshot.submodule_config_source_categories),
            "submodule_credential_risk_categories": list(git_snapshot.submodule_credential_risks),
            "unexpected_untracked_count": git_snapshot.unexpected_untracked_count,
            "index_sha256": git_snapshot.index_sha256,
            "worktree_diff_sha256": git_snapshot.worktree_diff_sha256,
            "status_sha256": git_snapshot.status_sha256,
            "state_sha256": git_snapshot.state_sha256,
            "credential_risk_categories": list(git_snapshot.credential_risks),
            "git_executable": {
                "reference": git_executable.path.name if git_executable else None,
                "sha256": git_executable.sha256 if git_executable else None,
                "unchanged_after_test": git_executable_unchanged_after_test,
            },
        },
    }
    result = {
        "ok": state == "PASS",
        "state": state,
        "reason_codes": reasons,
        "exit_code": PUBLIC_EXIT_CODES[state],
    }
    return receipt, result


def verify_pull_request(
    *,
    task_path: str | Path,
    evidence_path: str | Path,
    policy_path: str | Path,
    test_command: str,
    approval_path: str | Path | None = None,
    output_directory: str | Path = DEFAULT_OUTPUT_DIRECTORY,
    repository: str | None = None,
    pull_request: int | None = None,
    head_sha: str | None = None,
    execution_identity: str | None = None,
    environment: Mapping[str, str] | None = None,
    workspace: str | Path | None = None,
    action_configuration_path: str | Path | None = None,
    action_configuration_root: str | Path | None = None,
) -> dict[str, Any]:
    """Run one bounded PR verification and create its receipt and summary once."""

    raw_output = Path(output_directory).expanduser()
    output_path_syntax_safe = bool(str(raw_output)) and not any(part in {".", ".."} for part in raw_output.parts)
    requested_output = Path(os.path.abspath(raw_output)) if output_path_syntax_safe else Path(os.path.abspath("artifacts/titmas"))
    output = requested_output
    receipt_output: ExclusiveOutput | None = None
    summary_output: ExclusiveOutput | None = None
    output_preflight_reason = "GATE_OUTPUT_PATH_PREEXISTED"
    output_preflight_safe = output_path_syntax_safe and not _path_has_symlink_component(requested_output)
    if not output_preflight_safe:
        output_preflight_reason = "OUTPUT_PATH_SYMLINK_NOT_ALLOWED"

    def abort_reserved(reserved: ExclusiveOutput | None) -> None:
        if reserved is not None:
            reserved.__exit__(RuntimeError, RuntimeError("OUTPUT_RESERVATION_ABORTED"), None)

    def reserve(
        directory: Path,
        expected_ancestor_identities: tuple[tuple[str, int, int], ...] | None = None,
    ) -> tuple[ExclusiveOutput, ExclusiveOutput]:
        first = ExclusiveOutput(
            directory / "receipt.json",
            expected_ancestor_identities=expected_ancestor_identities,
        )
        try:
            second = ExclusiveOutput(
                directory / "summary.md",
                expected_ancestor_identities=expected_ancestor_identities,
            )
        except Exception:
            abort_reserved(first)
            raise
        return first, second

    def reserve_private() -> tuple[Path, ExclusiveOutput, ExclusiveOutput]:
        for _attempt in range(8):
            private_directory, private_identities = _private_output_directory()
            try:
                first, second = reserve(private_directory, private_identities)
            except (FileExistsError, OSError, RuntimeError, UnsafePathError):
                continue
            return private_directory, first, second
        raise UnsafePathError("PRIVATE_OUTPUT_DIRECTORY_UNAVAILABLE")

    if output_preflight_safe:
        try:
            receipt_output, summary_output = reserve(output)
        except UnsafePathError:
            output_preflight_safe = False
            output_preflight_reason = "OUTPUT_PATH_SYMLINK_NOT_ALLOWED"
        except (FileExistsError, OSError, RuntimeError):
            output_preflight_safe = False
    if not output_preflight_safe:
        output, receipt_output, summary_output = reserve_private()

    assert receipt_output is not None and summary_output is not None

    def output_integrity_state() -> str:
        if not receipt_output._path_is_reserved_inode() or not summary_output._path_is_reserved_inode():
            return "IDENTITY_CHANGED"
        if not receipt_output.pristine() or not summary_output.pristine():
            return "CONTENT_MUTATED"
        return "PRISTINE"

    observed_output_state = "PRISTINE"

    def output_integrity_check() -> str:
        nonlocal observed_output_state
        observed_output_state = output_integrity_state()
        return observed_output_state

    receipt, result = _evaluate_pull_request(
        task_path=task_path,
        evidence_path=evidence_path,
        policy_path=policy_path,
        test_command=test_command,
        approval_path=approval_path,
        repository=repository,
        pull_request=pull_request,
        head_sha=head_sha,
        execution_identity=execution_identity,
        environment=environment,
        workspace=workspace,
        action_configuration_path=action_configuration_path,
        action_configuration_root=action_configuration_root,
        output_preflight_safe=output_preflight_safe,
        output_preflight_reason=output_preflight_reason,
        output_integrity_check=output_integrity_check,
        declared_output_paths=(receipt_output.path, summary_output.path),
    )
    output_state = observed_output_state
    output_relocated = output_state != "PRISTINE"
    if output_relocated:
        reason = "RESERVED_OUTPUT_IDENTITY_CHANGED" if output_state == "IDENTITY_CHANGED" else "RESERVED_OUTPUT_CONTENT_MUTATED"
        abort_reserved(receipt_output)
        abort_reserved(summary_output)
        output, receipt_output, summary_output = reserve_private()
    receipt["output_integrity"] = {
        "requested_reference": requested_output.name,
        "preflight_safe": output_preflight_safe,
        "mutated_during_test": output_relocated,
        "mutation_reason": None if not output_relocated else reason,
        "relocated_to_private_directory": output != requested_output,
    }
    summary_output.write_text(_receipt_summary(receipt))
    receipt_output.write_text(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    receipt_path = output / "receipt.json"
    summary_path = output / "summary.md"
    return {
        **result,
        "receipt": str(receipt_path),
        "summary": str(summary_path),
        "receipt_sha256": hashlib.sha256(receipt_path.read_bytes()).hexdigest(),
        "summary_sha256": hashlib.sha256(summary_path.read_bytes()).hexdigest(),
        "output_integrity": "TRUSTED_CREATE_ONLY",
    }
