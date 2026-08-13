"""Narrow provider adapters; only service-consumed ALLOW decisions reach these."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Protocol

from .canonical import format_datetime, sha256_json, utc_now
from .errors import ActionGateError


class GitHubProvider(Protocol):
    def execute(self, invocation: dict[str, Any]) -> dict[str, Any]: ...


class InMemoryGitHubProvider:
    """Deterministic no-network provider for the competition demo and tests."""

    def __init__(self):
        self.pull_requests: dict[int, dict[str, Any]] = {}
        self.next_pull_number = 1

    def execute(self, invocation: dict[str, Any]) -> dict[str, Any]:
        action = invocation["action"]
        parameters = invocation["parameters"]
        if action == "github.pull_request.create":
            number = self.next_pull_number
            self.next_pull_number += 1
            result = {
                "pull_number": number,
                "state": "OPEN",
                "base": parameters["base"],
                "head": parameters["head"],
                "title": parameters["title"],
            }
            self.pull_requests[number] = result
        elif action == "github.pull_request.merge":
            number = int(parameters["pull_number"])
            if number not in self.pull_requests:
                raise ActionGateError("PROVIDER_RESOURCE_NOT_FOUND", f"pull request {number} does not exist")
            self.pull_requests[number]["state"] = "MERGED"
            result = {"pull_number": number, "state": "MERGED", "merge_method": parameters["merge_method"]}
        elif action in {"github.branch.push", "github.tag.create", "github.release.create"}:
            result = {"state": "RECORDED", "parameters": parameters}
        else:
            raise ActionGateError("PROVIDER_ACTION_UNSUPPORTED", f"unsupported GitHub action: {action}")
        return {
            "provider": "github-sandbox",
            "provider_mode": "IN_MEMORY_NO_EXTERNAL_WRITE",
            "action": action,
            "repository": invocation["repository"],
            "result": result,
            "result_sha256": sha256_json(result),
            "executed_at": format_datetime(utc_now()),
        }


class GhCliProvider:
    """Optional real GitHub adapter restricted to one configured repository."""

    def __init__(self, allowed_repository: str, *, allowed_worktree_root: str | Path | None = None):
        self.allowed_repository = allowed_repository
        self.allowed_worktree_root = Path(allowed_worktree_root).resolve() if allowed_worktree_root else None

    def _run(self, arguments: list[str]) -> dict[str, Any]:
        completed = subprocess.run(
            ["gh", "api", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ActionGateError(
                "PROVIDER_CALL_FAILED",
                "GitHub CLI provider call failed.",
                details={"returncode": completed.returncode, "stderr": completed.stderr[-1000:]},
            )
        return json.loads(completed.stdout) if completed.stdout.strip() else {}

    @staticmethod
    def _normalized_github_repository(remote_url: str) -> str | None:
        value = remote_url.strip().removesuffix(".git")
        patterns = (
            r"https://github\.com/(?P<repository>[^/]+/[^/]+)$",
            r"ssh://git@github\.com/(?P<repository>[^/]+/[^/]+)$",
            r"git@github\.com:(?P<repository>[^/]+/[^/]+)$",
        )
        for pattern in patterns:
            match = re.fullmatch(pattern, value)
            if match:
                return match.group("repository")
        return None

    def _git_output(self, arguments: list[str]) -> str:
        if self.allowed_worktree_root is None:
            raise ActionGateError("PROVIDER_CONFIGURATION_INVALID", "branch push requires an allowed worktree root")
        completed = subprocess.run(
            ["git", "-C", str(self.allowed_worktree_root), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0:
            raise ActionGateError(
                "PROVIDER_WORKTREE_INVALID",
                "Git worktree validation failed.",
                details={"returncode": completed.returncode, "stderr": completed.stderr[-1000:]},
            )
        return completed.stdout.strip()

    def _validate_branch_push(self, branch: str, commit: str) -> None:
        if self.allowed_worktree_root is None or not self.allowed_worktree_root.is_dir():
            raise ActionGateError("PROVIDER_CONFIGURATION_INVALID", "branch push requires an existing allowed worktree root")
        top_level = Path(self._git_output(["rev-parse", "--show-toplevel"])).resolve()
        if top_level != self.allowed_worktree_root:
            raise ActionGateError("PROVIDER_WORKTREE_DENIED", "Configured worktree is not the exact Git repository root.")
        remote_repository = self._normalized_github_repository(self._git_output(["remote", "get-url", "origin"]))
        if remote_repository != self.allowed_repository:
            raise ActionGateError("PROVIDER_REMOTE_DENIED", "Git origin does not match the provider repository allowlist.")
        if not re.fullmatch(r"[a-f0-9]{40}", commit):
            raise ActionGateError("PROVIDER_COMMIT_INVALID", "commit must be an exact 40-character SHA-1")
        self._git_output(["cat-file", "-e", f"{commit}^{{commit}}"])
        completed = subprocess.run(
            ["git", "check-ref-format", "--branch", branch],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if completed.returncode != 0 or len(branch) > 120:
            raise ActionGateError("PROVIDER_BRANCH_INVALID", "branch name is not allowed")

    def _execute_branch_push(self, parameters: dict[str, Any]) -> dict[str, Any]:
        worktree = self.allowed_worktree_root
        branch = str(parameters["branch"])
        commit = str(parameters["commit"])
        self._validate_branch_push(branch, commit)
        completed = subprocess.run(
            ["git", "-C", str(worktree), "push", "origin", f"{commit}:refs/heads/{branch}"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if completed.returncode != 0:
            raise ActionGateError(
                "PROVIDER_CALL_FAILED",
                "GitHub branch push failed.",
                details={"returncode": completed.returncode, "stderr": completed.stderr[-1000:]},
            )
        return {"branch": branch, "commit": commit, "state": "PUSHED"}

    def _execute_pull_request_create(self, repository: str, parameters: dict[str, Any]) -> dict[str, Any]:
        payload = self._run(
            [
                "--method", "POST", f"repos/{repository}/pulls",
                "-f", f"title={parameters['title']}",
                "-f", f"head={parameters['head']}",
                "-f", f"base={parameters['base']}",
            ]
        )
        return {
            "pull_number": int(payload["number"]),
            "state": str(payload["state"]).upper(),
            "html_url": payload["html_url"],
            "base": payload["base"]["ref"],
            "head": payload["head"]["ref"],
        }

    def _execute_pull_request_merge(self, repository: str, parameters: dict[str, Any]) -> dict[str, Any]:
        payload = self._run(
            [
                "--method", "PUT", f"repos/{repository}/pulls/{int(parameters['pull_number'])}/merge",
                "-f", f"merge_method={parameters['merge_method']}",
            ]
        )
        return {
            "merged": bool(payload.get("merged")),
            "message": payload.get("message"),
            "sha": payload.get("sha"),
        }

    def execute(self, invocation: dict[str, Any]) -> dict[str, Any]:
        repository = invocation["repository"]
        if repository != self.allowed_repository:
            raise ActionGateError("PROVIDER_REPOSITORY_DENIED", "Invocation repository is outside the provider allowlist.")
        action = invocation["action"]
        parameters = invocation["parameters"]

        if action == "github.branch.push":
            normalized = self._execute_branch_push(parameters)
        elif action == "github.pull_request.create":
            normalized = self._execute_pull_request_create(repository, parameters)
        elif action == "github.pull_request.merge":
            normalized = self._execute_pull_request_merge(repository, parameters)
        else:
            raise ActionGateError("PROVIDER_ACTION_UNSUPPORTED", f"real adapter does not implement {action}")

        return {
            "provider": "github",
            "provider_mode": "GH_CLI_EXTERNAL_WRITE",
            "action": action,
            "repository": repository,
            "result": normalized,
            "result_sha256": sha256_json(normalized),
            "executed_at": format_datetime(utc_now()),
        }
