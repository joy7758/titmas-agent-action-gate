from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import timedelta
from pathlib import Path

import yaml

from titmas_action_gate.approval import ApprovalAuthority
from titmas_action_gate.canonical import sha256_json, utc_now
from titmas_action_gate.evidence import AgentEvidenceAdapter
from titmas_action_gate.policy import PolicyEngine
from titmas_action_gate.pr_gate import PUBLIC_EXIT_CODES, verify_pull_request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "joy7758/titmas-merge-gate-sandbox"
PULL_REQUEST = 24
HEAD = "a" * 40
IDENTITY = "github-actions:titmas-evidence-gate"
EVIDENCE_TYPES = ["SOURCE_PIN", "DIFF", "TEST_RESULT", "PULL_REQUEST_STATE"]
APPROVAL_KEY = "security-regression-approval-key-0001"


class PullRequestGateSecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="titmas-pr-gate-security-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def request(head: str, command: list[str]) -> dict:
        parameters = {
            "pull_request": PULL_REQUEST,
            "head_sha": head,
            "execution_identity": IDENTITY,
            "test_command": command,
        }
        return {
            "schema_version": "0.1.0",
            "request_id": f"aar-security-{head[:12]}",
            "created_at": "2026-08-13T00:00:00Z",
            "requested_by": {"agent_id": "request-analyst", "team_id": "titmas-action-gate"},
            "action": "github.pull_request.merge",
            "target": {
                "provider": "github",
                "repository": REPOSITORY,
                "resource_ref": f"refs/pull/{PULL_REQUEST}/head@{head}",
            },
            "parameters": parameters,
            "parameters_sha256": sha256_json(parameters),
            "evidence_requirements": EVIDENCE_TYPES,
            "uncertainty": [],
            "idempotency_key": f"security:{PULL_REQUEST}:{head}",
        }

    @staticmethod
    def write_json(path: Path, value: dict) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def write_evidence(self, directory: Path, request: dict, name: str = "evidence.json") -> Path:
        adapter = AgentEvidenceAdapter(directory)
        profile = adapter.build_profile(
            request,
            actor="security-regression-evidence-producer",
            phase="pr-check",
            operation_status="succeeded",
            output={"test_exit_code": 0, "head_sha": request["parameters"]["head_sha"]},
            evidence_types=EVIDENCE_TYPES,
        )
        return adapter.write_profile(profile, name)

    def prepare(
        self,
        command: list[str],
        *,
        directory: Path | None = None,
        head: str = HEAD,
        high_risk: bool = False,
        approval: bool = False,
    ) -> dict:
        directory = directory or self.root
        request = self.request(head, command)
        task = self.write_json(directory / "task.json", request)
        evidence = self.write_evidence(directory, request)
        policy_source = ROOT / "policies" / (
            "github-demo-policy.v0.2.json" if high_risk else "github-merge-gate-low-risk-demo.v0.1.json"
        )
        policy = directory / "policy.json"
        policy.write_bytes(policy_source.read_bytes())
        approval_path = None
        environment: dict[str, str] = {}
        if approval:
            evaluated = PolicyEngine(policy).evaluate(request, evaluated_at=utc_now())
            approval_payload = ApprovalAuthority(APPROVAL_KEY.encode()).create(
                request,
                evaluated,
                subject="human:security-reviewer",
                identity_provider="test-idp",
                decided_at=utc_now() - timedelta(seconds=1),
            )
            approval_path = self.write_json(directory / "approval.json", approval_payload)
            environment["TITMAS_APPROVAL_HMAC_KEY"] = APPROVAL_KEY
        return {
            "request": request,
            "task": task,
            "evidence": evidence,
            "policy": policy,
            "approval": approval_path,
            "environment": environment,
        }

    def run_gate(
        self,
        prepared: dict,
        command: list[str],
        *,
        output_name: str,
        environment: dict[str, str] | None = None,
        workspace: Path | None = None,
        action_configuration: Path | None = None,
        action_root: Path | None = None,
        repository: str = REPOSITORY,
        head: str = HEAD,
    ) -> tuple[dict, dict, str]:
        output = self.root / output_name
        result = verify_pull_request(
            task_path=prepared["task"],
            evidence_path=prepared["evidence"],
            policy_path=prepared["policy"],
            approval_path=prepared["approval"],
            test_command=shlex.join(command),
            output_directory=output,
            repository=repository,
            pull_request=PULL_REQUEST,
            head_sha=head,
            execution_identity=IDENTITY,
            environment=environment if environment is not None else prepared["environment"],
            workspace=workspace,
            action_configuration_path=action_configuration,
            action_configuration_root=action_root,
        )
        receipt_path = Path(result["receipt"])
        summary_path = Path(result["summary"])
        receipt_text = receipt_path.read_text(encoding="utf-8")
        receipt = json.loads(receipt_text)
        self.assertTrue(summary_path.is_file())
        self.assertEqual(result["output_integrity"], "TRUSTED_CREATE_ONLY")
        self.assertEqual(result["receipt_sha256"], hashlib.sha256(receipt_path.read_bytes()).hexdigest())
        self.assertEqual(result["summary_sha256"], hashlib.sha256(summary_path.read_bytes()).hexdigest())
        return result, receipt, receipt_text + summary_path.read_text(encoding="utf-8")

    def assert_mutation_blocked(self, role: str, *, multiple: bool = False) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        prepared = self.prepare(command, high_risk=role == "approval", approval=role == "approval")
        paths = [prepared[role]]
        if multiple:
            paths.extend([prepared["evidence"], prepared["policy"]])
        script = "from pathlib import Path; " + "; ".join(
            f"Path({str(path)!r}).write_text('{{}}', encoding='utf-8')" for path in paths
        )
        mutation_command = [sys.executable, "-c", script]
        prepared["request"]["parameters"]["test_command"] = mutation_command
        prepared["request"]["parameters_sha256"] = sha256_json(prepared["request"]["parameters"])
        self.write_json(prepared["task"], prepared["request"])
        prepared["evidence"] = self.write_evidence(self.root, prepared["request"])
        if role == "approval":
            evaluated = PolicyEngine(prepared["policy"]).evaluate(prepared["request"], evaluated_at=utc_now())
            prepared["approval"] = self.write_json(
                self.root / "approval.json",
                ApprovalAuthority(APPROVAL_KEY.encode()).create(
                    prepared["request"],
                    evaluated,
                    subject="human:security-reviewer",
                    identity_provider="test-idp",
                    decided_at=utc_now() - timedelta(seconds=1),
                ),
            )
        result, receipt, _ = self.run_gate(prepared, mutation_command, output_name=f"mutate-{role}")
        self.assertEqual(result["state"], "FAIL")
        self.assertEqual(result["exit_code"], PUBLIC_EXIT_CODES["FAIL"])
        self.assertEqual(result["reason_codes"], ["GATE_INPUT_MUTATED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertTrue(receipt["frozen_inputs"][role]["mutated_during_test"])
        self.assertEqual(receipt["task"]["request_id"], prepared["request"]["request_id"])

    def test_task_mutation_fails_closed_with_frozen_request(self) -> None:
        self.assert_mutation_blocked("task")

    def test_evidence_mutation_fails_closed_with_frozen_verification(self) -> None:
        self.assert_mutation_blocked("evidence")

    def test_policy_mutation_fails_closed_with_frozen_evaluation(self) -> None:
        self.assert_mutation_blocked("policy")

    def test_approval_mutation_fails_closed_with_frozen_approval(self) -> None:
        self.assert_mutation_blocked("approval")

    def test_multiple_input_mutations_fail_closed(self) -> None:
        self.assert_mutation_blocked("task", multiple=True)

    def test_action_configuration_mutation_fails_closed(self) -> None:
        action = self.root / "action.yml"
        action.write_bytes((ROOT / "action.yml").read_bytes())
        mutation_command = [sys.executable, "-c", f"from pathlib import Path; Path({str(action)!r}).write_text('name: changed\\n')"]
        prepared = self.prepare(mutation_command)
        result, receipt, _ = self.run_gate(
            prepared,
            mutation_command,
            output_name="mutate-action",
            action_configuration=action,
        )
        self.assertEqual(result["reason_codes"], ["GATE_INPUT_MUTATED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertTrue(receipt["action_configuration"]["mutated_during_test"])

    def test_symlink_input_is_rejected_before_test(self) -> None:
        marker = self.root / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command)
        actual = prepared["evidence"]
        link = self.root / "evidence-link.json"
        link.symlink_to(actual)
        prepared["evidence"] = link
        result, receipt, _ = self.run_gate(prepared, command, output_name="symlink")
        self.assertEqual(result["reason_codes"], ["INPUT_SYMLINK_NOT_ALLOWED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())

    def test_normal_unmodified_inputs_pass(self) -> None:
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="normal")
        self.assertEqual(result["state"], "PASS", receipt["test_result"])
        self.assertEqual(receipt["decision"]["outcome"], "ALLOW")
        self.assertTrue(all(not item["mutated_during_test"] for item in receipt["frozen_inputs"].values()))

    def test_credentials_and_github_command_files_are_not_inherited_or_logged(self) -> None:
        sentinel = self.root / "github-env"
        sentinel.write_text("unchanged\n", encoding="utf-8")
        secret_values = ["fake-github-secret", "fake-aws-secret", "fake-oidc-secret", "fake-ssh-socket"]
        environment = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "LANG": "C.UTF-8",
            "GITHUB_TOKEN": secret_values[0],
            "AWS_SECRET_ACCESS_KEY": secret_values[1],
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": secret_values[2],
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://oidc.invalid",
            "SSH_AUTH_SOCK": secret_values[3],
            "KUBECONFIG": "/tmp/kubeconfig",
            "DOCKER_CONFIG": "/tmp/docker-config",
            "GOOGLE_APPLICATION_CREDENTIALS": "/tmp/google.json",
            "ALIBABA_CLOUD_ACCESS_KEY_ID": "fake-aliyun-id",
            "GITHUB_ENV": str(sentinel),
            "GITHUB_OUTPUT": str(self.root / "github-output"),
            "GITHUB_PATH": str(self.root / "github-path"),
        }
        forbidden = [key for key in environment if key not in {"PATH", "LANG"}]
        code = "import os; raise SystemExit(9 if any(name in os.environ for name in " + repr(forbidden) + ") else 0)"
        command = [sys.executable, "-c", code]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="credential-env", environment=environment)
        self.assertEqual(result["state"], "PASS")
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged\n")
        self.assertEqual(receipt["test_result"]["environment"]["policy_version"], "minimal-v1")
        self.assertTrue(set(forbidden).issubset(receipt["test_result"]["environment"]["removed_names"]))
        for secret in secret_values:
            self.assertNotIn(secret, text)

    def initialize_git_workspace(self) -> tuple[Path, str, str]:
        workspace = self.root / "workspace"
        workspace.mkdir()
        subprocess.run(["git", "init", "-q", workspace], check=True)
        subprocess.run(["git", "-C", workspace, "config", "user.name", "TITMAS test"], check=True)
        subprocess.run(["git", "-C", workspace, "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", workspace, "remote", "add", "origin", f"https://github.com/{REPOSITORY}.git"], check=True)
        tracked = workspace / "tracked.txt"
        tracked.write_text("one\n", encoding="utf-8")
        subprocess.run(["git", "-C", workspace, "add", "tracked.txt"], check=True)
        subprocess.run(["git", "-C", workspace, "commit", "-qm", "one"], check=True)
        first = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
        tracked.write_text("two\n", encoding="utf-8")
        subprocess.run(["git", "-C", workspace, "commit", "-qam", "two"], check=True)
        second = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
        return workspace, first, second

    @staticmethod
    def github_environment(workspace: Path) -> dict[str, str]:
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "GITHUB_ACTIONS": "true",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_WORKSPACE": str(workspace),
            "TITMAS_ACTION_CONFIG_PATH": str(ROOT / "action.yml"),
            "TITMAS_ACTION_ROOT": str(ROOT),
        }

    def test_current_head_change_during_test_fails_closed(self) -> None:
        workspace, first, second = self.initialize_git_workspace()
        command = ["git", "checkout", "--detach", first]
        prepared = self.prepare(command, directory=workspace, head=second)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="head-change",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=second,
        )
        self.assertEqual(result["reason_codes"], ["CURRENT_HEAD_CHANGED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(receipt["git_binding"]["head_sha"], first)

    def test_persisted_git_extraheader_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(
            ["git", "-C", workspace, "config", "http.https://github.com/.extraheader", "AUTHORIZATION: basic fake"],
            check=True,
        )
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, text = self.run_gate(
            prepared,
            command,
            output_name="git-extraheader",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())
        self.assertNotIn("AUTHORIZATION: basic fake", text)

    def test_persisted_git_credential_helper_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(["git", "-C", workspace, "config", "credential.helper", "store"], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="git-credential-helper",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertEqual(receipt["git_binding"]["credential_risk_categories"], ["CREDENTIAL_CONFIGURATION"])
        self.assertFalse(marker.exists())

    def test_worktree_extraheader_fails_before_test_without_leaking_value(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(["git", "-C", workspace, "config", "extensions.worktreeConfig", "true"], check=True)
        secret = "fake-worktree-extraheader-do-not-log"
        subprocess.run(["git", "-C", workspace, "config", "--worktree", "http.https://github.com/.extraheader", secret], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, text = self.run_gate(
            prepared,
            command,
            output_name="worktree-extraheader",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertIn("WORKTREE", receipt["git_binding"]["config_source_categories"])
        self.assertFalse(marker.exists())
        self.assertNotIn(secret, text)

    def test_worktree_credential_helper_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(["git", "-C", workspace, "config", "extensions.worktreeConfig", "true"], check=True)
        subprocess.run(["git", "-C", workspace, "config", "--worktree", "credential.helper", "store"], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="worktree-helper",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertEqual(receipt["git_binding"]["credential_risk_categories"], ["CREDENTIAL_CONFIGURATION"])
        self.assertFalse(marker.exists())

    def test_local_authenticated_http_proxy_fails_before_test_without_leaking_value(self) -> None:
        self._assert_local_git_configuration_risk(
            "http.proxy",
            "https://diagnostic:fake-proxy-password@proxy.invalid",
            "HTTP_PROXY_CONFIGURATION",
        )

    def test_worktree_client_key_file_fails_before_test_without_leaking_value(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(["git", "-C", workspace, "config", "extensions.worktreeConfig", "true"], check=True)
        secret_path = "/private/diagnostic/fake-client-key.pem"
        subprocess.run(["git", "-C", workspace, "config", "--worktree", "http.sslKey", secret_path], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, text = self.run_gate(
            prepared,
            command,
            output_name="worktree-client-key",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertIn("HTTP_CLIENT_CREDENTIAL_FILE", receipt["git_binding"]["credential_risk_categories"])
        self.assertFalse(marker.exists())
        self.assertNotIn(secret_path, text)

    def test_included_cookie_file_fails_before_test_without_leaking_value(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        included = workspace / ".git" / "included-cookie-config"
        secret_path = "/private/diagnostic/fake-cookie-file"
        included.write_text(f"[http]\n\tcookieFile = {secret_path}\n", encoding="utf-8")
        subprocess.run(["git", "-C", workspace, "config", "include.path", str(included)], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, text = self.run_gate(
            prepared,
            command,
            output_name="included-cookie-file",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertEqual(
            receipt["git_binding"]["credential_risk_categories"],
            ["CONFIG_INCLUDE", "HTTP_COOKIE_FILE"],
        )
        self.assertFalse(marker.exists())
        self.assertNotIn(secret_path, text)

    def test_included_git_configuration_risk_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        included = workspace / ".git" / "included-security-config"
        included.write_text("[core]\n\tsshCommand = diagnostic-command\n", encoding="utf-8")
        subprocess.run(["git", "-C", workspace, "config", "include.path", str(included)], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="included-git-config",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertEqual(receipt["git_binding"]["credential_risk_categories"], ["CONFIG_INCLUDE", "SSH_COMMAND"])
        self.assertFalse(marker.exists())

    def _assert_local_git_configuration_risk(self, key: str, value: str, expected_category: str) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(["git", "-C", workspace, "config", key, value], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, text = self.run_gate(
            prepared,
            command,
            output_name=f"git-risk-{expected_category.lower()}",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertIn(expected_category, receipt["git_binding"]["credential_risk_categories"])
        self.assertFalse(marker.exists())
        self.assertNotIn(value, text)

    def test_core_ssh_command_fails_before_test(self) -> None:
        self._assert_local_git_configuration_risk("core.sshCommand", "diagnostic-ssh-command", "SSH_COMMAND")

    def test_url_rewrite_fails_before_test(self) -> None:
        self._assert_local_git_configuration_risk("url.https://example.invalid/.insteadOf", "git@example.invalid:", "URL_REWRITE")

    def test_authenticated_remote_url_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        secret = "fake-password-do-not-log"
        subprocess.run(["git", "-C", workspace, "remote", "set-url", "origin", f"https://diagnostic:{secret}@github.com/{REPOSITORY}.git"], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, text = self.run_gate(
            prepared,
            command,
            output_name="authenticated-remote",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertIn("AUTHENTICATED_REMOTE_URL", receipt["git_binding"]["credential_risk_categories"])
        self.assertFalse(marker.exists())
        self.assertNotIn(secret, text)

    def test_local_git_configuration_mutation_during_test_fails_closed(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        command = ["git", "config", "diagnostic.changed", "true"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="local-config-mutation",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["GIT_SECURITY_CONFIGURATION_MUTATED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        checks = {item["check_id"]: item["passed"] for item in receipt["negative_checks"]}
        self.assertFalse(checks["GIT_SECURITY_CONFIGURATION_MUTATED_DURING_TEST"])

    def test_include_if_configuration_risk_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        included = workspace / ".git" / "conditional-security-config"
        included.write_text("[credential]\n\thelper = store\n", encoding="utf-8")
        subprocess.run(["git", "-C", workspace, "config", f"includeIf.gitdir:{workspace}/.path", str(included)], check=True)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="include-if-config",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["PERSISTED_GIT_CREDENTIAL_DETECTED"])
        self.assertIn("CONFIG_INCLUDE", receipt["git_binding"]["credential_risk_categories"])
        self.assertFalse(marker.exists())

    def test_worktree_git_configuration_mutation_during_test_fails_closed(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        subprocess.run(["git", "-C", workspace, "config", "extensions.worktreeConfig", "true"], check=True)
        command = ["git", "config", "--worktree", "diagnostic.changed", "true"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="worktree-config-mutation",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["GIT_SECURITY_CONFIGURATION_MUTATED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")

    def test_pull_request_target_is_rejected_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        environment = self.github_environment(workspace)
        environment["GITHUB_EVENT_NAME"] = "pull_request_target"
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="pull-request-target",
            environment=environment,
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["UNTRUSTED_EVENT_TYPE"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())

    def test_github_pull_request_mode_with_exact_head_and_no_credentials_passes(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="github-normal",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["state"], "PASS")
        self.assertEqual(receipt["execution_mode"], "GITHUB_PULL_REQUEST")
        self.assertTrue(receipt["git_binding"]["head_matches_context"])

    def _assert_preexisting_tracked_state_blocked(self, mutate, output_name: str) -> dict:
        workspace, _, head = self.initialize_git_workspace()
        mutate(workspace)
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name=output_name,
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["DIRTY_TRACKED_EXECUTION_BASELINE"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(receipt["test_result"]["executed"])
        self.assertNotEqual(result["exit_code"], 0)
        self.assertFalse(marker.exists())
        return receipt

    def test_preexisting_unstaged_tracked_change_fails_before_test(self) -> None:
        self._assert_preexisting_tracked_state_blocked(
            lambda workspace: (workspace / "tracked.txt").write_text("dirty\n"), "dirty-unstaged"
        )

    def test_preexisting_staged_tracked_change_fails_before_test(self) -> None:
        def mutate(workspace: Path) -> None:
            (workspace / "tracked.txt").write_text("dirty\n")
            subprocess.run(["git", "-C", workspace, "add", "tracked.txt"], check=True)

        self._assert_preexisting_tracked_state_blocked(mutate, "dirty-staged")

    def test_preexisting_tracked_delete_fails_before_test(self) -> None:
        self._assert_preexisting_tracked_state_blocked(lambda workspace: (workspace / "tracked.txt").unlink(), "dirty-delete")

    def test_preexisting_tracked_rename_fails_before_test(self) -> None:
        self._assert_preexisting_tracked_state_blocked(
            lambda workspace: (workspace / "tracked.txt").rename(workspace / "renamed.txt"), "dirty-rename"
        )

    @unittest.skipIf(os.name == "nt", "POSIX executable mode is required")
    def test_preexisting_tracked_type_or_mode_change_fails_before_test(self) -> None:
        self._assert_preexisting_tracked_state_blocked(
            lambda workspace: (workspace / "tracked.txt").chmod(0o755), "dirty-mode-change"
        )

    def test_dirty_submodule_fails_before_test(self) -> None:
        workspace, _, _ = self.initialize_git_workspace()
        source = self.root / "submodule-source"
        source.mkdir()
        subprocess.run(["git", "init", "-q", source], check=True)
        subprocess.run(["git", "-C", source, "config", "user.name", "TITMAS test"], check=True)
        subprocess.run(["git", "-C", source, "config", "user.email", "test@example.invalid"], check=True)
        (source / "submodule.txt").write_text("clean\n", encoding="utf-8")
        subprocess.run(["git", "-C", source, "add", "submodule.txt"], check=True)
        subprocess.run(["git", "-C", source, "commit", "-qm", "submodule"], check=True)
        subprocess.run(
            ["git", "-c", "protocol.file.allow=always", "-C", workspace, "submodule", "add", "-q", str(source), "vendor/submodule"],
            check=True,
        )
        subprocess.run(["git", "-C", workspace, "commit", "-qam", "add submodule"], check=True)
        head = subprocess.check_output(["git", "-C", workspace, "rev-parse", "HEAD"], text=True).strip()
        (workspace / "vendor/submodule/submodule.txt").write_text("dirty\n", encoding="utf-8")
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="dirty-submodule",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["DIRTY_TRACKED_EXECUTION_BASELINE"])
        self.assertFalse(receipt["test_result"]["executed"])
        self.assertFalse(marker.exists())

    def test_declared_untracked_gate_inputs_remain_compatible(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="declared-untracked-inputs",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["state"], "PASS")
        self.assertGreaterEqual(receipt["git_binding"]["unexpected_untracked_count"], 0)

    def test_declared_untracked_outputs_inside_workspace_remain_compatible(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        command = [sys.executable, "-c", "raise SystemExit(0)"]
        prepared = self.prepare(command, directory=workspace, head=head)
        output = workspace / "declared-output"
        result = verify_pull_request(
            task_path=prepared["task"],
            evidence_path=prepared["evidence"],
            policy_path=prepared["policy"],
            test_command=shlex.join(command),
            output_directory=output,
            repository=REPOSITORY,
            pull_request=PULL_REQUEST,
            head_sha=head,
            execution_identity=IDENTITY,
            environment=self.github_environment(workspace),
            workspace=workspace,
            action_configuration_path=ROOT / "action.yml",
            action_configuration_root=ROOT,
        )
        self.assertEqual(result["state"], "PASS")

    def test_undeclared_untracked_input_fails_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        (workspace / "undeclared-input").write_text("unexpected\n", encoding="utf-8")
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="undeclared-untracked",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["UNDECLARED_UNTRACKED_EXECUTION_INPUTS"])
        self.assertFalse(receipt["test_result"]["executed"])
        self.assertFalse(marker.exists())

    def test_github_mode_requires_action_configuration_and_root(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        environment = self.github_environment(workspace)
        environment.pop("TITMAS_ACTION_CONFIG_PATH")
        environment.pop("TITMAS_ACTION_ROOT")
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="missing-action-configuration",
            environment=environment,
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["state"], "FAIL")
        self.assertIn("ACTION_CONFIGURATION_REQUIRED", result["reason_codes"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())

    def test_github_mode_rejects_symlinked_action_root(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        installed = self.root / "installed-action"
        installed.mkdir()
        (installed / "action.yml").write_bytes((ROOT / "action.yml").read_bytes())
        linked = self.root / "linked-action"
        linked.symlink_to(installed, target_is_directory=True)
        environment = self.github_environment(workspace)
        environment["TITMAS_ACTION_CONFIG_PATH"] = str(linked / "action.yml")
        environment["TITMAS_ACTION_ROOT"] = str(linked)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="symlinked-action-root",
            environment=environment,
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["INPUT_SYMLINK_NOT_ALLOWED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())

    def test_github_mode_rejects_action_configuration_path_escape(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        installed = self.root / "bounded-action"
        installed.mkdir()
        outside = self.root / "outside-action.yml"
        outside.write_bytes((ROOT / "action.yml").read_bytes())
        environment = self.github_environment(workspace)
        environment["TITMAS_ACTION_CONFIG_PATH"] = str(outside)
        environment["TITMAS_ACTION_ROOT"] = str(installed)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="escaped-action-configuration",
            environment=environment,
            workspace=workspace,
            head=head,
        )
        self.assertIn(result["reason_codes"][0], {"ACTION_CONFIGURATION_PATH_MISMATCH", "INPUT_SYMLINK_NOT_ALLOWED"})
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())

    def _assert_git_mutation_blocked(self, command: list[str], output_name: str) -> dict:
        workspace, _, head = self.initialize_git_workspace()
        prepared = self.prepare(command, directory=workspace, head=head)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name=output_name,
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["GIT_STATE_CHANGED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        return receipt

    def test_tracked_worktree_mutation_fails_closed(self) -> None:
        command = [sys.executable, "-c", "from pathlib import Path; Path('tracked.txt').write_text('changed\\n')"]
        receipt = self._assert_git_mutation_blocked(command, "tracked-worktree-mutation")
        checks = {item["check_id"]: item["passed"] for item in receipt["negative_checks"]}
        self.assertFalse(checks["GIT_WORKTREE_UNCHANGED_DURING_TEST"])

    def test_staged_index_mutation_fails_closed(self) -> None:
        command = ["git", "add", "task.json"]
        receipt = self._assert_git_mutation_blocked(command, "staged-index-mutation")
        checks = {item["check_id"]: item["passed"] for item in receipt["negative_checks"]}
        self.assertFalse(checks["GIT_INDEX_UNCHANGED_DURING_TEST"])

    def test_untracked_file_mutation_fails_closed(self) -> None:
        command = [sys.executable, "-c", "from pathlib import Path; Path('new-untracked').write_text('x')"]
        receipt = self._assert_git_mutation_blocked(command, "untracked-mutation")
        checks = {item["check_id"]: item["passed"] for item in receipt["negative_checks"]}
        self.assertFalse(checks["GIT_STATUS_UNCHANGED_DURING_TEST"])

    def test_git_post_check_does_not_resolve_a_replaced_path_entry(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        malicious_bin = workspace / "malicious-bin"
        malicious_bin.mkdir()
        fake_git = malicious_bin / "git"
        command = [
            sys.executable,
            "-c",
            "from pathlib import Path; "
            f"p=Path({str(fake_git)!r}); "
            "p.write_text('#!/bin/sh\\nexit 0\\n'); "
            "p.chmod(0o755); Path('tracked.txt').write_text('changed\\n')",
        ]
        prepared = self.prepare(command, directory=workspace, head=head)
        environment = self.github_environment(workspace)
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="git-path-replacement",
            environment=environment,
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["GIT_STATE_CHANGED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertEqual(len(receipt["git_binding"]["git_executable"]["sha256"]), 64)
        self.assertTrue(receipt["git_binding"]["git_executable"]["unchanged_after_test"])

    def test_test_cannot_replace_trusted_receipt_or_summary(self) -> None:
        output = self.root / "output-path-takeover"
        fake_receipt = output / "receipt.json"
        fake_summary = output / "summary.md"
        script = (
            "from pathlib import Path; "
            f"r=Path({str(fake_receipt)!r}); s=Path({str(fake_summary)!r}); "
            "r.unlink(); s.unlink(); "
            "r.write_text('{\"final_state\":\"PASS\"}'); s.write_text('FAKE PASS')"
        )
        command = [sys.executable, "-c", script]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="output-path-takeover")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_IDENTITY_CHANGED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]), fake_receipt)
        self.assertTrue(receipt["output_integrity"]["relocated_to_private_directory"])
        self.assertNotIn("FAKE PASS", text)

    def test_output_parent_rename_and_symlink_replacement_fails_closed(self) -> None:
        output = self.root / "parent-replacement"
        moved = self.root / "attacker-selected-parent"
        script = (
            "from pathlib import Path; "
            f"source=Path({str(output)!r}); moved=Path({str(moved)!r}); "
            "source.rename(moved); source.symlink_to(moved, target_is_directory=True)"
        )
        command = [sys.executable, "-c", script]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="parent-replacement")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_IDENTITY_CHANGED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]).resolve(), (moved / "receipt.json").resolve())
        self.assertTrue(receipt["output_integrity"]["relocated_to_private_directory"])

    def test_output_ancestor_rename_and_symlink_replacement_fails_closed(self) -> None:
        ancestor = self.root / "output-ancestor"
        moved = self.root / "attacker-selected-ancestor"
        output_name = "output-ancestor/nested-output"
        script = (
            "from pathlib import Path; "
            f"source=Path({str(ancestor)!r}); moved=Path({str(moved)!r}); "
            "source.rename(moved); source.symlink_to(moved, target_is_directory=True)"
        )
        command = [sys.executable, "-c", script]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name=output_name)
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_IDENTITY_CHANGED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]).resolve(), (moved / "nested-output/receipt.json").resolve())
        self.assertTrue(receipt["output_integrity"]["relocated_to_private_directory"])

    def test_in_place_reserved_summary_write_relocates_trusted_fail_output(self) -> None:
        output = self.root / "in-place-summary-write"
        target = output / "summary.md"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(target)!r}).write_text('UNTRUSTED')"]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="in-place-summary-write")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_CONTENT_MUTATED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["summary"]), target)
        self.assertTrue(receipt["output_integrity"]["relocated_to_private_directory"])
        self.assertNotIn("UNTRUSTED", text)

    def test_in_place_reserved_receipt_append_relocates_trusted_fail_output(self) -> None:
        output = self.root / "in-place-receipt-append"
        target = output / "receipt.json"
        command = [sys.executable, "-c", f"from pathlib import Path; p=Path({str(target)!r}); p.write_bytes(p.read_bytes()+b'UNTRUSTED')"]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="in-place-receipt-append")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_CONTENT_MUTATED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]), target)
        self.assertNotIn("UNTRUSTED", text)

    def test_both_reserved_outputs_pwrite_relocates_trusted_fail_output(self) -> None:
        output = self.root / "both-pwrite"
        receipt_target = output / "receipt.json"
        summary_target = output / "summary.md"
        code = (
            "import os; "
            f"r=os.open({str(receipt_target)!r},os.O_WRONLY); s=os.open({str(summary_target)!r},os.O_WRONLY); "
            "os.pwrite(r,b'UNTRUSTED',0); os.pwrite(s,b'UNTRUSTED',0); os.close(r); os.close(s)"
        )
        command = [sys.executable, "-c", code]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="both-pwrite")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_CONTENT_MUTATED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]), receipt_target)
        self.assertNotEqual(Path(result["summary"]), summary_target)
        self.assertNotIn("UNTRUSTED", text)

    def test_truncate_then_rewrite_reserved_output_is_detected(self) -> None:
        output = self.root / "truncate-rewrite"
        target = output / "summary.md"
        command = [sys.executable, "-c", f"from pathlib import Path; p=Path({str(target)!r}); p.write_text('X'); p.write_text('Y')"]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="truncate-rewrite")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_CONTENT_MUTATED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")

    def test_write_then_truncate_reserved_output_back_to_empty_is_detected(self) -> None:
        output = self.root / "write-truncate-empty"
        target = output / "summary.md"
        command = [
            sys.executable,
            "-c",
            f"from pathlib import Path; p=Path({str(target)!r}); p.write_bytes(b'X'); p.write_bytes(b'')",
        ]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="write-truncate-empty")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_CONTENT_MUTATED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["summary"]), target)

    def test_reserved_output_hard_link_mutation_is_detected(self) -> None:
        output = self.root / "hard-link-output"
        target = output / "receipt.json"
        linked = self.root / "reserved-output-hard-link"
        command = [sys.executable, "-c", f"import os; os.link({str(target)!r}, {str(linked)!r})"]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="hard-link-output")
        self.assertEqual(result["reason_codes"], ["RESERVED_OUTPUT_CONTENT_MUTATED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]), target)

    def test_preexisting_output_path_blocks_before_test_and_returns_trusted_receipt(self) -> None:
        output = self.root / "preexisting-output-security"
        output.mkdir()
        fake = output / "receipt.json"
        fake.write_text('{"final_state":"PASS"}', encoding="utf-8")
        marker = self.root / "preexisting-output-executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="preexisting-output-security")
        self.assertEqual(result["reason_codes"], ["GATE_OUTPUT_PATH_PREEXISTED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())
        self.assertNotEqual(Path(result["receipt"]), fake)
        self.assertNotIn('{"final_state":"PASS"}', text)

    def test_github_input_outside_workspace_is_rejected_before_test(self) -> None:
        workspace, _, head = self.initialize_git_workspace()
        marker = workspace / "executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"]
        prepared = self.prepare(command, directory=workspace, head=head)
        outside = self.root / "outside-policy.json"
        outside.write_bytes(prepared["policy"].read_bytes())
        prepared["policy"] = outside
        result, receipt, _ = self.run_gate(
            prepared,
            command,
            output_name="input-out-of-scope",
            environment=self.github_environment(workspace),
            workspace=workspace,
            head=head,
        )
        self.assertEqual(result["reason_codes"], ["INPUT_PATH_OUT_OF_SCOPE"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertFalse(marker.exists())

    def test_action_metadata_passes_trusted_event_workspace_and_configuration(self) -> None:
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        verify_step = next(step for step in action["runs"]["steps"] if step.get("id") == "verify")
        self.assertEqual(verify_step["env"]["TITMAS_CURRENT_EVENT_NAME"], "${{ github.event_name }}")
        self.assertEqual(verify_step["env"]["TITMAS_WORKSPACE"], "${{ github.workspace }}")
        self.assertEqual(verify_step["env"]["TITMAS_ACTION_CONFIG_PATH"], "${{ github.action_path }}/action.yml")
        self.assertEqual(verify_step["env"]["TITMAS_ACTION_ROOT"], "${{ github.action_path }}")
        self.assertIn("--action-configuration", verify_step["run"])
        self.assertIn("--action-root", verify_step["run"])

    def test_output_limit_fails_closed_without_recording_output(self) -> None:
        command = [sys.executable, "-c", "import os; os.write(1, b'x' * (16 * 1024 * 1024))"]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="output-limit")
        self.assertEqual(result["reason_codes"], ["TEST_OUTPUT_LIMIT_EXCEEDED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertTrue(receipt["test_result"]["output_limit_exceeded"])
        self.assertLessEqual(receipt["test_result"]["stdout_bytes"], 1024 * 1024 + 1)
        self.assertNotIn("x" * 1024, text)

    def test_stdout_and_stderr_share_one_total_output_budget(self) -> None:
        command = [sys.executable, "-c", "import os; os.write(1,b'x'*(600*1024)); os.write(2,b'y'*(600*1024))"]
        prepared = self.prepare(command)
        result, receipt, text = self.run_gate(prepared, command, output_name="combined-output-limit")
        self.assertEqual(result["reason_codes"], ["TEST_OUTPUT_LIMIT_EXCEEDED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertLessEqual(receipt["test_result"]["combined_output_bytes"], 1024 * 1024 + 1)
        self.assertEqual(receipt["test_result"]["exit_code"], 125)
        self.assertNotIn("x" * 1024, text)
        self.assertNotIn("y" * 1024, text)

    def test_exact_total_output_budget_is_allowed(self) -> None:
        command = [sys.executable, "-c", "import os; os.write(1,b'x'*(512*1024)); os.write(2,b'y'*(512*1024))"]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="exact-output-limit")
        self.assertEqual(result["state"], "PASS")
        self.assertEqual(receipt["test_result"]["combined_output_bytes"], 1024 * 1024)
        self.assertFalse(receipt["test_result"]["output_limit_exceeded"])

    def test_total_output_budget_plus_one_fails_closed(self) -> None:
        command = [sys.executable, "-c", "import os; os.write(1,b'x'*(512*1024)); os.write(2,b'y'*(512*1024+1))"]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="output-limit-plus-one")
        self.assertEqual(result["reason_codes"], ["TEST_OUTPUT_LIMIT_EXCEEDED"])
        self.assertEqual(receipt["test_result"]["combined_output_bytes"], 1024 * 1024 + 1)

    def test_stderr_only_output_limit_fails_closed(self) -> None:
        command = [sys.executable, "-c", "import os; os.write(2,b'y'*(1024*1024+1))"]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="stderr-output-limit")
        self.assertEqual(result["reason_codes"], ["TEST_OUTPUT_LIMIT_EXCEEDED"])
        self.assertEqual(receipt["test_result"]["combined_output_bytes"], 1024 * 1024 + 1)

    def test_concurrent_output_budget_race_is_bounded(self) -> None:
        code = (
            "import os,threading,time; f=lambda n:[os.write(n,b'x'*4096) for _ in range(200)]; "
            "a=threading.Thread(target=f,args=(1,)); b=threading.Thread(target=f,args=(2,)); "
            "a.start(); b.start(); a.join(); b.join(); time.sleep(60)"
        )
        command = [sys.executable, "-c", code]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="concurrent-output-limit")
        self.assertEqual(result["reason_codes"], ["TEST_OUTPUT_LIMIT_EXCEEDED"])
        self.assertLessEqual(receipt["test_result"]["combined_output_bytes"], 1024 * 1024 + 1)
        self.assertEqual(receipt["test_result"]["process_group_cleanup"], "COMPLETE")

    @unittest.skipUnless(hasattr(os, "killpg"), "POSIX process groups required")
    def test_background_process_group_is_cleaned_up(self) -> None:
        pid_path = self.root / "child.pid"
        code = (
            "import pathlib, subprocess, sys; "
            "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
            f"pathlib.Path({str(pid_path)!r}).write_text(str(child.pid))"
        )
        command = [sys.executable, "-c", code]
        prepared = self.prepare(command)
        result, receipt, _ = self.run_gate(prepared, command, output_name="process-group")
        self.assertEqual(result["state"], "PASS", receipt["test_result"])
        self.assertEqual(receipt["test_result"]["process_group_cleanup"], "COMPLETE")
        child_pid = int(pid_path.read_text(encoding="utf-8"))
        for _ in range(50):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            self.fail("background child survived process-group cleanup")


if __name__ == "__main__":
    unittest.main()
