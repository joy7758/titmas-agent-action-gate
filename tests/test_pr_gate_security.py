from __future__ import annotations

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
        self.assertEqual(result["reason_codes"], ["GATE_OUTPUT_PATH_MUTATED_DURING_TEST"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertNotEqual(Path(result["receipt"]), fake_receipt)
        self.assertTrue(receipt["output_integrity"]["relocated_to_private_directory"])
        self.assertNotIn("FAKE PASS", text)

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
