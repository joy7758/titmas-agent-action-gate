from __future__ import annotations

import io
import json
import os
import shlex
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import timedelta
from pathlib import Path

import yaml

from titmas_action_gate.approval import ApprovalAuthority
from titmas_action_gate.canonical import format_datetime, sha256_json, utc_now
from titmas_action_gate.cli import main as cli_main
from titmas_action_gate.evidence import AGENT_EVIDENCE_VERSION, AGENT_EVIDENCE_WHEEL_SHA256, AgentEvidenceAdapter
from titmas_action_gate.policy import PolicyEngine
from titmas_action_gate.pr_gate import PUBLIC_EXIT_CODES, _missing_evidence_result, verify_pull_request

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "joy7758/titmas-merge-gate-sandbox"
PULL_REQUEST = 17
HEAD_A = "a" * 40
HEAD_B = "b" * 40
EXECUTION_IDENTITY = "github-actions:required-evidence-gate"
EVIDENCE_TYPES = ["SOURCE_PIN", "DIFF", "TEST_RESULT", "PULL_REQUEST_STATE"]
APPROVAL_KEY = "public-disposable-demo-key-material-0001"


class PullRequestGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-pr-gate-")
        self.root = Path(self.tempdir.name).resolve(strict=True)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def command(self, *, passes: bool = True) -> list[str]:
        return [sys.executable, "-c", f"raise SystemExit({0 if passes else 9})"]

    def request(self, head_sha: str, command: list[str]) -> dict:
        parameters = {
            "pull_request": PULL_REQUEST,
            "head_sha": head_sha,
            "execution_identity": EXECUTION_IDENTITY,
            "test_command": command,
        }
        return {
            "schema_version": "0.1.0",
            "request_id": f"aar-merge-gate-{head_sha[:12]}",
            "created_at": "2026-08-12T12:00:00Z",
            "requested_by": {"agent_id": "request-analyst", "team_id": "titmas-action-gate"},
            "action": "github.pull_request.merge",
            "target": {
                "provider": "github",
                "repository": REPOSITORY,
                "resource_ref": f"refs/pull/{PULL_REQUEST}/head@{head_sha}",
            },
            "parameters": parameters,
            "parameters_sha256": sha256_json(parameters),
            "evidence_requirements": EVIDENCE_TYPES,
            "uncertainty": [],
            "idempotency_key": f"merge-gate:{PULL_REQUEST}:{head_sha}",
        }

    def write_task(self, request: dict, name: str = "task.json") -> Path:
        path = self.root / name
        path.write_text(json.dumps(request, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def write_evidence(self, request: dict, name: str = "evidence.json") -> Path:
        adapter = AgentEvidenceAdapter(self.root)
        profile = adapter.build_profile(
            request,
            actor="evidence-verifier",
            phase="pr-check",
            operation_status="succeeded",
            output={"test_exit_code": 0, "head_sha": request["parameters"]["head_sha"]},
            evidence_types=EVIDENCE_TYPES,
        )
        return adapter.write_profile(profile, name)

    def verify(
        self,
        request: dict,
        command: list[str],
        *,
        evidence: Path | None = None,
        policy: str = "github-merge-gate-low-risk-demo.v0.1.json",
        approval: Path | None = None,
        current_head: str | None = None,
        output_name: str = "out",
        environment: dict[str, str] | None = None,
    ) -> tuple[dict, dict]:
        task = self.write_task(request, f"{output_name}-task.json")
        evidence_path = evidence or self.write_evidence(request, f"{output_name}-evidence.json")
        result = verify_pull_request(
            task_path=task,
            evidence_path=evidence_path,
            policy_path=ROOT / "policies" / policy,
            test_command=shlex.join(command),
            approval_path=approval,
            output_directory=self.root / output_name,
            repository=REPOSITORY,
            pull_request=PULL_REQUEST,
            head_sha=current_head or request["parameters"]["head_sha"],
            execution_identity=EXECUTION_IDENTITY,
            environment=environment or {},
        )
        receipt = json.loads((self.root / output_name / "receipt.json").read_text(encoding="utf-8"))
        return result, receipt

    def test_valid_low_risk_execution_is_pass(self) -> None:
        command = self.command()
        result, receipt = self.verify(self.request(HEAD_A, command), command, output_name="valid")
        self.assertEqual(result["state"], "PASS")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(receipt["decision"]["outcome"], "ALLOW")
        self.assertEqual(receipt["test_result"]["exit_code"], 0)
        self.assertEqual(receipt["commit_sha"], HEAD_A)
        self.assertEqual(receipt["evidence"]["status"], "VALID")
        self.assertTrue((self.root / "valid" / "summary.md").is_file())
        self.assertEqual(
            {
                "repository",
                "pull_request",
                "commit_sha",
                "task",
                "execution_identity",
                "test_result",
                "negative_checks",
                "authorization_scope",
                "evidence",
                "risk_class",
                "approval",
                "decision",
                "final_state",
                "reason_codes",
                "started_at",
                "finished_at",
                "tool",
                "policy",
                "execution_mode",
                "frozen_inputs",
                "action_configuration",
                "git_binding",
                "output_integrity",
            },
            set(receipt) - {"schema_version"},
        )

    def test_failing_test_is_fail_and_nonzero(self) -> None:
        command = self.command(passes=False)
        result, receipt = self.verify(self.request(HEAD_A, command), command, output_name="failed-test")
        self.assertEqual(result["state"], "FAIL")
        self.assertEqual(result["exit_code"], PUBLIC_EXIT_CODES["FAIL"])
        self.assertEqual(result["reason_codes"], ["TEST_COMMAND_FAILED"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertEqual(receipt["authorization_scope"]["policy_effect"], "DENY")

    def test_missing_evidence_is_incomplete_and_nonzero(self) -> None:
        command = self.command()
        missing = self.root / "missing-evidence.json"
        result, receipt = self.verify(self.request(HEAD_A, command), command, evidence=missing, output_name="missing")
        self.assertEqual(result["state"], "INCOMPLETE")
        self.assertEqual(result["exit_code"], PUBLIC_EXIT_CODES["INCOMPLETE"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")
        self.assertEqual(receipt["evidence"]["status"], "MISSING")

    def test_high_risk_without_approval_requires_review_and_nonzero(self) -> None:
        command = self.command()
        result, receipt = self.verify(
            self.request(HEAD_A, command),
            command,
            policy="github-demo-policy.v0.2.json",
            output_name="review",
        )
        self.assertEqual(result["state"], "REVIEW_REQUIRED")
        self.assertEqual(result["exit_code"], PUBLIC_EXIT_CODES["REVIEW_REQUIRED"])
        self.assertEqual(receipt["decision"]["outcome"], "REQUIRE_APPROVAL")
        self.assertIsNone(receipt["approval"]["reference"])

    def test_verified_high_risk_approval_rerun_is_pass(self) -> None:
        command = self.command()
        request = self.request(HEAD_A, command)
        task = self.write_task(request, "approved-task.json")
        evidence = self.write_evidence(request, "approved-evidence.json")
        checked_at = utc_now()
        policy_path = ROOT / "policies/github-demo-policy.v0.2.json"
        policy = PolicyEngine(policy_path).evaluate(request, evaluated_at=checked_at)
        approval = ApprovalAuthority(APPROVAL_KEY.encode()).create(
            request,
            policy,
            subject="human:demo-reviewer",
            identity_provider="public-demo-idp",
            decided_at=checked_at - timedelta(seconds=1),
        )
        approval_path = self.root / "approval.json"
        approval_path.write_text(json.dumps(approval, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        result = verify_pull_request(
            task_path=task,
            evidence_path=evidence,
            policy_path=policy_path,
            test_command=shlex.join(command),
            approval_path=approval_path,
            output_directory=self.root / "approved",
            repository=REPOSITORY,
            pull_request=PULL_REQUEST,
            head_sha=HEAD_A,
            execution_identity=EXECUTION_IDENTITY,
            environment={"TITMAS_APPROVAL_HMAC_KEY": APPROVAL_KEY},
        )
        receipt = json.loads((self.root / "approved/receipt.json").read_text(encoding="utf-8"))
        self.assertEqual(result["state"], "PASS")
        self.assertTrue(receipt["approval"]["verified"])
        self.assertEqual(receipt["decision"]["outcome"], "ALLOW")

    def test_commit_a_evidence_against_head_b_fails_before_test(self) -> None:
        command = self.command()
        request_a = self.request(HEAD_A, command)
        evidence_a = self.write_evidence(request_a, "commit-a-evidence.json")
        result, receipt = self.verify(
            request_a,
            command,
            evidence=evidence_a,
            current_head=HEAD_B,
            output_name="subject-mismatch",
        )
        self.assertEqual(result["state"], "FAIL")
        self.assertEqual(result["reason_codes"], ["EVIDENCE_SUBJECT_MISMATCH"])
        self.assertFalse(receipt["test_result"]["executed"])
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")

    def test_tampered_evidence_is_fail(self) -> None:
        command = self.command()
        request = self.request(HEAD_A, command)
        evidence = self.write_evidence(request, "tampered.json")
        payload = json.loads(evidence.read_text(encoding="utf-8"))
        payload["operation"]["description"] = "tampered after integrity"
        evidence.write_text(json.dumps(payload), encoding="utf-8")
        result, receipt = self.verify(request, command, evidence=evidence, output_name="tampered")
        self.assertEqual(result["state"], "FAIL")
        self.assertEqual(receipt["evidence"]["status"], "TAMPERED")
        self.assertEqual(receipt["decision"]["outcome"], "BLOCK")

    def test_test_command_mismatch_is_not_executed(self) -> None:
        bound = self.command()
        different = [sys.executable, "-c", "raise SystemExit(0)", "different"]
        result, receipt = self.verify(self.request(HEAD_A, bound), different, output_name="command-mismatch")
        self.assertEqual(result["state"], "FAIL")
        self.assertIn("TEST_COMMAND_BOUND", result["reason_codes"])
        self.assertFalse(receipt["test_result"]["executed"])

    def test_test_command_does_not_receive_approval_key(self) -> None:
        command = [
            sys.executable,
            "-c",
            "import os; raise SystemExit(9 if os.environ.get('TITMAS_APPROVAL_HMAC_KEY') else 0)",
        ]
        request = self.request(HEAD_A, command)
        result, receipt = self.verify(
            request,
            command,
            output_name="secret-isolation",
            environment={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "TITMAS_APPROVAL_HMAC_KEY": APPROVAL_KEY,
            },
        )
        self.assertEqual(result["state"], "PASS")
        self.assertEqual(receipt["test_result"]["exit_code"], 0)

    def test_action_metadata_exposes_required_bounded_inputs(self) -> None:
        action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
        self.assertEqual(action["name"], "TITMAS Evidence Gate")
        self.assertEqual(action["runs"]["using"], "composite")
        self.assertEqual(
            set(action["inputs"]),
            {"task", "evidence", "policy", "test-command", "approval", "execution-identity", "output-directory"},
        )

    def test_malformed_policy_fails_closed_and_still_writes_receipt(self) -> None:
        command = self.command()
        request = self.request(HEAD_A, command)
        task = self.write_task(request, "bad-policy-task.json")
        evidence = self.write_evidence(request, "bad-policy-evidence.json")
        bad_policy = self.root / "bad-policy.json"
        bad_policy.write_text('{"policy_id":"missing-rules"}\n', encoding="utf-8")
        output = self.root / "bad-policy-output"
        result = verify_pull_request(
            task_path=task,
            evidence_path=evidence,
            policy_path=bad_policy,
            test_command=shlex.join(command),
            output_directory=output,
            repository=REPOSITORY,
            pull_request=PULL_REQUEST,
            head_sha=HEAD_A,
            execution_identity=EXECUTION_IDENTITY,
            environment={},
        )
        self.assertEqual(result["state"], "FAIL")
        self.assertIn("INPUT_LOADING_AND_POLICY_EVALUATION", result["reason_codes"])
        self.assertTrue((output / "receipt.json").is_file())
        self.assertTrue((output / "summary.md").is_file())

    def test_existing_receipt_is_rejected_before_test_execution(self) -> None:
        output = self.root / "preexisting-output"
        output.mkdir()
        (output / "receipt.json").write_text("do-not-overwrite\n", encoding="utf-8")
        marker = self.root / "test-command-executed"
        command = [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).write_text('executed')"]
        request = self.request(HEAD_A, command)
        task = self.write_task(request, "preexisting-task.json")
        evidence = self.write_evidence(request, "preexisting-evidence.json")
        result = verify_pull_request(
            task_path=task,
            evidence_path=evidence,
            policy_path=ROOT / "policies/github-merge-gate-low-risk-demo.v0.1.json",
            test_command=shlex.join(command),
            output_directory=output,
            repository=REPOSITORY,
            pull_request=PULL_REQUEST,
            head_sha=HEAD_A,
            execution_identity=EXECUTION_IDENTITY,
            environment={},
        )
        self.assertEqual(result["state"], "FAIL")
        self.assertEqual(result["reason_codes"], ["GATE_OUTPUT_PATH_PREEXISTED"])
        self.assertNotEqual(Path(result["receipt"]), output / "receipt.json")
        trusted_receipt = json.loads(Path(result["receipt"]).read_text(encoding="utf-8"))
        self.assertEqual(trusted_receipt["decision"]["outcome"], "BLOCK")
        self.assertTrue(trusted_receipt["output_integrity"]["relocated_to_private_directory"])
        self.assertFalse(marker.exists())
        self.assertEqual((output / "receipt.json").read_text(encoding="utf-8"), "do-not-overwrite\n")


class MissingEvidenceResultTests(unittest.TestCase):
    def test_missing_evidence_result(self) -> None:
        request = {
            "request_id": "test-req-123",
            "action": "test-action",
            "target": {"repository": "test/repo", "resource_type": "pull_request", "resource_ref": "42", "provider": "github"},
            "parameters_sha256": "abcdef123456",
        }
        checked_at = utc_now()
        result = _missing_evidence_result(request, checked_at=checked_at)

        self.assertEqual(result["schema_version"], "0.1.0")
        self.assertEqual(result["request_id"], "test-req-123")
        self.assertEqual(result["request_binding"]["action"], "test-action")
        self.assertEqual(result["request_binding"]["provider"], "github")
        self.assertEqual(result["request_binding"]["repository"], "test/repo")
        self.assertEqual(result["request_binding"]["resource_ref"], "42")
        self.assertEqual(result["request_binding"]["parameters_sha256"], "abcdef123456")
        self.assertEqual(result["verifier"]["name"], "agent-evidence")
        self.assertEqual(result["verifier"]["version"], AGENT_EVIDENCE_VERSION)
        self.assertEqual(result["verifier"]["distribution_sha256"], AGENT_EVIDENCE_WHEEL_SHA256)
        self.assertEqual(result["status"], "MISSING")
        self.assertIsNone(result["bundle_sha256"])
        self.assertEqual(result["evidence_types"], [])
        self.assertEqual(result["checks"], [])
        self.assertEqual(result["verified_at"], format_datetime(checked_at))


class CliTests(PullRequestGateTests):
    def test_cli_returns_public_nonzero_exit_code_and_writes_outputs(self) -> None:
        command = self.command(passes=False)
        request = self.request(HEAD_A, command)
        task = self.write_task(request, "cli-task.json")
        evidence = self.write_evidence(request, "cli-evidence.json")
        output = self.root / "cli-output"
        with redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli_main(
                [
                    "verify-pr",
                    "--task",
                    str(task),
                    "--evidence",
                    str(evidence),
                    "--policy",
                    str(ROOT / "policies/github-merge-gate-low-risk-demo.v0.1.json"),
                    "--test-command",
                    shlex.join(command),
                    "--output-dir",
                    str(output),
                    "--repository",
                    REPOSITORY,
                    "--pull-request",
                    str(PULL_REQUEST),
                    "--head-sha",
                    HEAD_A,
                    "--execution-identity",
                    EXECUTION_IDENTITY,
                ]
            )
        self.assertEqual(raised.exception.code, PUBLIC_EXIT_CODES["FAIL"])
        self.assertTrue((output / "receipt.json").is_file())
        self.assertTrue((output / "summary.md").is_file())


    def test_reserve_rollback_when_summary_exists(self) -> None:
        output = self.root / "preexisting-summary"
        output.mkdir()
        (output / "summary.md").write_text("pre-existing\n", encoding="utf-8")

        command = [sys.executable, "-c", "raise SystemExit(0)"]
        request = self.request(HEAD_A, command)
        task = self.write_task(request, "preexisting-summary-task.json")
        evidence = self.write_evidence(request, "preexisting-summary-evidence.json")

        result = verify_pull_request(
            task_path=task,
            evidence_path=evidence,
            policy_path=ROOT / "policies/github-merge-gate-low-risk-demo.v0.1.json",
            test_command=shlex.join(command),
            output_directory=output,
            repository=REPOSITORY,
            pull_request=PULL_REQUEST,
            head_sha=HEAD_A,
            execution_identity=EXECUTION_IDENTITY,
            environment={},
        )

        trusted_receipt = json.loads(Path(result["receipt"]).read_text(encoding="utf-8"))
        self.assertTrue(trusted_receipt["output_integrity"]["relocated_to_private_directory"])
        self.assertFalse((output / "receipt.json").exists())


if __name__ == "__main__":
    unittest.main()
