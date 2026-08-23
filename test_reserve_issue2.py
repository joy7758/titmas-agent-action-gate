import sys
import unittest
import tempfile
import json
import shlex
from pathlib import Path

from titmas_action_gate.pr_gate import verify_pull_request
from tests.test_pr_gate import HEAD_A, PULL_REQUEST, REPOSITORY, EXECUTION_IDENTITY, ROOT, PullRequestGateTests

class TestReserve(PullRequestGateTests):
    def test_reserve_rollback_when_summary_exists(self):
        output = self.root / "preexisting-summary"
        output.mkdir()
        # Create summary.md so the second ExclusiveOutput fails
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

        # Verify that reserve() failed for output_directory, aborted first, and went to private directory
        trusted_receipt = json.loads(Path(result["receipt"]).read_text(encoding="utf-8"))
        self.assertTrue(trusted_receipt["output_integrity"]["relocated_to_private_directory"])
        # And importantly, output / "receipt.json" should NOT exist or be empty if it was aborted
        # Wait, ExclusiveOutput creates the file on `__init__`. When aborted, `__exit__` is called, but it deletes the file only if it was successfully opened. Oh wait, what does `abort_reserved` do?
        # It calls `reserved.__exit__(RuntimeError, RuntimeError("OUTPUT_RESERVATION_ABORTED"), None)`.
        # Which unlinks the file!
        self.assertFalse((output / "receipt.json").exists())

if __name__ == "__main__":
    unittest.main()
