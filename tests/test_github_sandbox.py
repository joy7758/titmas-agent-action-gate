from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

from titmas_action_gate.github_sandbox import exact_head_commit


class GithubSandboxTests(unittest.TestCase):
    def test_exact_head_commit_real_repo(self):
        with tempfile.TemporaryDirectory() as d:
            # Initialize a git repository and create a commit
            subprocess.run(["git", "-c", "init.defaultBranch=main", "init", d], check=True, capture_output=True)
            subprocess.run(["git", "-C", d, "config", "user.name", "Test User"], check=True, capture_output=True)
            subprocess.run(["git", "-C", d, "config", "user.email", "test@example.com"], check=True, capture_output=True)
            subprocess.run(["git", "-C", d, "commit", "--allow-empty", "-m", "Initial commit"], check=True, capture_output=True)

            # Get head commit manually for validation
            completed = subprocess.run(["git", "-C", d, "rev-parse", "HEAD"], check=True, capture_output=True, text=True)
            expected_commit = completed.stdout.strip()

            self.assertTrue(len(expected_commit) > 0)

            # Call function and assert
            actual_commit = exact_head_commit(d)
            self.assertEqual(expected_commit, actual_commit)

    @patch("titmas_action_gate.github_sandbox.subprocess.run")
    def test_exact_head_commit_mock(self, mock_run):
        mock_completed_process = MagicMock()
        mock_completed_process.stdout = "abc123def456\n"
        mock_run.return_value = mock_completed_process

        worktree = "/tmp/fake-repo"
        result = exact_head_commit(worktree)

        self.assertEqual("abc123def456", result)
        mock_run.assert_called_once_with(
            ["git", "-C", str(Path(worktree).resolve()), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )

    @patch("titmas_action_gate.github_sandbox.subprocess.run")
    def test_exact_head_commit_subprocess_error(self, mock_run):
        mock_run.side_effect = subprocess.CalledProcessError(1, ["git"])

        with self.assertRaises(subprocess.CalledProcessError):
            exact_head_commit("/tmp/fake-repo")

    @patch("titmas_action_gate.github_sandbox.subprocess.run")
    def test_exact_head_commit_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired(["git"], 10)

        with self.assertRaises(subprocess.TimeoutExpired):
            exact_head_commit("/tmp/fake-repo")


if __name__ == "__main__":
    unittest.main()
