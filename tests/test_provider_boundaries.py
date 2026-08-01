from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from titmas_action_gate.errors import ActionGateError
from titmas_action_gate.provider import GhCliProvider


class GhCliProviderBoundaryTests(unittest.TestCase):
    def test_remote_url_normalization_is_strict(self) -> None:
        normalize = GhCliProvider._normalized_github_repository
        self.assertEqual(normalize("https://github.com/owner/repo.git"), "owner/repo")
        self.assertEqual(normalize("git@github.com:owner/repo.git"), "owner/repo")
        self.assertEqual(normalize("ssh://git@github.com/owner/repo.git"), "owner/repo")
        self.assertIsNone(normalize("https://example.com/owner/repo.git"))
        self.assertIsNone(normalize("file:///tmp/repo.git"))

    def test_branch_push_denies_mismatched_origin_before_push(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "remote", "add", "origin", "https://github.com/other/repo.git"], check=True)
            provider = GhCliProvider("allowed/repo", allowed_worktree_root=root)
            invocation = {
                "action": "github.branch.push",
                "repository": "allowed/repo",
                "parameters": {"branch": "demo", "commit": "0" * 40},
            }
            with self.assertRaises(ActionGateError) as context:
                provider.execute(invocation)
            self.assertEqual(context.exception.code, "PROVIDER_REMOTE_DENIED")


if __name__ == "__main__":
    unittest.main()
