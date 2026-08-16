import unittest
from unittest.mock import MagicMock, patch

from titmas_action_gate.provider import GhCliProvider


class ProviderSecurityTests(unittest.TestCase):
    @patch("subprocess.run")
    @patch.object(GhCliProvider, "_validate_branch_push")
    def test_branch_push_uses_dash_dash_for_safety(self, mock_validate, mock_run):
        # We want to verify that the fix correctly uses `--` for branch push.
        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_run.return_value = mock_completed

        provider = GhCliProvider("allowed-repo", allowed_worktree_root="/tmp/fake-root")

        invocation = {
            "repository": "allowed-repo",
            "action": "github.branch.push",
            "parameters": {
                "branch": "main",
                "commit": "0" * 40,
            },
        }

        provider.execute(invocation)

        # Verify that subprocess.run was called with "--" before the refspec
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        self.assertIn("--", args)

        dash_index = args.index("--")
        refspec_index = args.index(f"{'0' * 40}:refs/heads/main")

        self.assertEqual(dash_index + 1, refspec_index, "The '--' separator must appear immediately before the refspec")


if __name__ == "__main__":
    unittest.main()
