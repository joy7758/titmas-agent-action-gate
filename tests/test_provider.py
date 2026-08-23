from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from titmas_action_gate.errors import ActionGateError
from titmas_action_gate.provider import GhCliProvider, InMemoryGitHubProvider


class InMemoryGitHubProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = InMemoryGitHubProvider()
        self.base_invocation = {"repository": "owner/repo"}

    def test_pull_request_create_and_merge(self):
        # Create PR
        create_invocation = {
            **self.base_invocation,
            "action": "github.pull_request.create",
            "parameters": {"title": "Test PR", "head": "feature", "base": "main"},
        }
        create_result = self.provider.execute(create_invocation)
        self.assertEqual(create_result["action"], "github.pull_request.create")
        self.assertEqual(create_result["result"]["pull_number"], 1)
        self.assertEqual(create_result["result"]["state"], "OPEN")

        # Merge PR
        merge_invocation = {
            **self.base_invocation,
            "action": "github.pull_request.merge",
            "parameters": {"pull_number": 1, "merge_method": "squash"},
        }
        merge_result = self.provider.execute(merge_invocation)
        self.assertEqual(merge_result["action"], "github.pull_request.merge")
        self.assertEqual(merge_result["result"]["state"], "MERGED")

    def test_merge_non_existent_pr(self):
        merge_invocation = {
            **self.base_invocation,
            "action": "github.pull_request.merge",
            "parameters": {"pull_number": 999, "merge_method": "squash"},
        }
        with self.assertRaises(ActionGateError) as context:
            self.provider.execute(merge_invocation)
        self.assertEqual(context.exception.code, "PROVIDER_RESOURCE_NOT_FOUND")

    def test_branch_push(self):
        push_invocation = {
            **self.base_invocation,
            "action": "github.branch.push",
            "parameters": {"branch": "feature", "commit": "abc"},
        }
        result = self.provider.execute(push_invocation)
        self.assertEqual(result["result"]["state"], "RECORDED")

    def test_unsupported_action(self):
        unsupported_invocation = {
            **self.base_invocation,
            "action": "github.unknown.action",
            "parameters": {},
        }
        with self.assertRaises(ActionGateError) as context:
            self.provider.execute(unsupported_invocation)
        self.assertEqual(context.exception.code, "PROVIDER_ACTION_UNSUPPORTED")


class GhCliProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = GhCliProvider(allowed_repository="owner/repo")
        self.base_invocation = {"repository": "owner/repo"}

    def test_repository_denied(self):
        invocation = {
            "action": "github.pull_request.create",
            "repository": "other/repo",
            "parameters": {},
        }
        with self.assertRaises(ActionGateError) as context:
            self.provider.execute(invocation)
        self.assertEqual(context.exception.code, "PROVIDER_REPOSITORY_DENIED")

    def test_unsupported_action(self):
        invocation = {
            **self.base_invocation,
            "action": "github.unknown.action",
            "parameters": {},
        }
        with self.assertRaises(ActionGateError) as context:
            self.provider.execute(invocation)
        self.assertEqual(context.exception.code, "PROVIDER_ACTION_UNSUPPORTED")

    @patch("titmas_action_gate.provider.subprocess.run")
    def test_pull_request_create(self, mock_run):
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = '{"number": 42, "state": "open", "html_url": "https://github.com", "base": {"ref": "main"}, "head": {"ref": "feature"}}'
        mock_run.return_value = mock_process

        invocation = {
            **self.base_invocation,
            "action": "github.pull_request.create",
            "parameters": {"title": "Test PR", "head": "feature", "base": "main"},
        }
        result = self.provider.execute(invocation)
        self.assertEqual(result["result"]["pull_number"], 42)
        self.assertEqual(result["result"]["state"], "OPEN")

    @patch("titmas_action_gate.provider.subprocess.run")
    def test_pull_request_merge(self, mock_run):
        mock_process = MagicMock()
        mock_process.returncode = 0
        mock_process.stdout = '{"merged": true, "message": "Merged successfully", "sha": "abcdef"}'
        mock_run.return_value = mock_process

        invocation = {
            **self.base_invocation,
            "action": "github.pull_request.merge",
            "parameters": {"pull_number": 42, "merge_method": "squash"},
        }
        result = self.provider.execute(invocation)
        self.assertTrue(result["result"]["merged"])
        self.assertEqual(result["result"]["sha"], "abcdef")

    @patch("titmas_action_gate.provider.subprocess.run")
    def test_run_failure(self, mock_run):
        mock_process = MagicMock()
        mock_process.returncode = 1
        mock_process.stderr = "error message"
        mock_run.return_value = mock_process

        invocation = {
            **self.base_invocation,
            "action": "github.pull_request.create",
            "parameters": {"title": "Test PR", "head": "feature", "base": "main"},
        }
        with self.assertRaises(ActionGateError) as context:
            self.provider.execute(invocation)
        self.assertEqual(context.exception.code, "PROVIDER_CALL_FAILED")


if __name__ == "__main__":
    unittest.main()
