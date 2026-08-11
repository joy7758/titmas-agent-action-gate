from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from titmas_action_gate.public_evidence import (
    PUBLIC_EVIDENCE_RELATIVE_PATH,
    RUNNER_RELATIVE_PATH,
    VALIDATOR_RELATIVE_PATH,
    workspace_content_provenance,
)


class TestWorkspaceContentProvenance(unittest.TestCase):
    @patch("titmas_action_gate.public_evidence.sha256_json")
    @patch("titmas_action_gate.public_evidence.sha256_file")
    @patch("pathlib.Path.is_file")
    @patch("subprocess.run")
    def test_workspace_content_provenance(
        self,
        mock_run: MagicMock,
        mock_is_file: MagicMock,
        mock_sha256_file: MagicMock,
        mock_sha256_json: MagicMock,
    ) -> None:
        # Set up mock git ls-files output
        mock_run.return_value.stdout = b"file1.txt\0file2.py\0" + PUBLIC_EVIDENCE_RELATIVE_PATH.encode("utf-8") + b"\0"

        # is_file always returns True for testing
        mock_is_file.return_value = True

        # Mock hashing functions
        def fake_sha256_file(path: Path) -> str:
            return f"hash_{path.name}"

        mock_sha256_file.side_effect = fake_sha256_file
        mock_sha256_json.return_value = "json_manifest_hash"

        root = Path("/fake/root")
        result = workspace_content_provenance(root)

        # Check git ls-files arguments
        mock_run.assert_called_once_with(
            ["git", "ls-files", "-co", "--exclude-standard", "-z"],
            cwd=root.resolve(),
            check=True,
            capture_output=True,
        )

        # Check that json manifest hash is present
        self.assertEqual(result["workspace_manifest_sha256"], "json_manifest_hash")

        # Check that expected hardcoded paths are hashed
        runner_path = root.resolve() / RUNNER_RELATIVE_PATH
        self.assertEqual(result["runner_sha256"], f"hash_{runner_path.name}")

        validator_path = root.resolve() / VALIDATOR_RELATIVE_PATH
        self.assertEqual(result["public_evidence_validator_sha256"], f"hash_{validator_path.name}")

        # Validate that PUBLIC_EVIDENCE_RELATIVE_PATH was excluded, but file1.txt and file2.py were checked
        # sha256_json should have been called with the manifest
        # manifest elements are sorted by path name
        expected_manifest = [
            {"path": "file1.txt", "sha256": "hash_file1.txt"},
            {"path": "file2.py", "sha256": "hash_file2.py"},
        ]
        mock_sha256_json.assert_called_once_with(expected_manifest)

if __name__ == "__main__":
    unittest.main()
