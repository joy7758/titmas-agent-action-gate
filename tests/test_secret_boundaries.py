from __future__ import annotations

import json
import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SecretBoundaryTests(unittest.TestCase):
    @staticmethod
    def candidate_commit_files() -> list[Path]:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        return [ROOT / item.decode("utf-8") for item in result.stdout.split(b"\0") if item]

    def test_no_secret_file_shape_is_tracked(self) -> None:
        forbidden_names = {".env", ".env.local", "credentials.json", "secrets.json"}
        forbidden_suffixes = {".pem", ".key", ".p12", ".pfx"}
        for path in self.candidate_commit_files():
            relative = path.relative_to(ROOT)
            self.assertNotIn(relative.name, forbidden_names, relative)
            self.assertNotIn(relative.suffix.lower(), forbidden_suffixes, relative)

    def test_no_live_key_shape_is_present_in_tracked_text(self) -> None:
        patterns = [
            re.compile(r"LTAI[0-9A-Za-z]{16,}"),
            re.compile(r"AIza[0-9A-Za-z_-]{24,}"),
            re.compile(r"sk-[0-9A-Za-z]{24,}"),
            re.compile("BEGIN " + "PRIVATE KEY"),
        ]
        findings: list[str] = []
        for path in self.candidate_commit_files():
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for pattern in patterns:
                for match in pattern.findall(text):
                    if "X" not in match and "example" not in match.lower():
                        findings.append(f"{path.relative_to(ROOT)}:{pattern.pattern}")
        self.assertEqual(findings, [])

    def test_known_secret_history_scan_receipt_is_sanitized_and_passed(self) -> None:
        receipt = json.loads(
            (ROOT / "demo/evidence/known-secret-git-history-scan-20260802.json").read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["status"], "VALID_NO_KNOWN_SECRET_MATCH")
        self.assertGreater(receipt["known_secret_source_count"], 0)
        self.assertGreater(receipt["git_history_commit_count"], 0)
        self.assertEqual(receipt["git_history_secret_match_count"], 0)
        self.assertEqual(receipt["candidate_secret_match_count"], 0)
        self.assertEqual(receipt["scan_error_count"], 0)
        self.assertFalse(receipt["secret_values_retained"])
        self.assertFalse(receipt["secret_value_digests_retained"])
        self.assertFalse(receipt["matching_content_retained"])


if __name__ == "__main__":
    unittest.main()
