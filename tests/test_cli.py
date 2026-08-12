import unittest
from unittest.mock import MagicMock, patch

from titmas_action_gate.cli import validate_install
from titmas_action_gate.evidence import AGENT_EVIDENCE_OAP_SCHEMA_SHA256, AGENT_EVIDENCE_VERSION


class TestCli(unittest.TestCase):
    def setUp(self):
        patcher_schema_dir = patch("titmas_action_gate.cli.schema_directory")
        patcher_data_root = patch("titmas_action_gate.cli.data_root")
        patcher_version = patch("titmas_action_gate.cli.version")
        patcher_sha256 = patch("titmas_action_gate.cli.sha256_file")
        patcher_validate_template = patch("titmas_action_gate.cli.validate_agentteams_template")
        patcher_eval_fixtures = patch("titmas_action_gate.cli.evaluate_fixtures")
        patcher_wheel_sha256 = patch("titmas_action_gate.cli.AGENT_EVIDENCE_WHEEL_SHA256", "a" * 64)

        self.mock_schema_dir = patcher_schema_dir.start()
        self.mock_data_root = patcher_data_root.start()
        self.mock_version = patcher_version.start()
        self.mock_sha256 = patcher_sha256.start()
        self.mock_validate_template = patcher_validate_template.start()
        self.mock_eval_fixtures = patcher_eval_fixtures.start()
        self.mock_wheel_sha256 = patcher_wheel_sha256.start()

        self.addCleanup(patcher_schema_dir.stop)
        self.addCleanup(patcher_data_root.stop)
        self.addCleanup(patcher_version.stop)
        self.addCleanup(patcher_sha256.stop)
        self.addCleanup(patcher_validate_template.stop)
        self.addCleanup(patcher_eval_fixtures.stop)
        self.addCleanup(patcher_wheel_sha256.stop)

        # Setup default happy path
        self.mock_schema_dir.return_value = MagicMock()
        self.mock_data_root.return_value = MagicMock()
        self.mock_version.return_value = AGENT_EVIDENCE_VERSION
        self.mock_sha256.return_value = AGENT_EVIDENCE_OAP_SCHEMA_SHA256
        self.mock_validate_template.return_value = {"ok": True}
        self.mock_eval_fixtures.return_value = {"ok": True}

    def test_validate_install_success(self):
        result = validate_install()
        self.assertTrue(result["ok"])
        self.assertTrue(result["checks"]["agent_evidence_version"])
        self.assertTrue(result["checks"]["agent_evidence_wheel_pin_recorded"])
        self.assertTrue(result["checks"]["agent_evidence_oap_schema_hash"])
        self.assertEqual(result["checks"]["agentteams_template"], {"ok": True})
        self.assertEqual(result["checks"]["fixture_evaluation"], {"ok": True})

    def test_validate_install_version_mismatch(self):
        self.mock_version.return_value = "invalid-version"
        result = validate_install()
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["agent_evidence_version"])

    def test_validate_install_hash_mismatch(self):
        self.mock_sha256.return_value = "invalid-hash"
        result = validate_install()
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["agent_evidence_oap_schema_hash"])

    def test_validate_install_template_failed(self):
        self.mock_validate_template.return_value = {"ok": False, "error": "bad template"}
        result = validate_install()
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["agentteams_template"]["ok"])

    def test_validate_install_fixtures_failed(self):
        self.mock_eval_fixtures.return_value = {"ok": False, "cases": []}
        result = validate_install()
        self.assertFalse(result["ok"])
        self.assertFalse(result["checks"]["fixture_evaluation"]["ok"])


if __name__ == "__main__":
    unittest.main()
