import pytest
from unittest.mock import patch, MagicMock

from titmas_action_gate.cli import validate_install
from titmas_action_gate.evidence import AGENT_EVIDENCE_VERSION, AGENT_EVIDENCE_OAP_SCHEMA_SHA256

@pytest.fixture
def mock_dependencies():
    with patch("titmas_action_gate.cli.schema_directory") as mock_schema_dir, \
         patch("titmas_action_gate.cli.data_root") as mock_data_root, \
         patch("titmas_action_gate.cli.version") as mock_version, \
         patch("titmas_action_gate.cli.sha256_file") as mock_sha256, \
         patch("titmas_action_gate.cli.validate_agentteams_template") as mock_validate_template, \
         patch("titmas_action_gate.cli.evaluate_fixtures") as mock_eval_fixtures:

        # Setup default happy path
        mock_schema_dir.return_value = MagicMock()
        mock_data_root.return_value = MagicMock()
        mock_version.return_value = AGENT_EVIDENCE_VERSION
        mock_sha256.return_value = AGENT_EVIDENCE_OAP_SCHEMA_SHA256
        mock_validate_template.return_value = {"ok": True}
        mock_eval_fixtures.return_value = {"ok": True}

        yield {
            "version": mock_version,
            "sha256": mock_sha256,
            "validate_template": mock_validate_template,
            "eval_fixtures": mock_eval_fixtures
        }

def test_validate_install_success(mock_dependencies):
    result = validate_install()
    assert result["ok"] is True
    assert result["checks"]["agent_evidence_version"] is True
    assert result["checks"]["agent_evidence_wheel_pin_recorded"] is True
    assert result["checks"]["agent_evidence_oap_schema_hash"] is True
    assert result["checks"]["agentteams_template"] == {"ok": True}
    assert result["checks"]["fixture_evaluation"] == {"ok": True}

def test_validate_install_version_mismatch(mock_dependencies):
    mock_dependencies["version"].return_value = "invalid-version"
    result = validate_install()
    assert result["ok"] is False
    assert result["checks"]["agent_evidence_version"] is False

def test_validate_install_hash_mismatch(mock_dependencies):
    mock_dependencies["sha256"].return_value = "invalid-hash"
    result = validate_install()
    assert result["ok"] is False
    assert result["checks"]["agent_evidence_oap_schema_hash"] is False

def test_validate_install_template_failed(mock_dependencies):
    mock_dependencies["validate_template"].return_value = {"ok": False, "error": "bad template"}
    result = validate_install()
    assert result["ok"] is False
    assert result["checks"]["agentteams_template"]["ok"] is False

def test_validate_install_fixtures_failed(mock_dependencies):
    mock_dependencies["eval_fixtures"].return_value = {"ok": False, "cases": []}
    result = validate_install()
    assert result["ok"] is False
    assert result["checks"]["fixture_evaluation"]["ok"] is False
