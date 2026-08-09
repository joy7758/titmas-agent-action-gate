import tempfile
import unittest
from pathlib import Path

from titmas_action_gate.workflow import validate_agentteams_template


class TestValidateAgentteamsTemplate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.file_path = Path(self.temp_dir.name) / "test.yaml"
        self.valid_content = """
kind: Worker
metadata:
  name: workflow-lead
---
kind: Worker
metadata:
  name: request-analyst
---
kind: Worker
metadata:
  name: evidence-verifier
---
kind: Worker
metadata:
  name: github-operator
---
kind: Worker
metadata:
  name: cloud-context-inspector
---
kind: Worker
metadata:
  name: release-steward
---
kind: Team
apiVersion: v1
metadata:
  name: my-team
spec:
  workerMembers:
    - role: team_leader
"""
        self.file_path.write_text(self.valid_content)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_validate_agentteams_template_valid(self):
        self.assertIsInstance(validate_agentteams_template(self.file_path), dict)

    def test_validate_agentteams_template_invalid_worker(self):
        self.file_path.write_text(self.valid_content.replace("workflow-lead", "wrong-worker"))
        with self.assertRaisesRegex(ValueError, "Worker resources do not match"):
            validate_agentteams_template(self.file_path)

    def test_validate_agentteams_template_invalid_team(self):
        self.file_path.write_text(self.valid_content.replace("kind: Team", "kind: Other"))
        with self.assertRaisesRegex(ValueError, "exactly one AgentTeams Team"):
            validate_agentteams_template(self.file_path)

    def test_validate_agentteams_template_invalid_leader(self):
        self.file_path.write_text(self.valid_content.replace("team_leader", "member"))
        with self.assertRaisesRegex(ValueError, "exactly one team_leader"):
            validate_agentteams_template(self.file_path)
