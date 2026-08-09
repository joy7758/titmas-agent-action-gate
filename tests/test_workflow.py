import pytest

from titmas_action_gate.workflow import validate_agentteams_template


@pytest.fixture
def valid_yaml(tmp_path):
    f = tmp_path / "test.yaml"
    content = """
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
    f.write_text(content)
    return f

def test_validate_agentteams_template_valid(valid_yaml):
    assert isinstance(validate_agentteams_template(valid_yaml), dict)

def test_validate_agentteams_template_invalid_worker(valid_yaml):
    valid_yaml.write_text(valid_yaml.read_text().replace("workflow-lead", "wrong-worker"))
    with pytest.raises(ValueError, match="Worker resources do not match"):
        validate_agentteams_template(valid_yaml)

def test_validate_agentteams_template_invalid_team(valid_yaml):
    valid_yaml.write_text(valid_yaml.read_text().replace("kind: Team", "kind: Other"))
    with pytest.raises(ValueError, match="exactly one AgentTeams Team"):
        validate_agentteams_template(valid_yaml)

def test_validate_agentteams_template_invalid_leader(valid_yaml):
    valid_yaml.write_text(valid_yaml.read_text().replace("team_leader", "member"))
    with pytest.raises(ValueError, match="exactly one team_leader"):
        validate_agentteams_template(valid_yaml)
