import pytest


@pytest.fixture(autouse=True)
def set_demo_keys(monkeypatch):
    monkeypatch.setenv("TITMAS_APPROVAL_KEY", "dummy_approval_key_for_testing")
    monkeypatch.setenv("TITMAS_RECORD_SIGNING_KEY", "dummy_record_key_for_testing")
