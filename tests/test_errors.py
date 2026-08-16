from titmas_action_gate.errors import ActionGateError


def test_action_gate_error_to_dict_without_details():
    error = ActionGateError(code="TEST_CODE", message="Test message")
    expected = {
        "ok": False,
        "error": {
            "code": "TEST_CODE",
            "message": "Test message",
            "details": {}
        }
    }
    assert error.to_dict() == expected

def test_action_gate_error_to_dict_with_details():
    error = ActionGateError(code="TEST_CODE", message="Test message", details={"key": "value"})
    expected = {
        "ok": False,
        "error": {
            "code": "TEST_CODE",
            "message": "Test message",
            "details": {"key": "value"}
        }
    }
    assert error.to_dict() == expected
