1. **Remove hardcoded keys from `ActionGateService.demo()`**:
   Modify `src/titmas_action_gate/service.py` to extract `approval_key` and `record_signing_key` from environment variables, or require them to be passed directly instead of hardcoding them.
   If environment variables are used, I will use `os.environ.get()` to retrieve `TITMAS_APPROVAL_KEY` and `TITMAS_RECORD_SIGNING_KEY`. If they are not found, we can either raise an error or check if they are provided as arguments. Since the prompt says "Clear hardcoded secrets. It should be required to explicitly pass a key or use an environment variable," I'll update the function signature and logic.

```python
@classmethod
def demo(
    cls,
    state_dir: str | Path,
    *,
    caller_token: str = "titmas-demo-caller-token",
    approver_token: str = "titmas-demo-approver-token",
    approval_key: bytes | None = None,
    record_signing_key: bytes | None = None,
) -> ActionGateService:
    import os

    if approval_key is None:
        if "TITMAS_APPROVAL_KEY" in os.environ:
            approval_key = hashlib.sha256(os.environ["TITMAS_APPROVAL_KEY"].encode()).digest()
        else:
            raise ValueError("Explicit approval_key or TITMAS_APPROVAL_KEY environment variable is required.")
    if record_signing_key is None:
        if "TITMAS_RECORD_SIGNING_KEY" in os.environ:
            record_signing_key = hashlib.sha256(os.environ["TITMAS_RECORD_SIGNING_KEY"].encode()).digest()
        else:
            raise ValueError("Explicit record_signing_key or TITMAS_RECORD_SIGNING_KEY environment variable is required.")

    return cls(
        state_dir,
        caller_token=caller_token,
        approver_token=approver_token,
        approval_key=approval_key,
        record_signing_key=record_signing_key,
    )
```

2. **Fix Test Cases**:
   Any tests that previously relied on `demo()` working without an environment variable or key passed will now break. I will update tests in `tests/` to either mock the environment variable, or pass a hardcoded/mocked key explicitly to `demo()`.
   Using `grep` I found multiple files testing `ActionGateService.demo()`, such as:
   - `tests/test_runtime_mcp_end_to_end.py`
   - `tests/test_runtime_mcp_transport.py`
   - `tests/test_cloud_context_mcp.py`
   - `tests/test_service_bindings.py`
   - `tests/test_workflow_runtime.py`
   - `tests/test_cloud_context.py`
   - `tests/test_mcp_runtime.py`

   Wait, maybe instead of checking env vars in `demo()`, it would be better to check them in tests? If the issue is *specifically* hardcoded demo keys, I can just change the default to `None` and then read `os.environ.get("TITMAS_APPROVAL_KEY")` and `os.environ.get("TITMAS_RECORD_SIGNING_KEY")`. But this requires me to modify quite a lot of tests, which is fine, I can just set `os.environ` in `conftest.py` or individually in the tests, OR modify the test suite to pass keys to `.demo()`. But actually, for tests I can pass dummy keys explicitly.

   Let's check if there is a `conftest.py` where I can set environment variables for testing, or if I can use `pytest-env` or `pytest.MonkeyPatch`.
