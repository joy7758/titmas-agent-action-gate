# MCP boundary

This directory contains the machine-readable server manifest. The experimental implementation is in `src/titmas_action_gate/mcp_server.py`; stdio protocol initialization, tool discovery, and one authenticated call are covered by `tests/test_mcp_stdio.py`. No network deployment is claimed.

The Action Gate MCP server has no provider credentials and its six tools do not mutate GitHub. The optional provider adapter remains a separate trust domain and accepts only exact, server-verified, unexpired, unconsumed `ALLOW` decisions plus its own identity/ACL checks.
