import sys
import os
import shutil
import tempfile
from pathlib import Path
from titmas_action_gate.pr_gate import verify_pull_request
from unittest.mock import patch, MagicMock

# verify_pull_request calls reserve() internally.
# reserve() tries to create receipt.json and then summary.md using ExclusiveOutput.
# If summary.md creation fails, it should abort the first one (receipt.json).
# How to make summary.md creation fail?
# We can create summary.md manually so that O_EXCL fails with FileExistsError when reserve() runs.
# Since reserve() is run in verify_pull_request, verify_pull_request will try to fallback to reserve_private().
