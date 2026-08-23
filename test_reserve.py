import sys
from pathlib import Path
from titmas_action_gate.canonical import ExclusiveOutput
import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

# The function to test is nested inside verify_pull_request, so we cannot easily mock or import it directly.
# Wait, `reserve` is defined inside `verify_pull_request`.
