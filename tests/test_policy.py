import os
import unittest
from pathlib import Path
from unittest import mock

from titmas_action_gate.errors import ContractValidationError
from titmas_action_gate.policy import POLICY_FILENAME, default_policy_path


class DefaultPolicyPathTests(unittest.TestCase):
    def setUp(self):
        self.patcher_environ = mock.patch.dict(os.environ, clear=True)
        self.patcher_environ.start()

    def tearDown(self):
        self.patcher_environ.stop()

    def test_default_policy_path_from_env(self):
        with mock.patch("pathlib.Path.is_file", return_value=True):
            os.environ["TITMAS_ACTION_GATE_POLICY_PATH"] = "/dummy/custom_policy.json"
            self.assertEqual(default_policy_path(), Path("/dummy/custom_policy.json"))

    def test_default_policy_path_from_env_expanduser(self):
        with mock.patch("pathlib.Path.is_file", return_value=True):
            os.environ["TITMAS_ACTION_GATE_POLICY_PATH"] = "~/custom_policy.json"
            os.environ["HOME"] = "/home/dummy"
            self.assertEqual(default_policy_path(), Path("/home/dummy/custom_policy.json"))

    def test_default_policy_path_fallback_to_repo(self):
        dummy_file = Path("/repo/src/titmas_action_gate/policy.py")
        expected_path = Path("/repo/policies") / POLICY_FILENAME

        with mock.patch("titmas_action_gate.policy.__file__", str(dummy_file)):

            def mock_is_file(path_obj):
                return path_obj == expected_path

            with mock.patch.object(Path, "is_file", autospec=True, side_effect=mock_is_file):
                self.assertEqual(default_policy_path(), expected_path)

    def test_default_policy_path_fallback_to_sysconfig(self):
        dummy_file = Path("/repo/src/titmas_action_gate/policy.py")
        sysconfig_dir = Path("/sysconfig/data")
        expected_path = sysconfig_dir / "share/titmas-action-gate/policies" / POLICY_FILENAME

        with mock.patch("titmas_action_gate.policy.__file__", str(dummy_file)), mock.patch("sysconfig.get_path", return_value=str(sysconfig_dir)):

            def mock_is_file(path_obj):
                return path_obj == expected_path

            with mock.patch.object(Path, "is_file", autospec=True, side_effect=mock_is_file):
                self.assertEqual(default_policy_path(), expected_path)

    def test_default_policy_path_not_found(self):
        with mock.patch.object(Path, "is_file", return_value=False):
            with self.assertRaises(ContractValidationError) as ctx:
                default_policy_path()

            self.assertEqual(ctx.exception.code, "POLICY_NOT_FOUND")
            self.assertIn("Pinned GitHub policy file was not found", str(ctx.exception))
