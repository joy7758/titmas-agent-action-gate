import sys
import unittest

from titmas_action_gate.pr_gate import MAX_TOTAL_TEST_OUTPUT_BYTES, _run_test


class RunTestOutputObservationTests(unittest.TestCase):
    def test_run_test_observes_output_streams(self) -> None:
        command = [sys.executable, "-c", "import sys; sys.stdout.write('out'); sys.stderr.write('err')"]
        result = _run_test(command, execute=True, environment={}, workspace=None)

        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["stdout_bytes"], 3)
        self.assertEqual(result["stderr_bytes"], 3)
        self.assertEqual(result["combined_output_bytes"], 6)
        self.assertFalse(result["output_limit_exceeded"])

    def test_run_test_observes_output_limit_exceeded(self) -> None:
        command = [sys.executable, "-c", f"import sys; sys.stdout.write('x' * ({MAX_TOTAL_TEST_OUTPUT_BYTES} + 1))"]
        result = _run_test(command, execute=True, environment={}, workspace=None)

        self.assertTrue(result["output_limit_exceeded"])
        self.assertEqual(result["exit_code"], 125)


if __name__ == "__main__":
    unittest.main()
