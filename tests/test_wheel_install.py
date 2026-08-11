from __future__ import annotations

import json
import os
import site
import subprocess
import sys
import tempfile
import textwrap
import unittest
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_SKILL_ROOT = Path(
    os.environ.get(
        "TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH",
        Path.home() / ".local/share/titmas-agent-action-gate/external-skills/alibabacloud-resourcecenter-search",
    )
).resolve()


class WheelInstallTests(unittest.TestCase):
    def test_native_mcp_loads_installed_source_lock_without_source_checkout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-wheel-install-") as tempdir:
            workspace = Path(tempdir).resolve()
            wheel_dir = workspace / "wheel"
            wheel_dir.mkdir()
            built = subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--outdir", str(wheel_dir)],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            wheel = next(wheel_dir.glob("*.whl"))

            environment = workspace / "venv"
            venv.EnvBuilder(with_pip=True).create(environment)
            python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
            installed = subprocess.run(
                [str(python), "-m", "pip", "install", "--no-deps", str(wheel)],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(installed.returncode, 0, installed.stderr)

            child_site = Path(
                subprocess.run(
                    [str(python), "-c", "import site; print(site.getsitepackages()[0])"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
            )
            parent_site = next(Path(path).resolve() for path in site.getsitepackages() if Path(path).is_dir())
            (child_site / "parent-test-dependencies.pth").write_text(str(parent_site) + "\n", encoding="utf-8")

            script = textwrap.dedent(
                """
                import json
                from pathlib import Path
                import titmas_action_gate
                from titmas_action_gate.runtime_mcp_server import build_from_environment

                runtime = build_from_environment()
                receipt = runtime.cloud_context_inspector.load_external_skill()
                print(json.dumps({
                    "package_file": str(Path(titmas_action_gate.__file__).resolve()),
                    "data_root": str(runtime.cloud_context_inspector.root),
                    "runtime_load_result": receipt["runtime_load_result"],
                }))
                """
            )
            runtime_dir = workspace / "runtime"
            runtime_dir.mkdir()
            principals = {
                "workflow-lead",
                "request-analyst",
                "evidence-verifier",
                "github-operator",
                "cloud-context-inspector",
                "release-steward",
                "titmas-action-gate-reviewer",
            }
            credentials_path = runtime_dir / "credentials.json"
            credentials_path.write_text(
                json.dumps(
                    {
                        "credentials": {
                            principal: f"wheel-test-{index:02d}-" + chr(97 + index) * 32
                            for index, principal in enumerate(sorted(principals))
                        }
                    }
                ),
                encoding="utf-8",
            )
            credentials_path.chmod(0o600)
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            env["TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH"] = str(EXTERNAL_SKILL_ROOT)
            env["TITMAS_ACTION_GATE_STATE_DIR"] = str(runtime_dir / "state")
            env["TITMAS_ACTION_GATE_RUNTIME_CREDENTIALS_FILE"] = str(credentials_path)
            env["TITMAS_ACTION_GATE_CALLER_TOKEN"] = "titmas-demo-caller-token"
            env["TITMAS_ACTION_GATE_APPROVER_TOKEN"] = "titmas-demo-approver-token"
            env["TITMAS_ACTION_GATE_DEMO_MODE"] = "true"
            probe = subprocess.run(
                [str(python), "-c", script],
                cwd=runtime_dir,
                env=env,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(probe.returncode, 0, probe.stderr)
            result = json.loads(probe.stdout)
            self.assertTrue(Path(result["package_file"]).is_relative_to(environment), result)
            self.assertTrue(Path(result["data_root"]).is_relative_to(environment), result)
            self.assertTrue((Path(result["data_root"]) / "governance/alibabacloud-resourcecenter-search-source-lock.json").is_file())
            self.assertEqual(result["runtime_load_result"], "SOURCE_VERIFIED_THROUGH_AUTHENTICATED_MCP")


if __name__ == "__main__":
    unittest.main()
