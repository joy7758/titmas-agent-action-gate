from __future__ import annotations

import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from titmas_action_gate.errors import ActionGateError
from titmas_action_gate.skill_materialization import PackageConfig, build_worker_packages, verify_worker_package

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL_SKILL_ROOT = Path(
    os.environ.get(
        "TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH",
        Path.home() / ".local/share/titmas-agent-action-gate/external-skills/alibabacloud-resourcecenter-search",
    )
).resolve()


def rewrite_zip(path: Path, *, drop: str | None = None, modify: str | None = None) -> None:
    with zipfile.ZipFile(path) as source:
        entries = [(item, source.read(item.filename)) for item in source.infolist() if item.filename != drop]
    with zipfile.ZipFile(path, "w") as destination:
        for info, data in entries:
            if info.filename == modify:
                data += b"\nmodified\n"
            destination.writestr(info, data)


class SkillMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.external_skill_env = patch.dict(
            os.environ,
            {"TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH": str(EXTERNAL_SKILL_ROOT)},
        )
        self.external_skill_env.start()

    def tearDown(self) -> None:
        self.external_skill_env.stop()

    def test_packages_are_deterministic_and_source_verified(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="titmas-skill-packages-a-") as first_dir,
            tempfile.TemporaryDirectory(prefix="titmas-skill-packages-b-") as second_dir,
        ):
            first = build_worker_packages(ROOT, first_dir, config=PackageConfig(source_commit="a" * 40, model="qwen3.7-max"))
            second = build_worker_packages(ROOT, second_dir, config=PackageConfig(source_commit="a" * 40, model="qwen3.7-max"))
            self.assertEqual(len(first["workers"]), 6)
            self.assertEqual(
                {item["worker_id"]: item["package_sha256"] for item in first["workers"]},
                {item["worker_id"]: item["package_sha256"] for item in second["workers"]},
            )
            self.assertTrue(all(item["source_hashes_verified"] for item in first["workers"]))
            lead = next(item for item in first["workers"] if item["worker_id"] == "workflow-lead")
            self.assertEqual(lead["runtime"], "copaw")
            self.assertNotIn("preview", lead["model"])
            cloud = next(item for item in first["workers"] if item["worker_id"] == "cloud-context-inspector")
            self.assertEqual(cloud["skill_name"], "alibabacloud-resourcecenter-search")
            self.assertEqual(cloud["skill_version"], "git-92bd723f7cc217b252feab574c1883fa0aa46b3c")
            self.assertIsNone(cloud["skill_manifest_sha256"])
            self.assertFalse(cloud["upstream_skill_bytes_in_package"])
            with zipfile.ZipFile(Path(first_dir) / "cloud-context-inspector.zip") as archive:
                self.assertFalse(any(name.startswith("skills/alibabacloud-resourcecenter-search/") for name in archive.namelist()))

    def test_missing_skill_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-skill-missing-") as output_dir:
            build_worker_packages(ROOT, output_dir, config=PackageConfig(source_commit="a" * 40, model="qwen3.7-max"))
            package = Path(output_dir) / "request-analyst.zip"
            rewrite_zip(package, drop="skills/analyze-action-request/SKILL.md")
            with self.assertRaises(ActionGateError) as context:
                verify_worker_package(package, ROOT, expected_worker="request-analyst")
            self.assertEqual(context.exception.code, "SKILL_MISSING")

    def test_public_distribution_fails_closed_without_license_clearance(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="titmas-public-skill-package-") as output_dir,
            self.assertRaises(ActionGateError) as context,
        ):
            build_worker_packages(
                ROOT,
                output_dir,
                config=PackageConfig(
                    source_commit="a" * 40,
                    model="qwen3.7-max",
                    distribution_scope="PUBLIC_DISTRIBUTION",
                ),
            )
        self.assertEqual(context.exception.code, "LICENSE_CLEARANCE_REQUIRED")

    def test_modified_skill_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-skill-modified-") as output_dir:
            build_worker_packages(ROOT, output_dir, config=PackageConfig(source_commit="a" * 40, model="qwen3.7-max"))
            package = Path(output_dir) / "github-operator.zip"
            rewrite_zip(package, modify="skills/execute-github-action/SKILL.md")
            with self.assertRaises(ActionGateError) as context:
                verify_worker_package(package, ROOT, expected_worker="github-operator")
            self.assertEqual(context.exception.code, "SKILL_DIGEST_MISMATCH")

    def test_modified_external_official_skill_fails_closed_before_packaging(self) -> None:
        with (
            tempfile.TemporaryDirectory(prefix="titmas-official-skill-modified-") as external_dir,
            tempfile.TemporaryDirectory(prefix="titmas-official-package-") as output_dir,
        ):
            external = Path(external_dir) / "alibabacloud-resourcecenter-search"
            shutil.copytree(EXTERNAL_SKILL_ROOT, external)
            skill_md = external / "SKILL.md"
            skill_md.write_text(skill_md.read_text(encoding="utf-8") + "\nmodified\n", encoding="utf-8")
            with (
                patch.dict(os.environ, {"TITMAS_OFFICIAL_ALIBABA_CLOUD_SKILL_PATH": str(external)}),
                self.assertRaises(ActionGateError) as context,
            ):
                build_worker_packages(ROOT, output_dir, config=PackageConfig(source_commit="a" * 40, model="qwen3.7-max"))
            self.assertEqual(context.exception.code, "SKILL_DIGEST_MISMATCH")

    def test_unattested_extra_package_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="titmas-skill-extra-") as output_dir:
            build_worker_packages(ROOT, output_dir, config=PackageConfig(source_commit="a" * 40, model="qwen3.7-max"))
            package = Path(output_dir) / "request-analyst.zip"
            with zipfile.ZipFile(package, "a") as archive:
                archive.writestr("skills/unattested/SKILL.md", "unexpected")
            with self.assertRaises(ActionGateError) as context:
                verify_worker_package(package, ROOT, expected_worker="request-analyst")
            self.assertEqual(context.exception.code, "SKILL_SCOPE_INVALID")


if __name__ == "__main__":
    unittest.main()
