#!/usr/bin/env python3
"""Materialize the source-locked Alibaba Cloud Skill without redistributing it."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from titmas_action_gate.cloud_context import EXTERNAL_SKILL_PATH_ENV, CloudContextInspector

ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "governance/alibabacloud-resourcecenter-search-source-lock.json"
SKILLS_CLI_VERSION = "1.5.21"


def _run(arguments: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(arguments, cwd=cwd, check=True)


def main() -> None:
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    configured = os.environ.get(EXTERNAL_SKILL_PATH_ENV)
    if not configured:
        raise SystemExit(f"{EXTERNAL_SKILL_PATH_ENV} must name an external installation directory")
    target = Path(configured).expanduser().resolve()
    try:
        target.relative_to(ROOT)
    except ValueError:
        pass
    else:
        raise SystemExit("official Skill installation path must be outside the repository")
    if target.exists():
        CloudContextInspector(ROOT, external_skill_path=target).verify_skill_source()
        print("OFFICIAL_ALIBABA_CLOUD_SKILL_INSTALLED=true")
        print("INSTALLATION_ACTION=NONE_ALREADY_VERIFIED")
        return
    if shutil.which("git") is None or shutil.which("npx") is None:
        raise SystemExit("git and npx are required to materialize the source-locked Skill")
    with tempfile.TemporaryDirectory(prefix="titmas-official-skill-source-") as tempdir:
        checkout = Path(tempdir) / "alibabacloud-aiops-skills"
        install_root = Path(tempdir) / "installation"
        install_root.mkdir()
        _run(["git", "clone", "--filter=blob:none", "--no-checkout", lock["skill"]["repository"], str(checkout)])
        _run(["git", "checkout", "--detach", lock["skill"]["revision"]], cwd=checkout)
        observed = subprocess.run(["git", "rev-parse", "HEAD"], cwd=checkout, check=True, capture_output=True, text=True).stdout.strip()
        if observed != lock["skill"]["revision"]:
            raise RuntimeError("UPSTREAM_REVISION_MISMATCH")
        _run(
            [
                "npx",
                "--yes",
                f"skills@{SKILLS_CLI_VERSION}",
                "add",
                str(checkout),
                "--skill",
                lock["skill"]["name"],
                "--agent",
                "openclaw",
                "--yes",
                "--copy",
                "--full-depth",
            ],
            cwd=install_root,
        )
        materialized = install_root / "skills" / lock["skill"]["name"]
        if not materialized.is_dir():
            raise RuntimeError("SKILL_INSTALLATION_OUTPUT_MISSING")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(materialized), str(target))
    CloudContextInspector(ROOT, external_skill_path=target).verify_skill_source()
    print("OFFICIAL_ALIBABA_CLOUD_SKILL_INSTALLED=true")
    print("INSTALLATION_ACTION=MATERIALIZED_FROM_EXACT_REVISION_AND_HASH_VERIFIED")


if __name__ == "__main__":
    main()
