#!/usr/bin/env python3
"""Validate the retained Alibaba Cloud public runtime evidence fail closed."""

from __future__ import annotations

import json
from pathlib import Path

from titmas_action_gate.public_evidence import PUBLIC_EVIDENCE_RELATIVE_PATH, validate_public_evidence

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    path = ROOT / PUBLIC_EVIDENCE_RELATIVE_PATH
    evidence = json.loads(path.read_text(encoding="utf-8"))
    issues = validate_public_evidence(ROOT, evidence)
    if issues:
        for issue in issues:
            print(issue)
        raise SystemExit(1)
    print("ALIBABACLOUD_RUNTIME_EVIDENCE=VALID")


if __name__ == "__main__":
    main()
