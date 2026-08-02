#!/usr/bin/env python3
"""Build or verify deterministic AgentTeams Worker Skill packages."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from titmas_action_gate.skill_materialization import build_worker_packages, verify_worker_package

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--model", default="qwen3.7-max")
    parser.add_argument("--distribution-scope", default="LOCAL_RUNTIME_ONLY")
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    if args.verify_only:
        index = json.loads((output_dir / "attestation-index.json").read_text(encoding="utf-8"))
        receipts = [
            verify_worker_package(
                output_dir / f"{item['worker_id']}.zip",
                ROOT,
                expected_worker=item["worker_id"],
                expected_source_commit=index["source_commit"],
                expected_model=index["model"],
            )
            for item in index["workers"]
        ]
        result = {"verified": True, "workers": receipts}
    else:
        result = build_worker_packages(
            ROOT,
            output_dir,
            source_commit=args.source_commit,
            model=args.model,
            distribution_scope=args.distribution_scope,
        )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
