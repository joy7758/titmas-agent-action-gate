"""Thin adapter over the pinned public agent-evidence package."""

from __future__ import annotations

import json
from datetime import datetime
from importlib.metadata import version
from pathlib import Path
from typing import Any

from agent_evidence import EvidenceRecorder, LocalEvidenceStore, validate_profile_file, with_recomputed_integrity
from agent_evidence.crypto.chain import verify_chain

from .canonical import format_datetime, sha256_file, sha256_json, utc_now
from .contracts import schema_directory
from .errors import ActionGateError

AGENT_EVIDENCE_VERSION = "0.6.0"
AGENT_EVIDENCE_WHEEL_SHA256 = "3bec73551c252c4665ea54e49243190d2d27df430a92b5c6d1846d4e025d0b8e"
AGENT_EVIDENCE_OAP_SCHEMA_SHA256 = "cadff8c3b30a47f58563fa8700bcb2aa962338bc68336907d4f228e9b2387ea8"


class AgentEvidenceAdapter:
    def __init__(self, evidence_root: str | Path):
        self.root = Path(evidence_root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        installed = version("agent-evidence")
        if installed != AGENT_EVIDENCE_VERSION:
            raise ActionGateError(
                "VERIFIER_VERSION_MISMATCH",
                f"agent-evidence {AGENT_EVIDENCE_VERSION} is required; found {installed}.",
            )
        self.event_store = LocalEvidenceStore(self.root / "agent-evidence-events.jsonl")
        self.recorder = EvidenceRecorder(self.event_store)

    def _resolve_profile(self, profile_path: str | Path) -> Path:
        candidate = Path(profile_path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        candidate = candidate.resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ActionGateError("EVIDENCE_PATH_OUT_OF_SCOPE", "Evidence profile path escapes the configured evidence root.")
        return candidate

    def build_profile(
        self,
        request: dict[str, Any],
        *,
        actor: str,
        phase: str,
        operation_status: str,
        output: dict[str, Any],
        evidence_types: list[str],
        timestamp: datetime | None = None,
    ) -> dict[str, Any]:
        observed_at = timestamp or utc_now()
        request_id = request["request_id"]
        subject_id = f"obj:{request_id}"
        operation_id = f"op:{request_id}:{phase}"
        policy_id = f"policy:{request_id}:{phase}"
        provenance_id = f"prov:{request_id}:{phase}"
        evidence_id = f"evidence:{request_id}:{phase}"
        input_ref = f"ref:{request_id}:request"
        output_ref = f"ref:{request_id}:{phase}-output"
        constraints = [
            {"id": f"constraint:{value.lower().replace('_', '-')}", "description": f"Required evidence type {value} is present."}
            for value in evidence_types
        ]
        profile = {
            "profile": {"name": "execution-evidence-operation-accountability-profile", "version": "0.1"},
            "statement_id": f"eeoap:{request_id}:{phase}",
            "timestamp": format_datetime(observed_at),
            "actor": {"id": f"actor:{actor}", "name": actor, "runtime": "agentteams-v1.2.0-contract", "type": "agent"},
            "subject": {
                "id": subject_id,
                "type": "action-request",
                "locator": f"urn:titmas:action-request:{request_id}",
                "digest": f"sha256:{sha256_json(request)}",
            },
            "operation": {
                "id": operation_id,
                "type": request["action"],
                "description": f"TITMAS Action Gate {phase} evidence for one bounded request.",
                "subject_ref": subject_id,
                "policy_ref": policy_id,
                "input_refs": [input_ref],
                "output_refs": [output_ref],
                "result": {"status": operation_status, "summary": f"{phase} evidence captured"},
            },
            "policy": {
                "id": policy_id,
                "name": "titmas-action-gate-evidence-requirements",
                "constraint_refs": [item["id"] for item in constraints],
            },
            "constraints": constraints,
            "provenance": {
                "id": provenance_id,
                "actor_ref": f"actor:{actor}",
                "subject_ref": subject_id,
                "operation_ref": operation_id,
                "input_refs": [input_ref],
                "output_refs": [output_ref],
            },
            "evidence": {
                "id": evidence_id,
                "subject_ref": subject_id,
                "operation_ref": operation_id,
                "policy_ref": policy_id,
                "references": [
                    {
                        "ref_id": input_ref,
                        "role": "input",
                        "object_id": subject_id,
                        "locator": f"urn:titmas:action-request:{request_id}",
                        "digest": f"sha256:{sha256_json(request)}",
                    },
                    {
                        "ref_id": output_ref,
                        "role": "output",
                        "object_id": f"obj:{request_id}:{phase}-output",
                        "locator": f"urn:titmas:action-output:{request_id}:{phase}",
                        "digest": f"sha256:{sha256_json(output)}",
                    },
                ],
                "artifacts": [
                    {
                        "artifact_id": f"artifact:{request_id}:{phase}",
                        "type": "execution-log",
                        "locator": f"urn:titmas:artifact:{request_id}:{phase}",
                        "digest": f"sha256:{sha256_json({'request': request, 'output': output})}",
                    }
                ],
                "integrity": {
                    "references_digest": "sha256:" + "0" * 64,
                    "artifacts_digest": "sha256:" + "0" * 64,
                    "statement_digest": "sha256:" + "0" * 64,
                },
            },
            "validation": {
                "id": f"validation:{request_id}:{phase}",
                "method": "schema+reference+consistency",
                "validator": "agent-evidence validate-profile",
                "status": "verifiable",
                "evidence_ref": evidence_id,
                "provenance_ref": provenance_id,
                "policy_ref": policy_id,
            },
        }
        return with_recomputed_integrity(profile)

    def write_profile(self, profile: dict[str, Any], filename: str) -> Path:
        path = self._resolve_profile(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(profile, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
        return path

    def verify_profile(
        self,
        request: dict[str, Any],
        profile_path: str | Path,
        *,
        evidence_types: list[str],
        verified_at: datetime | None = None,
    ) -> dict[str, Any]:
        path = self._resolve_profile(profile_path)
        binding = {
            "action": request["action"],
            "provider": request["target"]["provider"],
            "repository": request["target"]["repository"],
            "resource_ref": request["target"]["resource_ref"],
            "parameters_sha256": request["parameters_sha256"],
        }
        if not path.is_file():
            status = "MISSING"
            digest = None
            checks: list[dict[str, Any]] = []
        else:
            digest = sha256_file(path)
            try:
                schema_path = schema_directory() / "agent-evidence-oap-v0.1.schema.json"
                if sha256_file(schema_path) != AGENT_EVIDENCE_OAP_SCHEMA_SHA256:
                    raise ActionGateError("VERIFIER_SCHEMA_DIGEST_MISMATCH", "Pinned agent-evidence OAP schema digest does not match the source lock.")
                report = validate_profile_file(path, schema_path=schema_path, fail_fast=False)
            except (ValueError, json.JSONDecodeError):
                report = {"ok": False, "issues": [{"code": "schema_violation"}], "stages": []}
            issue_codes = {item["code"] for item in report.get("issues", [])}
            if report.get("ok"):
                status = "VALID"
            elif any(code.endswith("_digest_mismatch") for code in issue_codes):
                status = "TAMPERED"
            else:
                status = "INVALID"
            checks = [
                {"check_id": str(stage["name"]).upper().replace("-", "_"), "passed": bool(stage.get("ok"))}
                for stage in report.get("stages", [])
            ]
            if not checks:
                checks = [{"check_id": "SCHEMA", "passed": False}]
        return {
            "schema_version": "0.1.0",
            "request_id": request["request_id"],
            "request_binding": binding,
            "verifier": {
                "name": "agent-evidence",
                "version": AGENT_EVIDENCE_VERSION,
                "distribution_sha256": AGENT_EVIDENCE_WHEEL_SHA256,
            },
            "status": status,
            "bundle_sha256": digest,
            "evidence_types": list(dict.fromkeys(evidence_types)),
            "checks": checks,
            "verified_at": format_datetime(verified_at or utc_now()),
        }

    def record_event(
        self,
        *,
        actor: str,
        event_type: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        request_id: str,
    ) -> dict[str, Any]:
        envelope = self.recorder.record(
            actor=actor,
            event_type=event_type,
            inputs=inputs,
            outputs=outputs,
            context={"source": "titmas-action-gate", "component": "action-gate", "attributes": {"request_id": request_id}},
            tags=["titmas", "action-gate", request_id],
        )
        return envelope.model_dump(mode="json")

    def verify_event_chain(self) -> list[str]:
        return verify_chain(self.event_store.list())
