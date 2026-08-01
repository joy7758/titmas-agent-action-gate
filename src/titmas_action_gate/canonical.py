"""RFC 8785 canonicalization and stable request bindings."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785


def canonical_json_bytes(value: Any) -> bytes:
    return rfc8785.dumps(value)


def canonical_json_text(value: Any) -> str:
    return canonical_json_bytes(value).decode("utf-8")


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def request_binding(request: dict[str, Any]) -> dict[str, str]:
    target = request["target"]
    return {
        "action": request["action"],
        "provider": target["provider"],
        "repository": target["repository"],
        "resource_ref": target["resource_ref"],
        "parameters_sha256": request["parameters_sha256"],
    }


def safe_request_binding(request: dict[str, Any]) -> dict[str, str]:
    target = request.get("target") if isinstance(request.get("target"), dict) else {}
    digest = request.get("parameters_sha256")
    if not isinstance(digest, str) or len(digest) != 64:
        digest = "0" * 64
    return {
        "action": str(request.get("action") or "invalid"),
        "provider": str(target.get("provider") or "invalid"),
        "repository": str(target.get("repository") or "invalid/invalid"),
        "resource_ref": str(target.get("resource_ref") or "invalid"),
        "parameters_sha256": digest,
    }


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_datetime(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
