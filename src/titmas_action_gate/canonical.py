"""RFC 8785 canonicalization and stable request bindings."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785


class ExclusiveOutput:
    """Reserve one regular output inode before effects and write it exactly once.

    ``O_EXCL`` closes the check-then-write race.  Inode checks ensure a path
    replacement or symlink cannot redirect the final write to existing data.
    """

    def __init__(self, path: str | Path, *, mode: int = 0o600):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        self._fd = os.open(self.path, flags, mode)
        os.fchmod(self._fd, mode)
        created = os.fstat(self._fd)
        if not stat.S_ISREG(created.st_mode):
            os.close(self._fd)
            self._fd = -1
            raise RuntimeError("EXCLUSIVE_OUTPUT_NOT_REGULAR")
        self._identity = (created.st_dev, created.st_ino)
        self._committed = False

    def __enter__(self) -> ExclusiveOutput:
        return self

    def _path_is_reserved_inode(self) -> bool:
        try:
            observed = os.stat(self.path, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return stat.S_ISREG(observed.st_mode) and (observed.st_dev, observed.st_ino) == self._identity

    def write_text(self, value: str) -> None:
        if self._committed or self._fd < 0:
            raise RuntimeError("EXCLUSIVE_OUTPUT_ALREADY_COMMITTED")
        if not self._path_is_reserved_inode():
            raise RuntimeError("EXCLUSIVE_OUTPUT_PATH_REPLACED")
        with os.fdopen(self._fd, "w", encoding="utf-8") as handle:
            self._fd = -1
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        if not self._path_is_reserved_inode():
            raise RuntimeError("EXCLUSIVE_OUTPUT_PATH_REPLACED")
        self._committed = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1
        if not self._committed:
            if self._path_is_reserved_inode():
                self.path.unlink()
            if exc_type is None:
                raise RuntimeError("EXCLUSIVE_OUTPUT_NOT_COMMITTED")
        return False


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
