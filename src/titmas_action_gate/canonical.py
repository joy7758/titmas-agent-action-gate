"""RFC 8785 canonicalization and stable request bindings."""

from __future__ import annotations

import hashlib
import os
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import rfc8785


class UnsafePathError(RuntimeError):
    """Stable fail-closed error for a path that cannot be walked without links."""

    code = "SYMLINK_ANCESTOR_NOT_ALLOWED"


def _open_directory_no_follow(path: Path, *, create: bool) -> tuple[int, tuple[tuple[str, int, int], ...]]:
    """Open an absolute directory one component at a time without following links."""

    candidate = path.expanduser()
    if not candidate.is_absolute() or not str(candidate) or any(part in {"", ".", ".."} for part in candidate.parts[1:]):
        raise UnsafePathError("PATH_ESCAPES_TRUSTED_ROOT")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(candidate.anchor, flags)
    except OSError as exc:
        raise UnsafePathError("PATH_COMPONENT_NOT_TRUSTED_DIRECTORY") from exc
    identities: list[tuple[str, int, int]] = []
    current = Path(candidate.anchor)
    try:
        root_observation = os.fstat(descriptor)
        identities.append((str(current), root_observation.st_dev, root_observation.st_ino))
        for part in candidate.parts[1:]:
            current = current / part
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
            except OSError as exc:
                raise UnsafePathError("SYMLINK_ANCESTOR_NOT_ALLOWED") from exc
            observation = os.fstat(child)
            if not stat.S_ISDIR(observation.st_mode):
                os.close(child)
                raise UnsafePathError("PATH_COMPONENT_NOT_TRUSTED_DIRECTORY")
            os.close(descriptor)
            descriptor = child
            identities.append((str(current), observation.st_dev, observation.st_ino))
        return descriptor, tuple(identities)
    except Exception:
        os.close(descriptor)
        raise


class ExclusiveOutput:
    """Reserve one regular output inode before effects and write it exactly once.

    ``O_EXCL`` closes the check-then-write race.  Inode checks ensure a path
    replacement or symlink cannot redirect the final write to existing data.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        mode: int = 0o600,
        expected_ancestor_identities: tuple[tuple[str, int, int], ...] | None = None,
    ):
        raw = Path(path).expanduser()
        if not str(raw) or any(part in {".", ".."} for part in raw.parts):
            raise UnsafePathError("PATH_ESCAPES_TRUSTED_ROOT")
        requested = raw if raw.is_absolute() else Path.cwd() / raw
        self.path = requested
        self._parent_path = requested.parent
        self._parent_fd, self._ancestor_identities = _open_directory_no_follow(self._parent_path, create=True)
        if expected_ancestor_identities is not None and self._ancestor_identities != expected_ancestor_identities:
            os.close(self._parent_fd)
            self._parent_fd = -1
            raise UnsafePathError("PATH_ANCESTOR_IDENTITY_CHANGED")
        parent_observation = os.fstat(self._parent_fd)
        if not stat.S_ISDIR(parent_observation.st_mode):
            os.close(self._parent_fd)
            self._parent_fd = -1
            raise RuntimeError("EXCLUSIVE_OUTPUT_PARENT_NOT_DIRECTORY")
        self._parent_identity = (parent_observation.st_dev, parent_observation.st_ino)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            self._fd = os.open(self.path.name, flags, mode, dir_fd=self._parent_fd)
        except Exception:
            os.close(self._parent_fd)
            self._parent_fd = -1
            raise
        try:
            os.fchmod(self._fd, mode)
        except Exception:
            os.close(self._fd)
            self._fd = -1
            os.close(self._parent_fd)
            self._parent_fd = -1
            raise
        created = os.fstat(self._fd)
        if not stat.S_ISREG(created.st_mode):
            os.close(self._fd)
            self._fd = -1
            os.close(self._parent_fd)
            self._parent_fd = -1
            raise RuntimeError("EXCLUSIVE_OUTPUT_NOT_REGULAR")
        self._identity = (created.st_dev, created.st_ino)
        self._initial_link_count = created.st_nlink
        self._initial_mode = stat.S_IMODE(created.st_mode)
        self._initial_uid = created.st_uid
        self._initial_gid = created.st_gid
        self._initial_mtime_ns = created.st_mtime_ns
        self._initial_ctime_ns = created.st_ctime_ns
        self._committed = False

    def __enter__(self) -> ExclusiveOutput:
        return self

    def _parent_is_reserved_directory(self) -> bool:
        if self._parent_fd < 0:
            return False
        try:
            descriptor_observation = os.fstat(self._parent_fd)
            path_observation = self._parent_path.lstat()
        except (FileNotFoundError, OSError):
            return False
        for path_text, expected_device, expected_inode in self._ancestor_identities:
            try:
                component = Path(path_text).lstat()
            except (FileNotFoundError, OSError):
                return False
            if (
                stat.S_ISLNK(component.st_mode)
                or not stat.S_ISDIR(component.st_mode)
                or (component.st_dev, component.st_ino) != (expected_device, expected_inode)
            ):
                return False
        return bool(
            stat.S_ISDIR(descriptor_observation.st_mode)
            and stat.S_ISDIR(path_observation.st_mode)
            and (descriptor_observation.st_dev, descriptor_observation.st_ino) == self._parent_identity
            and (path_observation.st_dev, path_observation.st_ino) == self._parent_identity
        )

    def _directory_entry_is_reserved_inode(self) -> bool:
        if self._parent_fd < 0:
            return False
        try:
            observed = os.stat(self.path.name, dir_fd=self._parent_fd, follow_symlinks=False)
        except (FileNotFoundError, OSError):
            return False
        return stat.S_ISREG(observed.st_mode) and (observed.st_dev, observed.st_ino) == self._identity

    def _path_is_reserved_inode(self) -> bool:
        if not self._parent_is_reserved_directory() or not self._directory_entry_is_reserved_inode():
            return False
        try:
            observed = os.stat(self.path, follow_symlinks=False)
        except (FileNotFoundError, OSError):
            return False
        return stat.S_ISREG(observed.st_mode) and (observed.st_dev, observed.st_ino) == self._identity

    def pristine(self) -> bool:
        """Return whether the reserved inode is still empty and exclusively linked."""

        if self._fd < 0 or not self._path_is_reserved_inode():
            return False
        observed = os.fstat(self._fd)
        if (
            not stat.S_ISREG(observed.st_mode)
            or observed.st_nlink != self._initial_link_count
            or stat.S_IMODE(observed.st_mode) != self._initial_mode
            or observed.st_uid != self._initial_uid
            or observed.st_gid != self._initial_gid
            or observed.st_mtime_ns != self._initial_mtime_ns
            or observed.st_ctime_ns != self._initial_ctime_ns
            or observed.st_size != 0
        ):
            return False
        os.lseek(self._fd, 0, os.SEEK_SET)
        return os.read(self._fd, 1) == b""

    def write_text(self, value: str) -> None:
        if self._committed or self._fd < 0:
            raise RuntimeError("EXCLUSIVE_OUTPUT_ALREADY_COMMITTED")
        if not self._path_is_reserved_inode():
            raise RuntimeError("EXCLUSIVE_OUTPUT_PATH_REPLACED")
        if not self.pristine():
            raise RuntimeError("EXCLUSIVE_OUTPUT_NOT_PRISTINE")
        payload = value.encode("utf-8")
        os.ftruncate(self._fd, 0)
        os.lseek(self._fd, 0, os.SEEK_SET)
        written = 0
        while written < len(payload):
            written += os.write(self._fd, payload[written:])
        os.fsync(self._fd)
        os.lseek(self._fd, 0, os.SEEK_SET)
        observed = b""
        while len(observed) < len(payload):
            chunk = os.read(self._fd, len(payload) - len(observed))
            if not chunk:
                break
            observed += chunk
        if observed != payload or hashlib.sha256(observed).digest() != hashlib.sha256(payload).digest() or os.fstat(self._fd).st_size != len(payload):
            raise RuntimeError("EXCLUSIVE_OUTPUT_WRITE_VERIFICATION_FAILED")
        os.close(self._fd)
        self._fd = -1
        if not self._path_is_reserved_inode():
            raise RuntimeError("EXCLUSIVE_OUTPUT_PATH_REPLACED")
        os.close(self._parent_fd)
        self._parent_fd = -1
        self._committed = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1
        if not self._committed:
            if self._parent_fd >= 0 and self._directory_entry_is_reserved_inode():
                os.unlink(self.path.name, dir_fd=self._parent_fd)
            if self._parent_fd >= 0:
                os.close(self._parent_fd)
                self._parent_fd = -1
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
