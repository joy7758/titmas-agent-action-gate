"""Stable machine errors for fail-closed callers."""

from __future__ import annotations

from typing import Any


class ActionGateError(Exception):
    def __init__(self, code: str, message: str, *, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> dict[str, Any]:
        return {"ok": False, "error": {"code": self.code, "message": self.message, "details": self.details}}


class ContractValidationError(ActionGateError):
    pass


class AuthenticationError(ActionGateError):
    pass


class ConflictError(ActionGateError):
    pass


class NotFoundError(ActionGateError):
    pass
