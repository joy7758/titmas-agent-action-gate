"""SQLite append-only record chain and atomic decision consumption."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json_text, format_datetime, parse_datetime, sha256_json, utc_now
from .errors import ConflictError, NotFoundError


@dataclass
class SecurityEventInput:
    event_id: str
    scope: dict[str, str]
    principal_id: str
    tool_name: str
    outcome: str
    reason_code: str
    business_state_delta: int
    details: dict[str, Any] | None = None
    created_at: datetime | None = None


class AppendOnlyStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                PRAGMA foreign_keys=ON;
                CREATE TABLE IF NOT EXISTS records (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_type TEXT NOT NULL,
                    record_id TEXT NOT NULL UNIQUE,
                    request_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS records_request_idx ON records(request_id, sequence);
                CREATE TABLE IF NOT EXISTS decision_consumptions (
                    decision_id TEXT PRIMARY KEY,
                    consumed_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    invocation_sha256 TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runtime_request_scopes (
                    request_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    submitted_by TEXT NOT NULL,
                    bound_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runtime_scope_idx
                    ON runtime_request_scopes(run_id, correlation_id, task_id, request_id);
                CREATE TABLE IF NOT EXISTS runtime_security_events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    run_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    business_state_delta INTEGER NOT NULL,
                    details_json TEXT NOT NULL,
                    previous_hash TEXT,
                    record_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS runtime_security_run_idx
                    ON runtime_security_events(run_id, sequence);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "sequence": row["sequence"],
            "record_type": row["record_type"],
            "record_id": row["record_id"],
            "request_id": row["request_id"],
            "payload": json.loads(row["payload_json"]),
            "previous_hash": row["previous_hash"],
            "record_hash": row["record_hash"],
            "created_at": row["created_at"],
        }

    def _append_record_conn(
        self,
        connection: sqlite3.Connection,
        *,
        record_type: str,
        record_id: str,
        request_id: str,
        payload: dict[str, Any],
        created_at: datetime,
    ) -> dict[str, Any]:
        existing = connection.execute("SELECT * FROM records WHERE record_id = ?", (record_id,)).fetchone()
        payload_json = canonical_json_text(payload)
        if existing is not None:
            record = self._row_to_record(existing)
            if record["record_type"] == record_type and record["request_id"] == request_id and canonical_json_text(record["payload"]) == payload_json:
                return record
            raise ConflictError("RECORD_ID_CONFLICT", f"record_id already exists with different content: {record_id}")
        prior = connection.execute("SELECT record_hash FROM records ORDER BY sequence DESC LIMIT 1").fetchone()
        previous_hash = prior["record_hash"] if prior else None
        material = {
            "record_type": record_type,
            "record_id": record_id,
            "request_id": request_id,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        record_hash = sha256_json(material)
        created = format_datetime(created_at)
        cursor = connection.execute(
            "INSERT INTO records(record_type,record_id,request_id,payload_json,previous_hash,record_hash,created_at) VALUES(?,?,?,?,?,?,?)",
            (record_type, record_id, request_id, payload_json, previous_hash, record_hash, created),
        )
        row = connection.execute("SELECT * FROM records WHERE sequence = ?", (cursor.lastrowid,)).fetchone()
        return self._row_to_record(row)

    def append_record(
        self,
        *,
        record_type: str,
        record_id: str,
        request_id: str,
        payload: dict[str, Any],
        created_at: datetime | None = None,
    ) -> dict[str, Any]:
        with self._transaction() as connection:
            return self._append_record_conn(
                connection,
                record_type=record_type,
                record_id=record_id,
                request_id=request_id,
                payload=payload,
                created_at=created_at or utc_now(),
            )

    def get_record(self, record_id: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT * FROM records WHERE record_id = ?", (record_id,)).fetchone()
        if row is None:
            raise NotFoundError("RECORD_NOT_FOUND", f"record not found: {record_id}")
        return self._row_to_record(row)

    def records_for_request(self, request_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT * FROM records WHERE request_id = ? ORDER BY sequence", (request_id,)).fetchall()
        return [self._row_to_record(row) for row in rows]

    def latest_for_request(self, request_id: str, record_type: str) -> dict[str, Any]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM records WHERE request_id = ? AND record_type = ? ORDER BY sequence DESC LIMIT 1",
                (request_id, record_type),
            ).fetchone()
        if row is None:
            raise NotFoundError("RECORD_NOT_FOUND", f"no {record_type} record for request {request_id}")
        return self._row_to_record(row)

    def verify_chain(self) -> list[str]:
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT * FROM records ORDER BY sequence").fetchall()
        issues: list[str] = []
        previous_hash: str | None = None
        for row in rows:
            record = self._row_to_record(row)
            expected = sha256_json(
                {
                    "record_type": record["record_type"],
                    "record_id": record["record_id"],
                    "request_id": record["request_id"],
                    "payload": record["payload"],
                    "previous_hash": previous_hash,
                }
            )
            if record["previous_hash"] != previous_hash:
                issues.append(f"record {record['sequence']}: previous_hash mismatch")
            if record["record_hash"] != expected:
                issues.append(f"record {record['sequence']}: record_hash mismatch")
            previous_hash = expected
        return issues

    def consume_decision(
        self,
        decision: dict[str, Any],
        invocation: dict[str, Any],
        *,
        actor: str,
        consumed_at: datetime | None = None,
    ) -> dict[str, Any]:
        checked_at = consumed_at or utc_now()
        if decision.get("outcome") != "ALLOW" or decision.get("may_execute") is not True:
            raise ConflictError("DECISION_NOT_ALLOW", "Only an ALLOW decision can be consumed.")
        if checked_at >= parse_datetime(decision["expires_at"]):
            raise ConflictError("DECISION_EXPIRED", "The ALLOW decision has expired.")
        expected_binding = decision["request_binding"]
        actual_binding = {key: invocation.get(key) for key in expected_binding}
        if actual_binding != expected_binding or invocation.get("decision_id") != decision["decision_id"]:
            raise ConflictError("INVOCATION_MISMATCH", "Provider invocation does not match the exact ALLOW binding.")
        if sha256_json(invocation.get("parameters")) != expected_binding["parameters_sha256"]:
            raise ConflictError("INVOCATION_DIGEST_MISMATCH", "Provider parameters do not match the exact ALLOW digest.")
        invocation_sha256 = sha256_json(invocation)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT decision_id FROM decision_consumptions WHERE decision_id = ?",
                (decision["decision_id"],),
            ).fetchone()
            if existing is not None:
                raise ConflictError("DECISION_ALREADY_CONSUMED", "The ALLOW decision was already consumed.")
            receipt_payload = {
                "decision_id": decision["decision_id"],
                "actor": actor,
                "invocation_sha256": invocation_sha256,
                "consumed_at": format_datetime(checked_at),
            }
            receipt = self._append_record_conn(
                connection,
                record_type="decision_consumption",
                record_id=f"consumption-{decision['decision_id'].removeprefix('decision-')}",
                request_id=decision["request_id"],
                payload=receipt_payload,
                created_at=checked_at,
            )
            connection.execute(
                "INSERT INTO decision_consumptions(decision_id,consumed_at,actor,invocation_sha256,record_hash) VALUES(?,?,?,?,?)",
                (decision["decision_id"], format_datetime(checked_at), actor, invocation_sha256, receipt["record_hash"]),
            )
        return receipt

    def is_consumed(self, decision_id: str) -> bool:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT 1 FROM decision_consumptions WHERE decision_id = ?", (decision_id,)).fetchone()
        return row is not None

    @staticmethod
    def _scope_tuple(scope: dict[str, str]) -> tuple[str, str, str, str, str]:
        return (
            scope["run_id"],
            scope["correlation_id"],
            scope["task_id"],
            scope["repository"],
            scope["commit"],
        )

    def bind_request_scope(
        self,
        request_id: str,
        scope: dict[str, str],
        *,
        principal_id: str,
        bound_at: datetime | None = None,
    ) -> dict[str, str]:
        """Bind one request to an immutable native runtime scope."""

        expected = self._scope_tuple(scope)
        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT * FROM runtime_request_scopes WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if existing is not None:
                actual = (
                    existing["run_id"],
                    existing["correlation_id"],
                    existing["task_id"],
                    existing["repository"],
                    existing["commit_sha"],
                )
                if actual != expected or existing["submitted_by"] != principal_id:
                    raise ConflictError(
                        "CORRELATION_CONFLICT",
                        "request_id is already bound to a different runtime scope or principal.",
                    )
            else:
                connection.execute(
                    """
                    INSERT INTO runtime_request_scopes(
                        request_id,run_id,correlation_id,task_id,repository,commit_sha,submitted_by,bound_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (request_id, *expected, principal_id, format_datetime(bound_at or utc_now())),
                )
        return {"request_id": request_id, **scope, "submitted_by": principal_id}

    def scope_for_request(self, request_id: str) -> dict[str, str]:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM runtime_request_scopes WHERE request_id = ?",
                (request_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError("RUNTIME_SCOPE_NOT_BOUND", f"request has no runtime scope: {request_id}")
        return {
            "run_id": row["run_id"],
            "correlation_id": row["correlation_id"],
            "task_id": row["task_id"],
            "repository": row["repository"],
            "commit": row["commit_sha"],
        }

    def assert_request_scope(self, request_id: str, scope: dict[str, str]) -> None:
        actual = self.scope_for_request(request_id)
        if actual["run_id"] != scope["run_id"]:
            raise ConflictError("CROSS_RUN_ACCESS_DENIED", "request belongs to a different runtime run.")
        if actual != scope:
            raise ConflictError("CORRELATION_MISMATCH", "request runtime scope does not match the admitted correlation and task.")

    def append_security_event(self, event: SecurityEventInput) -> dict[str, Any]:
        """Append a per-run security record without mutating request business state."""

        observed = event.created_at or utc_now()
        payload = event.details or {}
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT record_hash FROM runtime_security_events WHERE run_id = ? ORDER BY sequence DESC LIMIT 1",
                (event.scope["run_id"],),
            ).fetchone()
            previous_hash = prior["record_hash"] if prior else None
            material = {
                "event_id": event.event_id,
                "run_id": event.scope["run_id"],
                "correlation_id": event.scope["correlation_id"],
                "task_id": event.scope["task_id"],
                "principal_id": event.principal_id,
                "tool_name": event.tool_name,
                "outcome": event.outcome,
                "reason_code": event.reason_code,
                "business_state_delta": event.business_state_delta,
                "details": payload,
                "previous_hash": previous_hash,
            }
            record_hash = sha256_json(material)
            cursor = connection.execute(
                """
                INSERT INTO runtime_security_events(
                    event_id,run_id,correlation_id,task_id,principal_id,tool_name,outcome,reason_code,
                    business_state_delta,details_json,previous_hash,record_hash,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    event.event_id,
                    event.scope["run_id"],
                    event.scope["correlation_id"],
                    event.scope["task_id"],
                    event.principal_id,
                    event.tool_name,
                    event.outcome,
                    event.reason_code,
                    event.business_state_delta,
                    canonical_json_text(payload),
                    previous_hash,
                    record_hash,
                    format_datetime(observed),
                ),
            )
            sequence = int(cursor.lastrowid)
        return {**material, "sequence": sequence, "record_hash": record_hash, "created_at": format_datetime(observed)}

    def security_events_for_run(self, run_id: str) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM runtime_security_events WHERE run_id = ? ORDER BY sequence",
                (run_id,),
            ).fetchall()
        return [
            {
                "sequence": row["sequence"],
                "event_id": row["event_id"],
                "run_id": row["run_id"],
                "correlation_id": row["correlation_id"],
                "task_id": row["task_id"],
                "principal_id": row["principal_id"],
                "tool_name": row["tool_name"],
                "outcome": row["outcome"],
                "reason_code": row["reason_code"],
                "business_state_delta": row["business_state_delta"],
                "details": json.loads(row["details_json"]),
                "previous_hash": row["previous_hash"],
                "record_hash": row["record_hash"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def verify_security_chain(self, run_id: str) -> list[str]:
        issues: list[str] = []
        previous_hash: str | None = None
        for record in self.security_events_for_run(run_id):
            material = {
                key: record[key]
                for key in (
                    "event_id",
                    "run_id",
                    "correlation_id",
                    "task_id",
                    "principal_id",
                    "tool_name",
                    "outcome",
                    "reason_code",
                    "business_state_delta",
                    "details",
                    "previous_hash",
                )
            }
            if record["previous_hash"] != previous_hash:
                issues.append(f"security event {record['sequence']}: previous_hash mismatch")
            expected = sha256_json(material)
            if record["record_hash"] != expected:
                issues.append(f"security event {record['sequence']}: record_hash mismatch")
            previous_hash = expected
        return issues
