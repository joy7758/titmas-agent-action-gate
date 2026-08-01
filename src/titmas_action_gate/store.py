"""SQLite append-only record chain and atomic decision consumption."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import closing, contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any

from .canonical import canonical_json_text, format_datetime, parse_datetime, sha256_json, utc_now
from .errors import ConflictError, NotFoundError


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
