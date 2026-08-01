from __future__ import annotations

import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from titmas_action_gate.errors import ConflictError
from titmas_action_gate.store import AppendOnlyStore

CHECKED_AT = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)


def allow_decision() -> dict:
    binding = {
        "action": "github.pull_request.create",
        "provider": "github",
        "repository": "joy7758/action-gate-demo",
        "resource_ref": "refs/heads/docs-demo",
        "parameters_sha256": "a" * 64,
    }
    return {
        "decision_id": "decision-" + "b" * 64,
        "request_id": "aar-store-runtime-001",
        "request_binding": binding,
        "outcome": "ALLOW",
        "may_execute": True,
        "expires_at": "2026-08-02T00:05:00Z",
    }


class StoreRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory(prefix="titmas-aag-store-")
        self.path = Path(self.tempdir.name) / "gate.sqlite3"
        self.store = AppendOnlyStore(self.path)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_append_chain_and_idempotent_record(self) -> None:
        first = self.store.append_record(record_type="test", record_id="one", request_id="aar-store-runtime-001", payload={"value": 1})
        repeated = self.store.append_record(record_type="test", record_id="one", request_id="aar-store-runtime-001", payload={"value": 1})
        self.store.append_record(record_type="test", record_id="two", request_id="aar-store-runtime-001", payload={"value": 2})
        self.assertEqual(first["record_hash"], repeated["record_hash"])
        self.assertEqual(self.store.verify_chain(), [])

    def test_database_tampering_is_detected(self) -> None:
        self.store.append_record(record_type="test", record_id="one", request_id="aar-store-runtime-001", payload={"value": 1})
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("UPDATE records SET payload_json = ? WHERE record_id = ?", ('{"value":2}', "one"))
            connection.commit()
        self.assertTrue(self.store.verify_chain())

    def test_exact_invocation_consumes_once(self) -> None:
        decision = allow_decision()
        invocation = {"decision_id": decision["decision_id"], **decision["request_binding"], "parameters": {"title": "demo"}}
        receipt = self.store.consume_decision(decision, invocation, actor="github-operator", consumed_at=CHECKED_AT)
        self.assertTrue(receipt["record_hash"])
        self.assertTrue(self.store.is_consumed(decision["decision_id"]))
        with self.assertRaises(ConflictError) as context:
            self.store.consume_decision(decision, invocation, actor="github-operator", consumed_at=CHECKED_AT)
        self.assertEqual(context.exception.code, "DECISION_ALREADY_CONSUMED")

    def test_scope_expansion_is_rejected_before_consumption(self) -> None:
        decision = allow_decision()
        invocation = {"decision_id": decision["decision_id"], **decision["request_binding"], "parameters": {}}
        invocation["action"] = "github.pull_request.merge"
        with self.assertRaises(ConflictError) as context:
            self.store.consume_decision(decision, invocation, actor="github-operator", consumed_at=CHECKED_AT)
        self.assertEqual(context.exception.code, "INVOCATION_MISMATCH")
        self.assertFalse(self.store.is_consumed(decision["decision_id"]))

    def test_concurrent_replay_allows_only_one_consumer(self) -> None:
        decision = allow_decision()
        invocation = {"decision_id": decision["decision_id"], **decision["request_binding"], "parameters": {}}

        def consume() -> str:
            try:
                self.store.consume_decision(decision, invocation, actor="github-operator", consumed_at=CHECKED_AT)
                return "CONSUMED"
            except ConflictError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(lambda _: consume(), range(2)))
        self.assertEqual(sorted(results), ["CONSUMED", "DECISION_ALREADY_CONSUMED"])


if __name__ == "__main__":
    unittest.main()
