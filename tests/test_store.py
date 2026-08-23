from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from titmas_action_gate.errors import ConflictError, NotFoundError
from titmas_action_gate.store import AppendOnlyStore


class StoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = Path(self.tempdir.name) / "gate.sqlite3"
        self.store = AppendOnlyStore(self.path)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_append_and_get_record(self) -> None:
        created_at = datetime(2026, 8, 2, 0, 0, tzinfo=UTC)
        record = self.store.append_record(
            record_type="test",
            record_id="r1",
            request_id="req1",
            payload={"a": 1},
            created_at=created_at,
        )
        self.assertEqual(record["record_type"], "test")
        self.assertEqual(record["record_id"], "r1")
        self.assertEqual(record["request_id"], "req1")
        self.assertEqual(record["payload"], {"a": 1})

        fetched = self.store.get_record("r1")
        self.assertEqual(fetched, record)

    def test_get_record_not_found(self) -> None:
        with self.assertRaises(NotFoundError):
            self.store.get_record("nonexistent")

    def test_append_duplicate_record_id_conflict(self) -> None:
        self.store.append_record(
            record_type="test",
            record_id="r1",
            request_id="req1",
            payload={"a": 1},
        )
        with self.assertRaises(ConflictError):
            self.store.append_record(
                record_type="test",
                record_id="r1",
                request_id="req1",
                payload={"a": 2},
            )

    def test_records_for_request(self) -> None:
        self.store.append_record(record_type="type1", record_id="1", request_id="req1", payload={})
        self.store.append_record(record_type="type2", record_id="2", request_id="req1", payload={})
        self.store.append_record(record_type="type1", record_id="3", request_id="req2", payload={})

        records = self.store.records_for_request("req1")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["record_id"], "1")
        self.assertEqual(records[1]["record_id"], "2")

    def test_latest_for_request(self) -> None:
        self.store.append_record(record_type="type1", record_id="1", request_id="req1", payload={"v": 1})
        self.store.append_record(record_type="type1", record_id="2", request_id="req1", payload={"v": 2})

        latest = self.store.latest_for_request("req1", "type1")
        self.assertEqual(latest["record_id"], "2")
        self.assertEqual(latest["payload"]["v"], 2)

    def test_latest_for_request_not_found(self) -> None:
        with self.assertRaises(NotFoundError):
            self.store.latest_for_request("req1", "type1")

if __name__ == "__main__":
    unittest.main()
