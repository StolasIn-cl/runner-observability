"""Durable local outbox storage contract tests."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from runner_observability.outbox import DurableOutbox, OutboxLimits


RUNNER_ID = "20000000-0000-4000-8000-000000000001"


def heartbeat(*, event_id: str = "10000000-0000-4000-8000-000000000001") -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "runner.heartbeat",
        "event_id": event_id,
        "runner_id": RUNNER_ID,
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": 1,
        "occurred_at": "2026-09-18T01:00:00Z",
    }


class OutboxStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="runner-observability-outbox-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_enqueue_is_atomic_and_survives_reopen(self) -> None:
        outbox = DurableOutbox(self.root)

        result = outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")

        self.assertEqual(result.status, "queued")
        pending_file = self.root / "pending" / f"{result.event_id}.json"
        self.assertTrue(pending_file.is_file())
        self.assertEqual(list((self.root / "pending").glob("*.tmp")), [])
        raw = pending_file.read_text(encoding="utf-8")
        self.assertNotIn("secret-token", raw)
        self.assertNotIn("https://monitor.invalid", raw)

        reopened = DurableOutbox(self.root)
        pending, corrupt = reopened.pending_events()

        self.assertEqual(corrupt, 0)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0][1]["event"], heartbeat())

    def test_duplicate_is_idempotent_and_conflict_preserves_original(self) -> None:
        outbox = DurableOutbox(self.root)
        original = heartbeat()
        first = outbox.enqueue(original, queued_at="2026-09-24T01:00:00.000Z")

        duplicate = outbox.enqueue(original, queued_at="2026-09-24T02:00:00.000Z")
        changed = heartbeat()
        changed["producer_sequence"] = 2
        conflict = outbox.enqueue(changed, queued_at="2026-09-24T03:00:00.000Z")

        self.assertEqual(first.status, "queued")
        self.assertEqual(duplicate.status, "duplicate")
        self.assertEqual(conflict.status, "conflict")
        pending, corrupt = outbox.pending_events()
        self.assertEqual(corrupt, 0)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0][1]["event"], original)

    def test_corrupt_pending_file_is_skipped_without_leaking_contents(self) -> None:
        diagnostics: list[str] = []
        outbox = DurableOutbox(self.root, diagnostic=diagnostics.append)
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")
        corrupt_file = self.root / "pending" / "corrupt.json"
        corrupt_file.write_text(
            '{"token":"secret-token","event":', encoding="utf-8"
        )

        pending, corrupt = outbox.pending_events()

        self.assertEqual(len(pending), 1)
        self.assertEqual(corrupt, 1)
        self.assertEqual(diagnostics, ["outbox_corrupt_event"])
        self.assertNotIn("secret-token", "\n".join(diagnostics))
        self.assertTrue(corrupt_file.is_file())

    def test_event_count_capacity_rejects_without_removing_existing_events(self) -> None:
        outbox = DurableOutbox(self.root, limits=OutboxLimits(max_events=1))
        first = outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")
        second_event = heartbeat(event_id="10000000-0000-4000-8000-000000000002")

        second = outbox.enqueue(second_event, queued_at="2026-09-24T02:00:00.000Z")

        self.assertEqual(first.status, "queued")
        self.assertEqual(second.status, "rejected")
        self.assertEqual(second.reason, "outbox_capacity_exceeded")
        self.assertEqual(len(list((self.root / "pending").glob("*.json"))), 1)

    def test_byte_capacity_rejects_event_before_writing_it(self) -> None:
        outbox = DurableOutbox(self.root, limits=OutboxLimits(max_bytes=1))

        result = outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")

        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.reason, "outbox_capacity_exceeded")
        self.assertFalse((self.root / "pending").exists())


if __name__ == "__main__":
    unittest.main()
