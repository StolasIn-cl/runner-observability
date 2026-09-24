"""Durable local outbox storage contract tests."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from runner_observability.agent import DeliveryResult
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

    def test_successful_delivery_removes_pending_event(self) -> None:
        outbox = DurableOutbox(self.root)
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")
        calls: list[tuple[object, str, str]] = []

        result = outbox.drain(
            lambda event, endpoint, token: (
                calls.append((event, endpoint, token)) or DeliveryResult(True, 1, http_status=202)
            ),
            "https://monitor.invalid/v1/events",
            "secret-token",
        )

        self.assertEqual(result.delivered, 1)
        self.assertEqual(result.retained, 0)
        self.assertEqual(result.dead_lettered, 0)
        self.assertEqual(result.corrupt, 0)
        self.assertEqual(calls[0][1:], ("https://monitor.invalid/v1/events", "secret-token"))
        self.assertEqual(list((self.root / "pending").glob("*.json")), [])

    def test_transient_failure_is_replayed_after_reopening_outbox(self) -> None:
        outbox = DurableOutbox(self.root)
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")

        failed = outbox.drain(
            lambda _event, _endpoint, _token: DeliveryResult(
                False, 3, "temporary_http_failure", 503
            ),
            "https://monitor.invalid/v1/events",
            "secret-token",
        )

        self.assertEqual(failed.delivered, 0)
        self.assertEqual(failed.retained, 1)
        self.assertTrue(list((self.root / "pending").glob("*.json")))

        reopened = DurableOutbox(self.root)
        replayed = reopened.drain(
            lambda _event, _endpoint, _token: DeliveryResult(True, 1, http_status=202),
            "https://monitor.invalid/v1/events",
            "secret-token",
        )

        self.assertEqual(replayed.delivered, 1)
        self.assertEqual(replayed.retained, 0)
        self.assertEqual(list((self.root / "pending").glob("*.json")), [])

    def test_permanent_rejection_moves_validated_event_to_dead_letter(self) -> None:
        outbox = DurableOutbox(self.root)
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")

        result = outbox.drain(
            lambda _event, _endpoint, _token: DeliveryResult(
                False, 1, "rejected_http_response", 401
            ),
            "https://monitor.invalid/v1/events",
            "secret-token",
        )

        self.assertEqual(result.dead_lettered, 1)
        self.assertEqual(list((self.root / "pending").glob("*.json")), [])
        dead_letter = next((self.root / "dead-letter").glob("*.json"))
        dead_text = dead_letter.read_text(encoding="utf-8")
        dead = json.loads(dead_text)
        self.assertEqual(dead["dead_letter_reason"], "rejected_http_response")
        self.assertEqual(dead["event"], heartbeat())
        self.assertNotIn("secret-token", dead_text)
        self.assertNotIn("https://monitor.invalid", dead_text)

    def test_corrupt_file_does_not_block_healthy_event_drain(self) -> None:
        diagnostics: list[str] = []
        outbox = DurableOutbox(self.root, diagnostic=diagnostics.append)
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")
        (self.root / "pending" / "corrupt.json").write_text("not-json", encoding="utf-8")

        result = outbox.drain(
            lambda _event, _endpoint, _token: DeliveryResult(True, 1, http_status=202),
            "https://monitor.invalid/v1/events",
            "secret-token",
        )

        self.assertEqual(result.delivered, 1)
        self.assertEqual(result.corrupt, 1)
        self.assertEqual(diagnostics, ["outbox_corrupt_event"])
        self.assertTrue((self.root / "pending" / "corrupt.json").is_file())

    def test_drain_event_limit_leaves_later_events_pending(self) -> None:
        outbox = DurableOutbox(self.root, limits=OutboxLimits(max_drain_events=1))
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")
        outbox.enqueue(
            heartbeat(event_id="10000000-0000-0000-0000-000000000002"),
            queued_at="2026-09-24T02:00:00.000Z",
        )

        result = outbox.drain(
            lambda _event, _endpoint, _token: DeliveryResult(True, 1, http_status=202),
            "https://monitor.invalid/v1/events",
            "secret-token",
        )

        self.assertEqual(result.delivered, 1)
        self.assertEqual(len(list((self.root / "pending").glob("*.json"))), 1)

    def test_drain_time_limit_stops_before_processing_when_budget_elapsed(self) -> None:
        outbox = DurableOutbox(
            self.root,
            limits=OutboxLimits(max_drain_events=100, max_drain_seconds=0.5),
        )
        outbox.enqueue(heartbeat(), queued_at="2026-09-24T01:00:00.000Z")
        clock_values = iter((0.0, 1.0))

        result = outbox.drain(
            lambda _event, _endpoint, _token: DeliveryResult(True, 1, http_status=202),
            "https://monitor.invalid/v1/events",
            "secret-token",
            clock=lambda: next(clock_values),
        )

        self.assertEqual(result.delivered, 0)
        self.assertEqual(result.retained, 1)
        self.assertEqual(len(list((self.root / "pending").glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
