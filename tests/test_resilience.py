"""Fake-clock resilience tests for PERS-02 local SQLite state."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from runner_observability.contracts import validate_event
from runner_observability.store import Store


BASE = datetime(2026, 9, 18, 1, 0, tzinfo=timezone.utc)
RUNNER = "c56a4180-65aa-42ec-a945-5fd21dec0538"


def at(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


def event(
    event_type: str,
    event_id: str,
    sequence: int,
    *,
    attempt: int = 1,
    outcome: str | None = None,
    producer_id: str = "runner-agent",
    producer_epoch: str = "2026-09-18T01",
) -> object:
    payload: dict[str, object] = {
        "schema_version": 1,
        "event_type": event_type,
        "event_id": event_id,
        "runner_id": RUNNER,
        "producer_id": producer_id,
        "producer_epoch": producer_epoch,
        "producer_sequence": sequence,
        "occurred_at": at(sequence).isoformat().replace("+00:00", "Z"),
    }
    if event_type.startswith("job."):
        payload["job"] = {
            "repository": "acme/widgets",
            "workflow_run_id": 77,
            "run_attempt": attempt,
            "job_id": 99,
            "job_name": "verification",
            "run_url": "https://github.com/acme/widgets/actions/runs/77",
        }
    if outcome is not None:
        payload["outcome"] = outcome
    return validate_event(payload)


class ResilienceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def ingest(self, item: object, seconds: int) -> None:
        self.assertTrue(self.store.ingest(item, at(seconds)).accepted)  # type: ignore[arg-type]

    def require_store_method(self, name: str) -> None:
        self.assertTrue(callable(getattr(self.store, name, None)), f"PERS-02 requires Store.{name}()")

    def test_late_or_stale_sequence_stays_in_history_but_cannot_regress_runner(self) -> None:
        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000001", 4), 4)
        self.ingest(event("runner.offline", "10000000-0000-4000-8000-000000000002", 3), 5)

        runner = self.store.current_runner(RUNNER)
        self.assertEqual(runner["liveness"], "online")
        self.assertEqual(runner["producer_sequence"], 4)
        self.assertFalse(self.store.history()[-1]["projection_applied"])

    def test_interleaved_producer_does_not_erase_another_producers_watermark(self) -> None:
        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000018", 10), 10)
        self.ingest(
            event(
                "runner.heartbeat",
                "10000000-0000-4000-8000-000000000019",
                1,
                producer_id="runner-agent-b",
            ),
            11,
        )
        self.ingest(event("runner.offline", "10000000-0000-4000-8000-000000000020", 9), 12)

        runner = self.store.current_runner(RUNNER)
        self.assertEqual(runner["liveness"], "online")
        self.assertEqual(runner["producer_id"], "runner-agent-b")
        self.assertFalse(self.store.history()[-1]["projection_applied"])

    def test_older_attempt_cannot_replace_newer_attempt_runner_activity(self) -> None:
        self.ingest(event("job.started", "10000000-0000-4000-8000-000000000003", 1, attempt=2), 1)
        self.ingest(
            event("job.finished", "10000000-0000-4000-8000-000000000004", 2, attempt=1, outcome="failed"),
            2,
        )

        runner = self.store.current_runner(RUNNER)
        self.assertEqual(runner["activity"], "running")
        self.assertIsNone(runner["last_job_outcome"])
        self.assertFalse(self.store.history()[-1]["projection_applied"])

    def test_terminal_job_never_regresses_to_running_even_with_later_sequence(self) -> None:
        self.ingest(event("job.started", "10000000-0000-4000-8000-000000000005", 1), 1)
        self.ingest(
            event("job.finished", "10000000-0000-4000-8000-000000000006", 2, outcome="succeeded"), 2
        )
        self.ingest(event("job.heartbeat", "10000000-0000-4000-8000-000000000007", 3), 3)

        job = self.store.current_job("acme/widgets", 77, 1, 99)
        self.assertEqual(job["state"], "finished")
        self.assertEqual(job["outcome"], "succeeded")
        self.assertFalse(self.store.history()[-1]["projection_applied"])

    def test_later_terminal_event_cannot_replace_the_first_terminal_outcome(self) -> None:
        self.ingest(event("job.started", "10000000-0000-4000-8000-000000000013", 1), 1)
        self.ingest(
            event("job.finished", "10000000-0000-4000-8000-000000000014", 2, outcome="succeeded"), 2
        )
        self.ingest(
            event("job.finished", "10000000-0000-4000-8000-000000000015", 3, outcome="failed"), 3
        )

        job = self.store.current_job("acme/widgets", 77, 1, 99)
        self.assertEqual(job["state"], "finished")
        self.assertEqual(job["outcome"], "succeeded")
        self.assertFalse(self.store.history()[-1]["projection_applied"])

    def test_ten_minute_timeout_keeps_running_job_and_valid_heartbeat_recovers(self) -> None:
        self.require_store_method("refresh_liveness")
        self.ingest(event("job.started", "10000000-0000-4000-8000-000000000008", 1), 0)
        self.store.refresh_liveness(at(10 * 60))
        self.assertEqual(self.store.current_runner(RUNNER)["liveness"], "online")

        self.store.refresh_liveness(at(10 * 60 + 1))
        runner = self.store.current_runner(RUNNER)
        job = self.store.current_job("acme/widgets", 77, 1, 99)
        self.assertEqual(runner["liveness"], "offline")
        self.assertEqual(runner["offline_reason"], "heartbeat_timeout")
        self.assertEqual(runner["activity"], "running")
        self.assertEqual(job["state"], "running")
        self.assertIsNone(job["outcome"])
        self.assertEqual(job["liveness"], "offline")

        self.ingest(event("job.heartbeat", "10000000-0000-4000-8000-000000000009", 2), 10 * 60 + 2)
        self.assertEqual(self.store.current_runner(RUNNER)["liveness"], "online")
        self.assertEqual(self.store.current_job("acme/widgets", 77, 1, 99)["liveness"], "online")

    def test_liveness_uses_monitor_received_at_not_sender_occurred_at(self) -> None:
        self.require_store_method("refresh_liveness")
        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000016", 1), 10_000)

        self.store.refresh_liveness(at(10_600))

        self.assertEqual(self.store.current_runner(RUNNER)["liveness"], "online")

    def test_incidents_are_edge_triggered_persisted_and_recovery_is_silent(self) -> None:
        self.require_store_method("set_notifier")
        self.require_store_method("refresh_liveness")
        self.require_store_method("incidents")
        notices: list[dict[str, object]] = []
        self.store.set_notifier(notices.append)
        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000010", 1), 0)
        self.store.refresh_liveness(at(601))
        self.store.refresh_liveness(at(700))

        incidents = self.store.incidents()
        self.assertEqual(len(incidents), 1)
        self.assertTrue(incidents[0]["active"])
        self.assertEqual(incidents[0]["condition"], "heartbeat_timeout")
        self.assertEqual(len(notices), 1)

        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000011", 2), 701)
        self.assertFalse(self.store.incidents()[0]["active"])
        self.assertEqual(len(notices), 1)

    def test_explicit_runner_offline_opens_one_persisted_incident_and_notifies_once(self) -> None:
        notices: list[dict[str, object]] = []
        self.store.set_notifier(notices.append)
        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000021", 1), 0)
        self.ingest(event("runner.offline", "10000000-0000-4000-8000-000000000022", 2), 1)
        self.ingest(event("runner.offline", "10000000-0000-4000-8000-000000000023", 3), 2)

        incidents = self.store.incidents(active_only=True)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["condition"], "explicit_shutdown")
        self.assertEqual(len(notices), 1)

    def test_notifier_failure_never_rolls_back_persisted_incident(self) -> None:
        self.require_store_method("set_notifier")
        self.require_store_method("refresh_liveness")
        self.require_store_method("incidents")
        def denied(_: dict[str, object]) -> None:
            raise PermissionError("toast disabled")

        self.store.set_notifier(denied)
        self.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000012", 1), 0)
        self.store.refresh_liveness(at(601))

        self.assertTrue(self.store.incidents()[0]["active"])

    def test_active_incident_persists_across_reopen_and_does_not_notify_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "monitor.sqlite"
            first = Store(database)
            if not callable(getattr(first, "refresh_liveness", None)):
                first.close()
                self.fail("PERS-02 requires Store.refresh_liveness()")
            if not callable(getattr(first, "incidents", None)):
                first.close()
                self.fail("PERS-02 requires Store.incidents()")
            try:
                first.ingest(event("runner.heartbeat", "10000000-0000-4000-8000-000000000017", 1), at(0))
                first.refresh_liveness(at(601))
            finally:
                first.close()

            reopened = Store(database)
            try:
                notices: list[dict[str, object]] = []
                reopened.set_notifier(notices.append)
                reopened.refresh_liveness(at(700))

                self.assertEqual(len(reopened.incidents(active_only=True)), 1)
                self.assertEqual(notices, [])
            finally:
                reopened.close()


if __name__ == "__main__":
    unittest.main()
