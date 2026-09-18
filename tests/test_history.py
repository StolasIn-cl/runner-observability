"""History, replay, integrity, and retention tests for PERS-02."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect
from pathlib import Path
import sqlite3
import tempfile
import unittest

from runner_observability.contracts import validate_event
from runner_observability.store import Store


BASE = datetime(2026, 9, 18, 1, 0, tzinfo=timezone.utc)
RUNNER = "c56a4180-65aa-42ec-a945-5fd21dec0538"


def at(days: int = 0, seconds: int = 0) -> datetime:
    return BASE + timedelta(days=days, seconds=seconds)


def job_event(event_id: str, event_type: str, sequence: int, *, outcome: str | None = None) -> object:
    payload: dict[str, object] = {
        "schema_version": 1,
        "event_type": event_type,
        "event_id": event_id,
        "runner_id": RUNNER,
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": sequence,
        "occurred_at": at(seconds=sequence).isoformat().replace("+00:00", "Z"),
        "job": {
            "repository": "acme/widgets",
            "workflow_run_id": 77,
            "run_attempt": 1,
            "job_id": 99,
            "job_name": "verification",
            "run_url": "https://github.com/acme/widgets/actions/runs/77",
        },
    }
    if outcome is not None:
        payload["outcome"] = outcome
    return validate_event(payload)


class HistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def require_store_method(self, name: str) -> None:
        self.assertTrue(callable(getattr(self.store, name, None)), f"PERS-02 requires Store.{name}()")

    def test_history_filters_by_runner_workflow_outcome_and_received_time_window(self) -> None:
        self.assertEqual(len(inspect.signature(self.store.history).parameters), 1, "PERS-02 requires history(filters)")
        self.store.ingest(job_event("20000000-0000-4000-8000-000000000001", "job.started", 1), at(seconds=1))
        self.store.ingest(
            job_event("20000000-0000-4000-8000-000000000002", "job.finished", 2, outcome="failed"), at(seconds=2)
        )

        items = self.store.history(
            {
                "runner_id": RUNNER,
                "workflow_run_id": 77,
                "outcome": "failed",
                "received_after": at(seconds=2),
                "received_before": at(seconds=2),
            }
        )
        self.assertEqual([item["event_id"] for item in items], ["20000000-0000-4000-8000-000000000002"])

    def test_history_rejects_unknown_filter_even_when_no_events_match(self) -> None:
        with self.assertRaisesRegex(ValueError, r"^invalid_history_filter$"):
            self.store.history({"unapproved": "value"})

    def test_recent_events_pushes_its_bound_into_sql_and_returns_oldest_first(self) -> None:
        # dashboard.py uses this instead of history() so a live-view read
        # never has to load and JSON-decode the entire retained event log; the
        # LIMIT must be applied by SQLite, not by slicing a fully-materialised
        # Python list, and the result must come back in the same oldest-first
        # order history() uses.
        self.require_store_method("recent_events")
        for offset in range(1, 6):
            self.store.ingest(
                job_event(f"20000000-0000-4000-8000-00000000002{offset}", "job.heartbeat", offset),
                at(seconds=offset),
            )

        bounded = self.store.recent_events(2)

        self.assertEqual(
            [item["event_id"] for item in bounded],
            ["20000000-0000-4000-8000-000000000024", "20000000-0000-4000-8000-000000000025"],
        )
        self.assertEqual(bounded, self.store.history()[-2:])

    def test_history_filter_compares_legacy_variable_fractional_seconds_chronologically(self) -> None:
        event_id = "20000000-0000-4000-8000-000000000008"
        self.store.ingest(job_event(event_id, "job.started", 1), BASE + timedelta(microseconds=100_000))
        self.store._connection.execute(  # type: ignore[attr-defined]
            "UPDATE events SET received_at = ? WHERE event_id = ?", ("2026-09-18T01:00:00.10Z", event_id)
        )

        items = self.store.history({"received_before": "2026-09-18T01:00:00.1Z"})

        self.assertEqual([item["event_id"] for item in items], [event_id])

    def test_healthy_sqlite_integrity_check_leaves_store_non_degraded(self) -> None:
        self.require_store_method("check_integrity")
        self.assertTrue(self.store.check_integrity())
        self.assertFalse(self.store.degraded)

    def test_replay_restores_missing_projections_from_append_only_events(self) -> None:
        self.require_store_method("replay")
        self.store.ingest(job_event("20000000-0000-4000-8000-000000000003", "job.started", 1), at(seconds=1))
        self.store._connection.execute("DELETE FROM runner_state")  # type: ignore[attr-defined]
        self.store._connection.execute("DELETE FROM job_state")  # type: ignore[attr-defined]

        self.assertTrue(self.store.replay())
        self.assertEqual(self.store.current_runner(RUNNER)["activity"], "running")
        self.assertEqual(self.store.current_job("acme/widgets", 77, 1, 99)["state"], "running")
        self.assertFalse(self.store.degraded)

    def test_failed_replay_preserves_existing_readable_projection_and_sets_degraded(self) -> None:
        self.require_store_method("replay")
        self.store.ingest(job_event("20000000-0000-4000-8000-000000000004", "job.started", 1), at(seconds=1))
        self.store._connection.execute(  # type: ignore[attr-defined]
            "UPDATE events SET payload_json = ? WHERE event_id = ?", ("not-json", "20000000-0000-4000-8000-000000000004")
        )

        self.assertFalse(self.store.replay())
        self.assertTrue(self.store.degraded)
        self.assertEqual(self.store.current_runner(RUNNER)["activity"], "running")

    def test_replay_does_not_close_an_active_timeout_incident(self) -> None:
        self.require_store_method("refresh_liveness")
        self.require_store_method("incidents")
        self.require_store_method("replay")
        self.store.ingest(job_event("20000000-0000-4000-8000-000000000007", "job.started", 1), at(seconds=1))
        self.store.refresh_liveness(at(seconds=602))
        self.assertTrue(self.store.incidents(active_only=True))

        self.assertTrue(self.store.replay())
        self.assertTrue(self.store.incidents(active_only=True))

    def test_replay_preserves_timeout_liveness_without_a_new_heartbeat(self) -> None:
        self.store.ingest(job_event("20000000-0000-4000-8000-000000000009", "job.started", 1), at(seconds=1))
        self.store.refresh_liveness(at(seconds=602))

        self.assertTrue(self.store.replay())

        self.assertEqual(self.store.current_runner(RUNNER)["liveness"], "offline")
        self.assertEqual(self.store.current_job("acme/widgets", 77, 1, 99)["liveness"], "offline")

    def test_replay_refuses_pruned_history_and_preserves_current_projection(self) -> None:
        self.store.ingest(job_event("20000000-0000-4000-8000-000000000010", "job.started", 1), at(days=-8, seconds=1))
        self.store.ingest(
            job_event("20000000-0000-4000-8000-000000000011", "job.finished", 2, outcome="succeeded"),
            at(days=-8, seconds=2),
        )
        before = self.store.current_runner(RUNNER)
        self.assertEqual(self.store.prune_history(at(days=0)), 2)

        self.assertFalse(self.store.replay())

        self.assertEqual(self.store.current_runner(RUNNER), before)
        self.assertTrue(self.store.degraded)

    def test_startup_repairs_partial_job_projection_when_event_history_is_complete(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "monitor.sqlite"
            first = Store(database)
            try:
                first.ingest(job_event("20000000-0000-4000-8000-000000000012", "job.started", 1), at(seconds=1))
            finally:
                first.close()
            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM job_state")
                connection.commit()
            finally:
                connection.close()

            repaired = Store(database)
            try:
                self.assertEqual(repaired.current_job("acme/widgets", 77, 1, 99)["state"], "running")
                self.assertFalse(repaired.degraded)
            finally:
                repaired.close()

    def test_startup_repair_keeps_job_offline_when_its_timeout_incident_survives(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "monitor.sqlite"
            first = Store(database)
            try:
                first.ingest(job_event("20000000-0000-4000-8000-000000000013", "job.started", 1), at(seconds=1))
                first.refresh_liveness(at(seconds=602))
            finally:
                first.close()
            connection = sqlite3.connect(database)
            try:
                connection.execute("DELETE FROM job_state")
                connection.commit()
            finally:
                connection.close()

            repaired = Store(database)
            try:
                job = repaired.current_job("acme/widgets", 77, 1, 99)
                self.assertEqual(job["liveness"], "offline")
                self.assertEqual(job["offline_reason"], "heartbeat_timeout")
                self.assertTrue(repaired.incidents(active_only=True))
            finally:
                repaired.close()

    def test_retention_uses_received_at_and_never_removes_projections_or_incidents(self) -> None:
        self.require_store_method("refresh_liveness")
        self.require_store_method("incidents")
        self.require_store_method("prune_history")
        old = job_event("20000000-0000-4000-8000-000000000005", "job.started", 1)
        current = job_event("20000000-0000-4000-8000-000000000006", "job.heartbeat", 2)
        self.store.ingest(old, at(days=-8))
        self.store.ingest(current, at(days=0))
        self.store.refresh_liveness(at(days=0, seconds=601))
        before_incidents = self.store.incidents()

        self.assertEqual(self.store.prune_history(at(days=0)), 1)
        self.assertEqual([item["event_id"] for item in self.store.history()], ["20000000-0000-4000-8000-000000000006"])
        self.assertIsNotNone(self.store.current_runner(RUNNER))
        self.assertIsNotNone(self.store.current_job("acme/widgets", 77, 1, 99))
        self.assertEqual(self.store.incidents(), before_incidents)


if __name__ == "__main__":
    unittest.main()
