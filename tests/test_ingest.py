"""In-process SQLite integration tests for the PERS-01 event store."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
from types import MappingProxyType
import unittest

from runner_observability.contracts import ValidationError, validate_event


FIXTURE_PATH = Path(__file__).with_name("fixtures") / "generic_lifecycle.json"


def fixture_events() -> list[dict[str, object]]:
    """Load an independently hand-authored, generic lifecycle timeline."""
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


class StoreIntegrationTests(unittest.TestCase):
    """Exercise the real store against a private, in-process SQLite database."""

    def make_store(self):  # type: ignore[no-untyped-def]
        # This first RED assertion keeps an absent implementation from becoming
        # an import/setup error; all remaining assertions document its API.
        spec = importlib.util.find_spec("runner_observability.store")
        self.assertIsNotNone(spec, "PERS-01 needs a runner_observability.store module")
        from runner_observability.store import Store

        return Store(":memory:")

    def ingest_fixture(self, store):  # type: ignore[no-untyped-def]
        for offset, payload in enumerate(fixture_events()):
            received_at = datetime(2026, 9, 18, 1, 10, tzinfo=timezone.utc) + timedelta(seconds=offset)
            result = store.ingest(validate_event(payload), received_at)
            self.assertTrue(result.accepted)
            self.assertFalse(result.duplicate)

    def test_projects_generic_lifecycle_into_current_runner_and_job_views(self) -> None:
        """Catches append-only ingestion that never advances the baseline views."""
        store = self.make_store()
        self.addCleanup(store.close)

        self.ingest_fixture(store)

        runner = store.current_runner("20000000-0000-4000-8000-000000000001")
        job = store.current_job("CyberLink-Team/promeo-pc-promeo", 123456789, 2, 987654321)
        self.assertEqual(runner["liveness"], "online")
        self.assertEqual(runner["activity"], "idle")
        self.assertEqual(runner["last_heartbeat_at"], "2026-09-18T01:10:00Z")
        self.assertEqual(runner["last_job_outcome"], "succeeded")
        self.assertEqual(job["state"], "finished")
        self.assertEqual(job["outcome"], "succeeded")
        self.assertEqual(job["run_url"], "https://github.com/CyberLink-Team/promeo-pc-promeo/actions/runs/123456789")
        self.assertEqual([entry["event_type"] for entry in store.history()], [
            "runner.heartbeat", "job.started", "job.heartbeat", "job.finished"
        ])

    def test_duplicate_event_id_succeeds_without_appending_or_advancing_projection(self) -> None:
        """Catches retry handling that turns one logical event into two state changes."""
        store = self.make_store()
        self.addCleanup(store.close)
        event = validate_event(fixture_events()[1])

        first = store.ingest(event, "2026-09-18T01:10:01Z")
        duplicate = store.ingest(event, "2026-09-18T02:10:01Z")

        self.assertTrue(first.accepted)
        self.assertTrue(duplicate.accepted)
        self.assertTrue(duplicate.duplicate)
        self.assertEqual(len(store.history()), 1)
        runner = store.current_runner(event.runner_id)
        self.assertEqual(runner["last_received_at"], "2026-09-18T01:10:01Z")

    def test_rejects_a_forged_unvalidated_event_without_partial_persistence(self) -> None:
        """Catches a store that writes an envelope before enforcing the validation boundary."""
        store = self.make_store()
        self.addCleanup(store.close)
        valid = validate_event(fixture_events()[1])
        unsafe_payload = dict(valid.payload)
        unsafe_payload["token"] = "ghp_neverPersistThis"
        forged = replace(valid, payload=MappingProxyType(unsafe_payload))

        with self.assertRaisesRegex(ValidationError, r"^invalid_event$"):
            store.ingest(forged, "2026-09-18T01:10:01Z")

        self.assertEqual(store.history(), [])
        accepted = store.ingest(valid, "2026-09-18T01:10:02Z")
        self.assertTrue(accepted.accepted)
        self.assertEqual(len(store.history()), 1)

    def test_terminal_outcomes_leave_runner_idle_and_are_retained_on_the_job(self) -> None:
        """Catches a terminal event that loses its outcome or leaves work marked running."""
        for outcome in ("succeeded", "failed", "cancelled"):
            with self.subTest(outcome=outcome):
                store = self.make_store()
                self.addCleanup(store.close)
                started, finished = fixture_events()[1], fixture_events()[3]
                finished = dict(finished)
                finished["event_id"] = {
                    "succeeded": "10000000-0000-4000-8000-000000000004",
                    "failed": "10000000-0000-4000-8000-000000000005",
                    "cancelled": "10000000-0000-4000-8000-000000000006",
                }[outcome]
                finished["outcome"] = outcome
                store.ingest(validate_event(started), "2026-09-18T01:10:01Z")
                store.ingest(validate_event(finished), "2026-09-18T01:10:03Z")

                runner = store.current_runner("20000000-0000-4000-8000-000000000001")
                job = store.current_job("CyberLink-Team/promeo-pc-promeo", 123456789, 2, 987654321)
                self.assertEqual(runner["activity"], "idle")
                self.assertEqual(runner["last_job_outcome"], outcome)
                self.assertEqual(job["state"], "finished")
                self.assertEqual(job["outcome"], outcome)


if __name__ == "__main__":
    unittest.main()
