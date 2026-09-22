"""Snapshot and HTTP wiring tests for the PERS-01/PERS-03 command-center dashboard."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import http.client
import inspect
import json
from threading import Thread
import unittest

from runner_observability import dashboard as dashboard_module
from runner_observability.contracts import validate_event
from runner_observability.dashboard import HISTORY_FILTER_KEYS, dashboard_snapshot
from runner_observability.server import create_server
from runner_observability.store import Store


BASE = datetime(2026, 9, 18, 4, 0, tzinfo=timezone.utc)
RUNNER = "50000000-0000-4000-8000-000000000001"
JOB = {
    "repository": "acme/widgets",
    "workflow_run_id": 900,
    "run_attempt": 1,
    "job_id": 5001,
    "job_name": "pr_check",
    "run_url": "https://github.com/acme/widgets/actions/runs/900",
}


def at(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


def envelope(event_type: str, event_id: str, sequence: int, occurred_seconds: int, **extra: object) -> object:
    payload: dict[str, object] = {
        "schema_version": 1,
        "event_type": event_type,
        "event_id": event_id,
        "runner_id": RUNNER,
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T04",
        "producer_sequence": sequence,
        "occurred_at": at(occurred_seconds).isoformat().replace("+00:00", "Z"),
    }
    payload.update(extra)
    return validate_event(payload)


def heartbeat(event_id: str, sequence: int, seconds: int) -> object:
    return envelope("runner.heartbeat", event_id, sequence, seconds)


def job_started(event_id: str, sequence: int, seconds: int) -> object:
    return envelope("job.started", event_id, sequence, seconds, job=JOB)


def job_heartbeat(event_id: str, sequence: int, seconds: int) -> object:
    return envelope("job.heartbeat", event_id, sequence, seconds, job=JOB)


def job_finished(event_id: str, sequence: int, seconds: int, outcome: str) -> object:
    return envelope("job.finished", event_id, sequence, seconds, job=JOB, outcome=outcome)


def job_progress(event_id: str, sequence: int, seconds: int, **progress: object) -> object:
    body = {
        "stage_id": "selective_test",
        "stage_kind": "phase",
        "state": "running",
        "determinate": True,
        "total": 10,
        "completed": 1,
        "failed": 0,
        "pending": 9,
        "fallback_group_count": 0,
        "affected_test_count": 0,
        "attempt": 1,
    }
    body.update(progress)
    return envelope("job.progress", event_id, sequence, seconds, job=JOB, progress=body)


class DashboardSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)

    def snapshot(self, seconds: int) -> dict[str, object]:
        return dashboard_snapshot(self.store, at(seconds))

    def runner_view(self, snapshot: dict[str, object]) -> dict[str, object]:
        matches = [runner for runner in snapshot["runners"] if runner["runner_id"] == RUNNER]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def test_idle_runner_with_no_job_history_has_no_current_job(self) -> None:
        self.store.ingest(heartbeat("60000000-0000-4000-8000-000000000001", 1, 0), at(0))

        snapshot = self.snapshot(1)

        runner = self.runner_view(snapshot)
        self.assertEqual(runner["activity"], "idle")
        self.assertEqual(runner["liveness"], "online")
        self.assertIsNone(runner["current_job"])

    def test_snapshot_separates_current_runners_from_retained_offline_history(self) -> None:
        stale_runner = "60000000-0000-4000-8000-0000000000f1"
        self.store.ingest(heartbeat("60000000-0000-4000-8000-0000000000f0", 1, 600), at(600))
        self.store.ingest(
            envelope(
                "runner.heartbeat",
                "60000000-0000-4000-8000-0000000000f2",
                1,
                0,
                runner_id=stale_runner,
            ),
            at(0),
        )

        snapshot = self.snapshot(601)

        self.assertEqual(
            {item["runner_id"] for item in snapshot["runners"]},
            {RUNNER, stale_runner},
        )
        self.assertEqual(
            [item["runner_id"] for item in snapshot["active_runners"]],
            [RUNNER],
        )

    def test_idle_to_running_to_idle_keeps_the_last_known_job_and_outcome(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000002", 1, 0), at(0))
        mid_snapshot = self.snapshot(1)
        running_job = self.runner_view(mid_snapshot)["current_job"]
        self.assertEqual(running_job["state"], "running")
        self.assertIsNone(running_job["outcome"])

        self.store.ingest(job_finished("60000000-0000-4000-8000-000000000003", 2, 5, "succeeded"), at(5))
        final_snapshot = self.snapshot(6)

        runner = self.runner_view(final_snapshot)
        self.assertEqual(runner["activity"], "idle")
        self.assertEqual(runner["last_job_outcome"], "succeeded")
        last_known_job = runner["current_job"]
        self.assertIsNotNone(last_known_job)
        self.assertEqual(last_known_job["state"], "finished")
        self.assertEqual(last_known_job["outcome"], "succeeded")

    def test_job_offline_while_running_is_distinct_from_failed_or_cancelled(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000004", 1, 0), at(0))

        snapshot = self.snapshot(601)

        job = self.runner_view(snapshot)["current_job"]
        self.assertEqual(job["liveness"], "offline")
        self.assertEqual(job["offline_reason"], "heartbeat_timeout")
        self.assertEqual(job["state"], "running")
        self.assertIsNone(job["outcome"])

    def test_progress_unreported_is_true_only_when_a_newer_heartbeat_has_no_matching_progress(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000005", 1, 0), at(0))
        self.store.ingest(job_progress("60000000-0000-4000-8000-000000000006", 2, 5, completed=2, total=10), at(5))

        fresh_snapshot = self.snapshot(6)
        fresh_job = self.runner_view(fresh_snapshot)["current_job"]
        self.assertFalse(fresh_job["progress_unreported"])

        self.store.ingest(job_heartbeat("60000000-0000-4000-8000-000000000007", 3, 30), at(30))
        stalled_snapshot = self.snapshot(31)
        stalled_job = self.runner_view(stalled_snapshot)["current_job"]
        self.assertTrue(stalled_job["progress_unreported"])

    def test_progress_unreported_is_false_once_the_job_is_offline(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000008", 1, 0), at(0))
        self.store.ingest(job_progress("60000000-0000-4000-8000-000000000009", 2, 5, completed=2, total=10), at(5))

        offline_snapshot = self.snapshot(700)

        job = self.runner_view(offline_snapshot)["current_job"]
        self.assertEqual(job["liveness"], "offline")
        self.assertFalse(job["progress_unreported"])

    def test_run_url_is_the_event_supplied_value_verbatim(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-00000000000a", 1, 0), at(0))

        job = self.runner_view(self.snapshot(1))["current_job"]

        self.assertEqual(job["run_url"], JOB["run_url"])

    def test_dashboard_module_never_performs_an_outbound_network_call(self) -> None:
        source = inspect.getsource(dashboard_module)
        for forbidden in ("urllib", "http.client", "socket", "requests"):
            self.assertNotIn(forbidden, source)

    def test_history_filter_keys_match_the_approved_query_vocabulary(self) -> None:
        self.assertEqual(
            set(HISTORY_FILTER_KEYS),
            {"runner_id", "repository", "workflow_run_id", "outcome", "received_after", "received_before"},
        )

    def test_event_feed_excludes_runner_heartbeats_and_keeps_latest_seven(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000101", 1, 0), at(0))
        for sequence in range(2, 9):
            self.store.ingest(
                job_heartbeat(f"60000000-0000-4000-8000-{sequence:012d}", sequence, sequence),
                at(sequence),
            )
        self.store.ingest(heartbeat("60000000-0000-4000-8000-000000000109", 9, 9), at(9))

        feed = self.snapshot(10)["event_feed"]

        self.assertEqual(len(feed), 7)
        self.assertNotIn("runner.heartbeat", [entry["event_type"] for entry in feed])
        self.assertEqual(
            [entry["occurred_at"] for entry in feed],
            [f"2026-09-18 12:00:{seconds:02d}" for seconds in range(8, 1, -1)],
        )

    def test_job_timeline_keeps_latest_five_entries_in_latest_first_order(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000201", 1, 0), at(0))
        for sequence in range(2, 8):
            self.store.ingest(
                job_heartbeat(f"60000000-0000-4000-8000-{sequence:012d}", sequence, sequence),
                at(sequence),
            )

        job = self.runner_view(self.snapshot(8))["current_job"]

        self.assertEqual(len(job["timeline"]), 5)
        self.assertEqual(
            [entry["occurred_at"] for entry in job["timeline"]],
            [f"2026-09-18 12:00:{seconds:02d}" for seconds in range(7, 2, -1)],
        )

    def test_job_timeline_keeps_latest_events_when_other_runners_are_busier(self) -> None:
        other_runner = "60000000-0000-4000-8000-0000000002ff"
        other_job = {
            "repository": "acme/other",
            "workflow_run_id": 901,
            "run_attempt": 1,
            "job_id": 5002,
            "job_name": "other_job",
            "run_url": "https://github.com/acme/other/actions/runs/901",
        }
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000211", 1, 0), at(0))
        for sequence in range(2, 8):
            self.store.ingest(
                job_heartbeat(f"60000000-0000-4000-8000-{sequence + 100:012d}", sequence, sequence),
                at(sequence),
            )
        for sequence in range(8, 509):
            self.store.ingest(
                envelope(
                    "job.heartbeat",
                    f"60000000-0000-4000-8000-{sequence + 1000:012d}",
                    sequence,
                    sequence,
                    runner_id=other_runner,
                    job=other_job,
                ),
                at(sequence),
            )

        job = self.runner_view(self.snapshot(509))["current_job"]

        self.assertEqual(
            [entry["occurred_at"] for entry in job["timeline"]],
            [f"2026-09-18 12:00:{seconds:02d}" for seconds in range(7, 2, -1)],
        )

    def test_dashboard_timestamps_are_formatted_in_taipei_time_without_iso_suffixes(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000301", 1, 0), at(0))
        self.store.ingest(job_heartbeat("60000000-0000-4000-8000-000000000302", 2, 1), at(1))

        snapshot = self.snapshot(2)
        runner = self.runner_view(snapshot)
        job = runner["current_job"]

        self.assertEqual(snapshot["generated_at"], "2026-09-18 12:00:02")
        self.assertEqual(job["last_received_at"], "2026-09-18 12:00:01")
        self.assertEqual(job["last_heartbeat_at"], "2026-09-18 12:00:01")
        self.assertEqual(job["timeline"][0]["received_at"], "2026-09-18 12:00:01")
        self.assertNotIn("Z", json.dumps(snapshot))

    def test_incidents_and_health_are_surfaced_from_the_store(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-00000000000b", 1, 0), at(0))

        snapshot = self.snapshot(601)

        self.assertTrue(any(item["active"] for item in snapshot["incidents"]))
        self.assertEqual(snapshot["health"], {"degraded": False, "reasons": []})

    def test_snapshot_contains_no_forbidden_content_regardless_of_event_history(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-00000000000c", 1, 0), at(0))
        self.store.ingest(
            job_progress(
                "60000000-0000-4000-8000-00000000000d", 2, 5,
                stage_id="parallel_4_group", completed=13, total=16, pending=3,
                fallback_group_count=3, affected_test_count=18,
            ),
            at(5),
        )
        self.store.ingest(
            envelope(
                "job.fallback", "60000000-0000-4000-8000-00000000000e", 3, 6, job=JOB,
                fallback={
                    "target_stage_id": "parallel_4_tests_rerun",
                    "reason_code": "group_flaky",
                    "completed_groups": 13,
                    "total_groups": 16,
                    "fallback_group_count": 3,
                    "affected_test_count": 18,
                },
            ),
            at(6),
        )

        serialised = json.dumps(self.snapshot(7))
        lowered = serialised.lower()

        for forbidden_word in (
            "token", "bearer", "password", "secret", "raw_log", "pr_title", "pr_body",
            "test_name", "group_name", "fallback_reason",
        ):
            self.assertNotIn(forbidden_word, lowered)
        for forbidden_path in ("C:\\", "/home/", "/Users/"):
            self.assertNotIn(forbidden_path, serialised)

    def test_unapproved_progress_stage_id_is_never_rendered_verbatim(self) -> None:
        # contracts.py only constrains `stage_id` to a charset
        # (`^[a-z][a-z0-9_]{0,63}$`), not to the PERS-03 approved vocabulary --
        # so a buggy or malicious sender can put a group/test-shaped
        # identifier here and it will still validate and be persisted. This
        # is the real regression test for that boundary: it injects such a
        # value through a synthetic, otherwise-valid event and asserts the
        # rendered snapshot never contains it, rather than merely asserting
        # that an all-approved fixture doesn't happen to contain it.
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000011", 1, 0), at(0))
        self.store.ingest(
            job_progress(
                "60000000-0000-4000-8000-000000000012", 2, 5,
                stage_id="checkout_widget_group_07", completed=3, total=5,
            ),
            at(5),
        )

        snapshot = self.snapshot(6)
        serialised = json.dumps(snapshot)

        self.assertNotIn("checkout_widget_group_07", serialised)
        job = self.runner_view(snapshot)["current_job"]
        self.assertIn(dashboard_module.UNRECOGNISED_STAGE_ID, job["phases"])
        self.assertEqual(job["phases"][dashboard_module.UNRECOGNISED_STAGE_ID]["category"], "generic")
        self.assertEqual(job["phases"][dashboard_module.UNRECOGNISED_STAGE_ID]["completed"], 3)

    def test_unapproved_fallback_target_and_any_reason_code_are_never_rendered_verbatim(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000013", 1, 0), at(0))
        self.store.ingest(
            envelope(
                "job.fallback", "60000000-0000-4000-8000-000000000014", 2, 5, job=JOB,
                fallback={
                    "target_stage_id": "leak_group_names_here",
                    "reason_code": "unit_path_c_users_secret_project",
                    "completed_groups": 1,
                    "total_groups": 4,
                    "fallback_group_count": 1,
                    "affected_test_count": 2,
                },
            ),
            at(5),
        )

        snapshot = self.snapshot(6)
        serialised = json.dumps(snapshot)

        self.assertNotIn("leak_group_names_here", serialised)
        self.assertNotIn("unit_path_c_users_secret_project", serialised)
        self.assertNotIn("reason_code", serialised)
        job = self.runner_view(snapshot)["current_job"]
        self.assertEqual(job["fallback"]["target_stage_id"], dashboard_module.UNRECOGNISED_STAGE_ID)

    def test_phase_recency_survives_a_producer_epoch_reset(self) -> None:
        # `producer_sequence` is only monotonic within one (runner, producer,
        # producer_epoch) triple -- it resets to 1 after an agent restart
        # changes the epoch (see projection.py's watermark logic). A stale
        # event from an old epoch can carry a *higher* raw sequence number
        # than a genuinely newer event from a fresh epoch. Recency must be
        # decided by monitor-owned `received_at`, not raw sequence.
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000015", 1, 0), at(0))
        old_epoch_event = envelope(
            "job.progress", "60000000-0000-4000-8000-000000000016", 9, 5, job=JOB,
            progress={
                "stage_id": "selective_test", "stage_kind": "phase", "state": "running",
                "determinate": True, "total": 10, "completed": 9, "failed": 0, "pending": 1,
                "fallback_group_count": 0, "affected_test_count": 0, "attempt": 1,
            },
        )
        self.store.ingest(old_epoch_event, at(5))
        restarted_agent_payload = {
            "schema_version": 1,
            "event_type": "job.progress",
            "event_id": "60000000-0000-4000-8000-000000000017",
            "runner_id": RUNNER,
            "producer_id": "runner-agent",
            "producer_epoch": "2026-09-18T04-restarted",
            "producer_sequence": 1,
            "occurred_at": at(10).isoformat().replace("+00:00", "Z"),
            "job": JOB,
            "progress": {
                "stage_id": "selective_test", "stage_kind": "phase", "state": "running",
                "determinate": True, "total": 10, "completed": 2, "failed": 0, "pending": 8,
                "fallback_group_count": 0, "affected_test_count": 0, "attempt": 1,
            },
        }
        self.store.ingest(validate_event(restarted_agent_payload), at(10))

        job = self.runner_view(self.snapshot(11))["current_job"]

        selective = job["phases"]["selective_test"]
        self.assertEqual((selective["completed"], selective["total"]), (2, 10))


class DashboardHttpWiringTests(unittest.TestCase):
    TOKEN = "dashboard-token"

    def setUp(self) -> None:
        self.store = Store()
        self.server = create_server(
            self.store,
            self.TOKEN,
            clock=lambda: at(601),
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()

    def get(self, path: str) -> tuple[int, str, dict[str, str]]:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        headers = {key: value for key, value in response.getheaders()}
        connection.close()
        return response.status, body, headers

    def test_root_serves_the_command_center_html_shell(self) -> None:
        status, body, headers = self.get("/")

        self.assertEqual(status, 200)
        self.assertIn("Runner Observability", body)
        self.assertEqual(headers.get("Cache-Control"), "no-store")

    def test_static_assets_are_served_read_only_without_a_build_step(self) -> None:
        css_status, css_body, css_headers = self.get("/app.css")
        js_status, js_body, js_headers = self.get("/app.js")

        self.assertEqual(css_status, 200)
        self.assertIn("text/css", css_headers.get("Content-Type", ""))
        self.assertTrue(css_body)
        self.assertEqual(js_status, 200)
        self.assertIn("javascript", js_headers.get("Content-Type", ""))
        self.assertTrue(js_body)

    def test_static_assets_define_dark_theme_and_history_pagination_controls(self) -> None:
        _, css_body, _ = self.get("/app.css")
        _, js_body, _ = self.get("/app.js")

        self.assertIn("color-scheme: dark", css_body)
        self.assertIn("history-page", js_body)
        self.assertIn("history-prev", js_body)
        self.assertIn("history-next", js_body)
        self.assertIn("runner_alias", js_body)
        self.assertIn("isoToLocalDateTime(filters.received_after)", js_body)
        self.assertIn("isoToLocalDateTime(filters.received_before)", js_body)
        self.assertNotIn("background: #e7edf4", css_body)
        self.assertIn(".progress-track", css_body)

    def test_static_assets_define_dashboard_auto_refresh_controls(self) -> None:
        _, css_body, _ = self.get("/app.css")
        _, js_body, _ = self.get("/app.js")

        self.assertIn("refresh-toggle", js_body)
        self.assertIn("last-updated", js_body)
        self.assertIn("document.visibilityState", js_body)
        self.assertIn("setInterval", js_body)
        self.assertIn("refresh-controls", css_body)

    def test_api_history_is_paginated_newest_first_and_hides_runner_heartbeats(self) -> None:
        self.store.ingest(heartbeat("60000000-0000-4000-8000-000000000401", 1, 0), at(0))
        for sequence in range(1, 22):
            self.store.ingest(
                job_started(f"60000000-0000-4000-8000-{sequence:012d}", sequence, sequence),
                at(sequence),
            )

        first_status, first_body, _ = self.get("/api/history?page=1")
        second_status, second_body, _ = self.get("/api/history?page=2")
        first_page = json.loads(first_body)
        second_page = json.loads(second_body)

        self.assertEqual(first_status, 200)
        self.assertEqual(first_page["page"], 1)
        self.assertEqual(first_page["page_size"], 20)
        self.assertTrue(first_page["has_next"])
        self.assertEqual(len(first_page["events"]), 20)
        self.assertNotIn("runner.heartbeat", [event["event_type"] for event in first_page["events"]])
        self.assertEqual(first_page["events"][0]["runner_alias"], f"runner-{RUNNER[:8]}")
        self.assertEqual(first_page["events"][0]["received_at"], "2026-09-18 12:00:21")

        self.assertEqual(second_status, 200)
        self.assertEqual(second_page["page"], 2)
        self.assertFalse(second_page["has_next"])
        self.assertEqual(len(second_page["events"]), 1)
        self.assertEqual(
            {event["event_id"] for event in first_page["events"]}.isdisjoint(
                {event["event_id"] for event in second_page["events"]}
            ),
            True,
        )

    def test_api_dashboard_returns_the_same_shape_as_dashboard_snapshot(self) -> None:
        self.store.ingest(job_started("60000000-0000-4000-8000-00000000000f", 1, 0), at(0))

        status, body, headers = self.get("/api/dashboard")

        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        payload = json.loads(body)
        self.assertIn("runners", payload)
        self.assertIn("event_feed", payload)
        self.assertIn("history_filter_keys", payload)

    def test_api_dashboard_never_appends_to_history_but_does_refresh_liveness(self) -> None:
        # dashboard_snapshot() is NOT read-only: it calls
        # store.refresh_liveness(now) before reading state, since nothing else
        # in this codebase runs that sweep periodically. This test names and
        # asserts that intentional side effect explicitly -- appending to the
        # append-only log never happens, but runner/job liveness does change
        # underneath a GET -- rather than letting a "read-only" test name
        # imply more than the code actually guarantees.
        self.store.ingest(job_started("60000000-0000-4000-8000-000000000010", 1, 0), at(0))
        before = len(self.store.history())

        self.get("/api/dashboard")
        self.get("/api/dashboard")

        self.assertEqual(len(self.store.history()), before)
        runner = self.store.current_runner(RUNNER)
        self.assertEqual(runner["liveness"], "offline")
        self.assertEqual(runner["offline_reason"], "heartbeat_timeout")


if __name__ == "__main__":
    unittest.main()
