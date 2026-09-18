"""PERS-03 controlled stage/fallback aggregation tests for the dashboard read model.

These exercise only the approved phase vocabulary and aggregate counts from
PERS-03: fixed `pr_check` phase ids, the two detail-tracked rebuild phases
(`rebuild_test_mapping`, `unsafe_group_detect`), and generic job-level lifecycle
for `plan`/`cpp`/`reduce`, using fixtures that only ever contain approved
values. That makes these tests sanity checks on the *approved* path, not
regression tests for the redaction boundary itself -- a fixture built entirely
from approved ids can never exercise the code that has to reject an
unapproved one. The actual regression tests for that boundary (a synthetic
event with an unapproved `stage_id`/`target_stage_id` that must not appear in
the rendered snapshot) live in test_dashboard.py, next to the rest of
`dashboard_snapshot`'s behavioural tests.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import unittest

from runner_observability.contracts import validate_event
from runner_observability.dashboard import (
    PR_CHECK_PHASE_IDS,
    REBUILD_PHASE_IDS,
    dashboard_snapshot,
)
from runner_observability.store import Store


PR_FIXTURE = Path(__file__).with_name("fixtures") / "pr_validation_progress.json"
REBUILD_FIXTURE = Path(__file__).with_name("fixtures") / "rebuild_progress.json"
BASE = datetime(2026, 9, 18, 2, 5, tzinfo=timezone.utc)


def load_fixture(path: Path) -> list[dict[str, object]]:
    return json.loads(path.read_text(encoding="utf-8"))


def ingest_all(store: Store, path: Path, base: datetime) -> None:
    for offset, payload in enumerate(load_fixture(path)):
        store.ingest(validate_event(payload), base + timedelta(seconds=offset))


class PrCheckPhaseProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        ingest_all(self.store, PR_FIXTURE, BASE)
        self.snapshot = dashboard_snapshot(self.store, BASE + timedelta(seconds=60))
        self.runner = self.snapshot["runners"][0]
        self.job = self.runner["current_job"]

    def test_only_approved_phase_ids_are_ever_categorised_as_pr_check_phases(self) -> None:
        for stage_id, phase in self.job["phases"].items():
            if phase["category"] == "pr_check_phase":
                self.assertIn(stage_id, PR_CHECK_PHASE_IDS)

    def test_lint_check_and_merge_coverage_completed_phases_carry_their_counts(self) -> None:
        lint = self.job["phases"]["lint_check"]
        coverage = self.job["phases"]["merge_coverage"]
        self.assertEqual(lint["state"], "completed")
        self.assertEqual((lint["completed"], lint["total"]), (1, 1))
        self.assertEqual(coverage["state"], "completed")
        self.assertEqual((coverage["completed"], coverage["total"]), (1, 1))

    def test_selective_test_progress_reports_completed_over_total_groups(self) -> None:
        selective = self.job["phases"]["selective_test"]
        self.assertEqual(selective["state"], "running")
        self.assertEqual((selective["completed"], selective["total"]), (34, 50))
        self.assertEqual(selective["unit_label"], "groups")

    def test_fallback_summary_shows_only_aggregate_group_and_test_counts(self) -> None:
        # The approved fallback summary (PERS-03 ticket 05) is exactly:
        # completed/total groups, fallback group count, affected test count,
        # and target phase. `reason_code` was never part of that approved
        # display contract, so it must never appear here even though the
        # fixture's underlying event carries one.
        fallback = self.job["fallback"]
        self.assertIsNotNone(fallback)
        self.assertEqual(fallback["target_stage_id"], "parallel_4_tests_rerun")
        self.assertEqual(fallback["completed_groups"], 13)
        self.assertEqual(fallback["total_groups"], 16)
        self.assertEqual(fallback["fallback_group_count"], 3)
        self.assertEqual(fallback["affected_test_count"], 18)
        self.assertEqual(set(fallback), {
            "target_stage_id", "completed_groups", "total_groups",
            "fallback_group_count", "affected_test_count", "received_at", "occurred_at",
        })
        self.assertNotIn("reason_code", fallback)

    def test_parallel_4_group_phase_also_carries_its_own_fallback_aggregate(self) -> None:
        phase = self.job["phases"]["parallel_4_group"]
        self.assertEqual(phase["fallback_group_count"], 3)
        self.assertEqual(phase["affected_test_count"], 18)

    def test_terminal_outcome_and_run_url_are_available_after_completion(self) -> None:
        self.assertEqual(self.job["state"], "finished")
        self.assertEqual(self.job["outcome"], "succeeded")
        self.assertEqual(self.job["run_url"], "https://github.com/acme/widgets/actions/runs/500")

    def test_no_fixture_or_snapshot_content_contains_an_individual_test_or_group_name(self) -> None:
        serialised = json.dumps(self.snapshot)
        for forbidden in ("test_name", "test_id", "group_name", "group_id", "TestCase", "group_07", "spec.dart", "unit_path"):
            self.assertNotIn(forbidden, serialised)


class RebuildShardPhaseProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store(":memory:")
        self.addCleanup(self.store.close)
        ingest_all(self.store, REBUILD_FIXTURE, BASE)
        self.snapshot = dashboard_snapshot(self.store, BASE + timedelta(seconds=60))

    def _job_by_name(self, name: str) -> dict[str, object]:
        for item in self.snapshot["runners"]:
            job = item["current_job"]
            if job is not None and job["job_name"] == name:
                return job
        self.fail(f"no job named {name} in snapshot")

    def test_only_approved_phase_ids_are_ever_categorised_as_rebuild_phases(self) -> None:
        job = self._job_by_name("dart-shard-07")
        for stage_id, phase in job["phases"].items():
            if phase["category"] == "rebuild_phase":
                self.assertIn(stage_id, REBUILD_PHASE_IDS)

    def test_rebuild_test_mapping_reports_tests_progress_and_failed_count_separately(self) -> None:
        job = self._job_by_name("dart-shard-07")
        phase = job["phases"]["rebuild_test_mapping"]
        self.assertEqual((phase["completed"], phase["total"]), (90, 120))
        self.assertEqual(phase["failed"], 4)
        self.assertEqual(phase["unit_label"], "tests")
        self.assertEqual(phase["fallback_group_count"], 1)
        self.assertEqual(phase["affected_test_count"], 5)

    def test_unsafe_group_detect_reports_only_the_folder_counts_v1_actually_carries(self) -> None:
        # v1's progress schema has no dedicated safe/unsafe/skipped fields, and
        # there is no non-contradictory way to derive a three-way breakdown
        # from total/completed/failed/pending alone without inventing new
        # semantics for a general-purpose field. Rather than fabricate a
        # number the event never asserted, this phase is rendered with the
        # same generic completed/total/failed/pending fields as every other
        # phase; `failed` is this stage's unsafe-folder count.
        job = self._job_by_name("dart-shard-07")
        phase = job["phases"]["unsafe_group_detect"]
        self.assertEqual((phase["completed"], phase["total"]), (17, 40))
        self.assertEqual(phase["failed"], 2)
        self.assertEqual(phase["pending"], 23)
        self.assertEqual(phase["unit_label"], "folders")
        self.assertNotIn("folder_breakdown", phase)

    def test_generic_reduce_job_has_no_fabricated_phase_or_shard_progress(self) -> None:
        reduce_job = self._job_by_name("reduce")
        self.assertEqual(reduce_job["phases"], {})
        self.assertNotIn("progress", reduce_job)


if __name__ == "__main__":
    unittest.main()
