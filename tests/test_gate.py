"""Local Verification Gate drill and evidence-report tests (issue #5).

Each drill exercises a restart, an offline/recovery cycle, or an injected
SQLite/cleanup/notification failure end-to-end through the gate's own
DrillResult/report machinery, and proves the evidence never leaks a
temp-path, raw diagnostic text, or a subprocess's individual test
identities. Every drill runs against a fresh, throwaway temp-file SQLite
database created by the test itself -- never any shared or named production
database file. Two of the five drills (offline/recovery and notification
failure) exercise scenarios close to existing `test_resilience.py`
coverage -- issue #5 names both explicitly as required local drills, so
they stay here, but what this file newly proves for them is the gate's own
report/redaction machinery around that behavior, not the underlying
liveness/incident logic itself (already covered elsewhere).

This suite is 100% runner-independent: it never opens a socket to a real
host, never assumes Runner A/B or a Monitor Host exist, and every assertion
here stays local. Issue #6 (HITL) is the only place real-hardware evidence
belongs.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import inspect
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from runner_observability import gate


BASE = datetime(2026, 9, 18, 1, 0, tzinfo=timezone.utc)


def at(seconds: int) -> datetime:
    return BASE + timedelta(seconds=seconds)


@dataclass
class FakeCompletedProcess:
    returncode: int
    stdout: str
    stderr: str = ""


class DrillIsolationTests(unittest.TestCase):
    """Every drill must take an explicit, caller-supplied throwaway database path."""

    def test_every_drill_requires_an_explicit_database_path_with_no_shared_default(self) -> None:
        drills = (
            gate.drill_monitor_restart_recovers_projection,
            gate.drill_runner_and_job_offline_then_recovery,
            gate.drill_sqlite_integrity_failure_is_isolated,
            gate.drill_cleanup_failure_is_isolated,
            gate.drill_notification_failure_is_isolated,
        )
        for drill in drills:
            with self.subTest(drill=drill.__name__):
                parameters = inspect.signature(drill).parameters
                first = next(iter(parameters.values()))
                self.assertIs(
                    first.default,
                    inspect.Parameter.empty,
                    f"{drill.__name__} must not default to a shared/production database path",
                )


class DrillScenarioTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-gate-test-")
        self.addCleanup(self._tmp.cleanup)
        self.database = Path(self._tmp.name) / "isolated-drill.sqlite"

    def test_monitor_restart_and_recover_preserves_projection_state(self) -> None:
        result = gate.drill_monitor_restart_recovers_projection(self.database, now=at(1))

        self.assertEqual(result.capability, "monitor_restart_recovery")
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, ())

    def test_runner_and_job_offline_then_recovery_drill_passes(self) -> None:
        result = gate.drill_runner_and_job_offline_then_recovery(self.database, started_at=at(0))

        self.assertEqual(result.capability, "offline_recovery")
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, ())

    def test_sqlite_integrity_failure_drill_is_isolated_and_degrades_safely(self) -> None:
        result = gate.drill_sqlite_integrity_failure_is_isolated(self.database, now=at(0))

        self.assertEqual(result.capability, "sqlite_integrity_failure_isolated")
        self.assertTrue(result.passed)
        self.assertIn("integrity_check_failed", result.reasons)

    def test_cleanup_failure_drill_is_isolated_and_degrades_safely(self) -> None:
        result = gate.drill_cleanup_failure_is_isolated(self.database, now=at(0))

        self.assertEqual(result.capability, "cleanup_failure_isolated")
        self.assertTrue(result.passed)
        self.assertIn("cleanup_failed", result.reasons)

    def test_notification_failure_drill_is_isolated_and_does_not_lose_the_incident(self) -> None:
        result = gate.drill_notification_failure_is_isolated(self.database, now=at(0))

        self.assertEqual(result.capability, "notification_failure_isolated")
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, ())

    def test_drill_results_never_contain_the_throwaway_database_path(self) -> None:
        results = [
            gate.drill_monitor_restart_recovers_projection(self.database, now=at(1)),
            gate.drill_sqlite_integrity_failure_is_isolated(self.database, now=at(2)),
        ]

        serialized = "\n".join(repr(result) for result in results)
        self.assertNotIn(str(self.database), serialized)
        self.assertNotIn(self._tmp.name, serialized)


class FailOpenContractDrillTests(unittest.TestCase):
    def test_simulated_timeout_and_rejection_keep_the_agent_cli_exit_zero(self) -> None:
        result = gate.verify_fail_open_contract()

        self.assertEqual(result.capability, "fail_open_contract")
        self.assertTrue(result.passed)
        self.assertEqual(result.reasons, ())


class SuiteResultParsingTests(unittest.TestCase):
    """`run_local_suite` never shells out for real here -- only its summary parsing is tested."""

    def test_parses_a_passing_summary_without_running_a_real_subprocess(self) -> None:
        tests_run = gate.MIN_EXPECTED_TESTS_RUN + 5
        completed = FakeCompletedProcess(
            returncode=0,
            stdout=(
                "".join(["."] * tests_run)
                + f"\n----------------------------------------------------------------------\nRan {tests_run} tests in 16.9s\n\nOK\n"
            ),
        )

        result = gate.run_local_suite(Path("."), invoke=lambda _command, _env, _cwd: completed)

        self.assertTrue(result.passed)
        self.assertEqual(result.tests_run, tests_run)
        self.assertEqual(result.failures, 0)
        self.assertEqual(result.errors, 0)
        # The parsed result must never retain the raw subprocess transcript.
        self.assertFalse(hasattr(result, "stdout"))
        self.assertFalse(hasattr(result, "stderr"))

    def test_zero_tests_run_never_passes_even_with_exit_code_zero_and_ok(self) -> None:
        # unittest discover exits 0 and prints "Ran 0 tests" / "OK" when it
        # finds nothing at all (wrong --repo-root, broken/renamed tests/
        # directory, a discovery misconfiguration). That must never parse as
        # a passing gate.
        completed = FakeCompletedProcess(
            returncode=0,
            stdout="\n----------------------------------------------------------------------\nRan 0 tests in 0.000s\n\nOK\n",
        )

        result = gate.run_local_suite(Path("."), invoke=lambda _command, _env, _cwd: completed)

        self.assertFalse(result.passed)
        self.assertEqual(result.tests_run, 0)
        self.assertEqual(result.failures, 0)
        self.assertEqual(result.errors, 0)

    def test_a_suite_run_below_the_known_minimum_count_never_passes(self) -> None:
        # Guards against a silently-shrinking suite, not just an empty one.
        tests_run = gate.MIN_EXPECTED_TESTS_RUN - 1
        completed = FakeCompletedProcess(
            returncode=0,
            stdout=f"\n----------------------------------------------------------------------\nRan {tests_run} tests in 1.0s\n\nOK\n",
        )

        result = gate.run_local_suite(Path("."), invoke=lambda _command, _env, _cwd: completed)

        self.assertFalse(result.passed)
        self.assertEqual(result.tests_run, tests_run)

    def test_a_suite_run_at_exactly_the_known_minimum_count_passes(self) -> None:
        tests_run = gate.MIN_EXPECTED_TESTS_RUN
        completed = FakeCompletedProcess(
            returncode=0,
            stdout=f"\n----------------------------------------------------------------------\nRan {tests_run} tests in 1.0s\n\nOK\n",
        )

        result = gate.run_local_suite(Path("."), invoke=lambda _command, _env, _cwd: completed)

        self.assertTrue(result.passed)
        self.assertEqual(result.tests_run, tests_run)

    def test_parses_a_failing_summary_and_never_retains_output_containing_test_identities_or_paths(self) -> None:
        leaking_output = (
            "F.E\n"
            "======================================================================\n"
            "FAIL: test_something_specific (tests.test_example.ExampleTests)\n"
            "Traceback (most recent call last):\n"
            '  File "C:\\Users\\stolas_in\\Desktop\\runner-observability\\tests\\test_example.py", line 12, in test_something_specific\n'
            "AssertionError\n"
            "----------------------------------------------------------------------\n"
            "Ran 91 tests in 12.1s\n\n"
            "FAILED (failures=1, errors=1)\n"
        )
        completed = FakeCompletedProcess(returncode=1, stdout=leaking_output)

        result = gate.run_local_suite(Path("."), invoke=lambda _command, _env, _cwd: completed)

        self.assertFalse(result.passed)
        self.assertEqual(result.tests_run, 91)
        self.assertEqual(result.failures, 1)
        self.assertEqual(result.errors, 1)
        serialized = repr(result)
        self.assertNotIn("test_something_specific", serialized)
        self.assertNotIn("C:\\Users\\stolas_in", serialized)


class ReportTests(unittest.TestCase):
    def _sample_report(self, *, suite_passed: bool = True, drill_passed: bool = True) -> "gate.GateReport":
        suite = gate.SuiteResult(passed=suite_passed, tests_run=91, failures=0 if suite_passed else 1, errors=0)
        drills = (
            gate.DrillResult("monitor_restart_recovery", drill_passed, () if drill_passed else ("restart_projection_mismatch",)),
            gate.DrillResult("offline_recovery", True, ()),
            gate.DrillResult("sqlite_integrity_failure_isolated", True, ("integrity_check_failed",)),
            gate.DrillResult("cleanup_failure_isolated", True, ("cleanup_failed",)),
            gate.DrillResult("notification_failure_isolated", True, ()),
        )
        fail_open = gate.DrillResult("fail_open_contract", True, ())
        return gate.GateReport(
            generated_at="2026-09-18T01:00:00Z",
            status=gate.GATE_STATUS_NOT_READY,
            suite=suite,
            drills=drills,
            fail_open=fail_open,
            limitations=gate.DEFAULT_LIMITATIONS,
        )

    def test_report_status_is_always_stamped_not_ready(self) -> None:
        report = self._sample_report()
        self.assertEqual(report.status, "not-ready")

    def test_report_local_gate_passed_reflects_every_component(self) -> None:
        passing = self._sample_report(suite_passed=True, drill_passed=True)
        failing = self._sample_report(suite_passed=True, drill_passed=False)

        self.assertTrue(passing.local_gate_passed)
        self.assertFalse(failing.local_gate_passed)

    def test_rendered_report_names_the_hitl_handoff_and_next_operator_action(self) -> None:
        text = gate.render_report(self._sample_report())

        self.assertIn("not-ready", text)
        self.assertIn("#6", text)
        self.assertIn("HITL", text)
        self.assertIn("Next operator action", text)

    def test_rendered_report_lists_every_verification_table_capability(self) -> None:
        text = gate.render_report(self._sample_report())

        for capability in (
            "monitor_restart_recovery",
            "offline_recovery",
            "sqlite_integrity_failure_isolated",
            "cleanup_failure_isolated",
            "notification_failure_isolated",
            "fail_open_contract",
        ):
            self.assertIn(capability, text)

    def test_rendered_report_never_contains_forbidden_redacted_content(self) -> None:
        text = gate.render_report(self._sample_report())

        for forbidden in ("Bearer ", "C:\\Users", "/home/", "token=", "test_something_specific"):
            self.assertNotIn(forbidden, text)

    def test_write_report_persists_exactly_the_rendered_text(self) -> None:
        text = gate.render_report(self._sample_report())
        with tempfile.TemporaryDirectory(prefix="runner-observability-gate-report-") as directory:
            report_path = Path(directory) / "gate-report.md"

            gate.write_report(report_path, text)

            self.assertEqual(report_path.read_text(encoding="utf-8"), text)

    def test_rendered_report_lists_automated_gate_capability_areas_without_test_identities(self) -> None:
        text = gate.render_report(self._sample_report())

        for area in gate.AUTOMATED_GATE_CAPABILITY_AREAS:
            self.assertIn(area, text)
        # A capability area is a fixed label, never an individual test name.
        self.assertNotIn("test_", text)

    def test_gate_report_rejects_any_status_other_than_not_ready(self) -> None:
        suite = gate.SuiteResult(passed=True, tests_run=105, failures=0, errors=0)
        drill = gate.DrillResult("monitor_restart_recovery", True, ())

        with self.assertRaises(ValueError):
            gate.GateReport(
                generated_at="2026-09-18T01:00:00Z",
                status="ready",
                suite=suite,
                drills=(drill,),
                fail_open=drill,
            )


class GateCrashHandlingTests(unittest.TestCase):
    """Covers the previously-untested crash path: a run that cannot complete
    must never leave a stale prior report looking like this run's evidence,
    and must never leak a raw traceback."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-gate-crash-test-")
        self.addCleanup(self._tmp.cleanup)
        self.report_path = Path(self._tmp.name) / "gate-report.md"

    def test_a_crash_overwrites_a_stale_prior_pass_report_instead_of_leaving_it(self) -> None:
        self.report_path.write_text("STALE PRIOR REPORT -- Overall local gate result: PASS\n", encoding="utf-8")

        with patch.object(gate, "build_full_report", side_effect=RuntimeError("simulated_drill_crash_with_a_path C:\\Users\\someone")):
            exit_code = gate.main(["--report-path", str(self.report_path)])

        self.assertEqual(exit_code, gate.GATE_EXIT_CRASHED)
        text = self.report_path.read_text(encoding="utf-8")
        self.assertNotIn("STALE PRIOR REPORT", text)
        self.assertNotIn("PASS", text)
        self.assertIn("CRASHED", text)
        self.assertIn(gate.GATE_STATUS_NOT_READY, text)
        # Never the exception message (which can embed arbitrary/absolute-path content).
        self.assertNotIn("simulated_drill_crash", text)
        self.assertNotIn("C:\\Users\\someone", text)
        # Only the stable exception type name is safe to persist.
        self.assertIn("RuntimeError", text)

    def test_a_crash_before_any_report_exists_still_produces_a_crash_marked_report(self) -> None:
        self.assertFalse(self.report_path.exists())

        with patch.object(gate, "build_full_report", side_effect=subprocess.TimeoutExpired(cmd=["python"], timeout=600)):
            exit_code = gate.main(["--report-path", str(self.report_path)])

        self.assertEqual(exit_code, gate.GATE_EXIT_CRASHED)
        self.assertTrue(self.report_path.exists())
        text = self.report_path.read_text(encoding="utf-8")
        self.assertIn("CRASHED", text)
        self.assertNotIn("PASS", text)

    def test_a_successful_run_after_a_prior_crash_report_replaces_it_cleanly(self) -> None:
        self.report_path.write_text("# stale crash report\nCRASHED\n", encoding="utf-8")
        passing_report = gate.GateReport(
            generated_at="2026-09-18T01:00:00Z",
            status=gate.GATE_STATUS_NOT_READY,
            suite=gate.SuiteResult(passed=True, tests_run=105, failures=0, errors=0),
            drills=(gate.DrillResult("monitor_restart_recovery", True, ()),),
            fail_open=gate.DrillResult("fail_open_contract", True, ()),
        )

        with patch.object(gate, "build_full_report", return_value=passing_report):
            exit_code = gate.main(["--report-path", str(self.report_path)])

        self.assertEqual(exit_code, 0)
        text = self.report_path.read_text(encoding="utf-8")
        self.assertNotIn("CRASHED", text)
        self.assertIn("PASS", text)

    def test_build_full_report_wraps_a_suite_failure_as_a_gate_crash_error_with_a_stable_phase(self) -> None:
        with patch.object(gate, "run_local_suite", side_effect=OSError("boom C:\\Users\\someone\\secret")):
            with self.assertRaises(gate.GateCrashError) as ctx:
                gate.build_full_report(Path("."))

        self.assertEqual(ctx.exception.phase, "automated_gate_suite")
        self.assertEqual(ctx.exception.cause_type, "OSError")
        # The crash error itself must not carry the original message text.
        self.assertNotIn("secret", repr(ctx.exception.cause_type))


if __name__ == "__main__":
    unittest.main()
