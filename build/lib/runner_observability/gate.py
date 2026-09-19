"""Local Verification Gate: isolated fault drills and a redacted evidence report (issue #5).

Scope boundary (binding): this module is 100% runner-independent. It never
opens a socket to a real host, never assumes a Monitor Host or Runner A/B
exists, and its report never claims production readiness -- that decision
belongs solely to issue #6's HITL acceptance evidence (see
``docs/canary-evidence-template.md``). Every drill here runs against a
throwaway temp-file SQLite database the caller supplies explicitly; nothing
in this module defaults to, or ever touches, a shared/named database file.

Redaction boundary: every value this module persists, renders, or returns is
either a stable capability/reason code drawn from this codebase's existing
vocabulary (``store.py``'s ``_degraded_reasons``, ``health.py``'s incident
conditions) or a plain pass/fail count. Nothing here ever stores a raw
subprocess transcript, an individual test identity, a temp-file path, a
bearer token, or any other value the project-wide contract forbids emitting
as a diagnostic (see ``contracts.py`` and the plan's Global Constraints).
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

from .agent import main as _agent_main
from .contracts import ValidatedEvent, validate_event
from .store import Store


GATE_STATUS_NOT_READY = "not-ready"  # This gate never emits any other status.

DEFAULT_LIMITATIONS: tuple[str, ...] = (
    "no_monitor_host_deployment_evidence",
    "no_runner_a_or_runner_b_deployment_evidence",
    "no_tls_auth_firewall_evidence",
    "no_real_github_actions_workflow_acceptance",
    "not_a_production_ready_decision",
)

_SAMPLE_RUNNER_ID = "40000000-0000-4000-8000-000000000001"
_SAMPLE_REPOSITORY = "acme/gate-drills"
_SAMPLE_WORKFLOW_RUN_ID = 1
_SAMPLE_RUN_ATTEMPT = 1
_SAMPLE_JOB_ID = 1
_SAMPLE_PRODUCER_EPOCH = "2026-09-18T01"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DrillResult:
    """The redacted, safe-to-persist outcome of one isolated fault drill."""

    capability: str
    passed: bool
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SuiteResult:
    """Aggregate counts only -- never the raw subprocess transcript."""

    passed: bool
    tests_run: int
    failures: int
    errors: int


@dataclass(frozen=True, slots=True)
class GateReport:
    """The complete, redacted local-gate evidence report for issue #5."""

    generated_at: str
    suite: SuiteResult
    drills: tuple[DrillResult, ...]
    fail_open: DrillResult
    status: str = GATE_STATUS_NOT_READY
    limitations: tuple[str, ...] = DEFAULT_LIMITATIONS

    def __post_init__(self) -> None:
        if self.status != GATE_STATUS_NOT_READY:
            raise ValueError("GateReport.status must always be GATE_STATUS_NOT_READY")

    @property
    def local_gate_passed(self) -> bool:
        """Whether every local capability passed -- independent of ``status``.

        ``status`` is always ``not-ready``: local pass/fail never upgrades it,
        because only issue #6's HITL evidence can do that.
        """
        return self.suite.passed and all(drill.passed for drill in self.drills) and self.fail_open.passed


# ---------------------------------------------------------------------------
# Isolated fault drills
# ---------------------------------------------------------------------------


def drill_monitor_restart_recovers_projection(database: Path, *, now: datetime) -> DrillResult:
    """Ingest one job lifecycle event, restart the monitor, and confirm state survives.

    ``database`` must be a fresh, caller-owned temp-file path; this function
    never opens a shared or named production database. "Restart" means
    closing the ``Store`` and reopening a new one against the same on-disk
    file, which forces the monitor's own startup replay path to rebuild
    projections from the append-only event log -- not merely reread a
    persisted table.
    """
    first = Store(database)
    try:
        first.ingest(_sample_job_event("job.started", sequence=1, now=now), now)
    finally:
        first.close()

    restarted = Store(database)
    try:
        job = restarted.current_job(_SAMPLE_REPOSITORY, _SAMPLE_WORKFLOW_RUN_ID, _SAMPLE_RUN_ATTEMPT, _SAMPLE_JOB_ID)
        passed = job is not None and job["state"] == "running" and not restarted.degraded
    finally:
        restarted.close()
    reasons = () if passed else ("restart_projection_mismatch",)
    return DrillResult("monitor_restart_recovery", passed, reasons)


def drill_runner_and_job_offline_then_recovery(database: Path, *, started_at: datetime) -> DrillResult:
    """Run a job past the ten-minute heartbeat timeout, then recover it with a fresh heartbeat."""
    store = Store(database)
    try:
        store.ingest(_sample_job_event("job.started", sequence=1, now=started_at), started_at)
        store.refresh_liveness(started_at + timedelta(seconds=601))
        runner = store.current_runner(_SAMPLE_RUNNER_ID)
        job = store.current_job(_SAMPLE_REPOSITORY, _SAMPLE_WORKFLOW_RUN_ID, _SAMPLE_RUN_ATTEMPT, _SAMPLE_JOB_ID)
        went_offline = (
            runner is not None
            and runner["liveness"] == "offline"
            and job is not None
            and job["liveness"] == "offline"
            and len(store.incidents(active_only=True)) >= 1
        )

        recovered_at = started_at + timedelta(seconds=602)
        store.ingest(_sample_job_event("job.heartbeat", sequence=2, now=recovered_at), recovered_at)
        runner = store.current_runner(_SAMPLE_RUNNER_ID)
        job = store.current_job(_SAMPLE_REPOSITORY, _SAMPLE_WORKFLOW_RUN_ID, _SAMPLE_RUN_ATTEMPT, _SAMPLE_JOB_ID)
        recovered = runner is not None and runner["liveness"] == "online" and job is not None and job["liveness"] == "online"

        passed = went_offline and recovered
    finally:
        store.close()
    reasons = () if passed else ("offline_recovery_state_mismatch",)
    return DrillResult("offline_recovery", passed, reasons)


def drill_sqlite_integrity_failure_is_isolated(database: Path, *, now: datetime) -> DrillResult:
    """Inject a real SQLite failure (a closed connection) and confirm the store degrades safely.

    Closing the connection makes SQLite raise ``sqlite3.ProgrammingError`` --
    a genuine ``sqlite3.DatabaseError`` subclass -- on the next call, which is
    exactly the class ``Store.check_integrity`` already catches. This proves
    the degrade-not-crash contract against a real driver error, without
    fabricating one and without ever touching a shared database file.
    """
    store = Store(database)
    try:
        store.ingest(_sample_job_event("job.started", sequence=1, now=now), now)
    finally:
        # Closing the connection here is the injected failure the rest of
        # this drill exercises; the try/finally only guards against a
        # leaked handle if `ingest` itself raises unexpectedly, which would
        # otherwise let TemporaryDirectory cleanup mask the real error.
        store.close()

    integrity_ok = store.check_integrity()
    health = store.health()
    passed = (not integrity_ok) and health["degraded"] and "integrity_check_failed" in health["reasons"]
    reasons = tuple(health["reasons"]) if passed else ("sqlite_failure_not_isolated",)
    return DrillResult("sqlite_integrity_failure_isolated", passed, reasons)


def drill_cleanup_failure_is_isolated(database: Path, *, now: datetime) -> DrillResult:
    """Inject the same closed-connection failure into retention cleanup and confirm safe degrade."""
    store = Store(database)
    try:
        store.ingest(_sample_job_event("job.started", sequence=1, now=now), now)
    finally:
        # See drill_sqlite_integrity_failure_is_isolated: the close is the
        # injected failure; the try/finally only guards a leaked handle if
        # `ingest` itself raises first.
        store.close()

    removed = store.prune_history(now)
    health = store.health()
    passed = removed == 0 and health["degraded"] and "cleanup_failed" in health["reasons"]
    reasons = tuple(health["reasons"]) if passed else ("cleanup_failure_not_isolated",)
    return DrillResult("cleanup_failure_isolated", passed, reasons)


def drill_notification_failure_is_isolated(database: Path, *, now: datetime) -> DrillResult:
    """Confirm a failing best-effort notifier never loses a persisted incident."""
    store = Store(database)
    try:
        store.set_notifier(_denied_notifier)
        store.ingest(_sample_runner_event("runner.heartbeat", sequence=1, now=now), now)
        store.refresh_liveness(now + timedelta(seconds=601))

        incidents = store.incidents(active_only=True)
        passed = len(incidents) == 1 and incidents[0]["condition"] == "heartbeat_timeout"
    finally:
        store.close()
    reasons = () if passed else ("notification_failure_lost_incident",)
    return DrillResult("notification_failure_isolated", passed, reasons)


def _denied_notifier(_incident: Mapping[str, object]) -> None:
    raise PermissionError("simulated_notification_sink_failure")


def verify_fail_open_contract() -> DrillResult:
    """Confirm a simulated telemetry timeout/rejection never breaks the agent CLI's fail-open exit.

    Uses only the agent's own injectable ``transport``/``clock``/``sleeper``
    -- never a real socket, host, or wall-clock sleep -- so this stays
    runner-independent and fast, like the rest of the gate.
    """
    payload = json.dumps(_sample_heartbeat_payload())
    timeout_clock = _FakeClock()
    timeout_code = _agent_main(
        ["emit", "--endpoint", "http://monitor.invalid/v1/events", "--token", "gate-drill-token", "--event-json", payload],
        transport=_raise_simulated_timeout,
        clock=timeout_clock,
        sleeper=timeout_clock.sleep,
        diagnostic=lambda _message: None,
    )
    rejected_code = _agent_main(
        ["emit", "--endpoint", "http://monitor.invalid/v1/events", "--token", "gate-drill-token", "--event-json", payload],
        transport=lambda _endpoint, _headers, _body: 401,
        diagnostic=lambda _message: None,
    )
    passed = timeout_code == 0 and rejected_code == 0
    reasons = () if passed else ("fail_open_contract_violated",)
    return DrillResult("fail_open_contract", passed, reasons)


class _FakeClock:
    """A monotonic clock the timeout drill advances itself instead of sleeping for real."""

    def __init__(self) -> None:
        self._value = 0.0

    def __call__(self) -> float:
        return self._value

    def sleep(self, seconds: float) -> None:
        self._value += seconds


def _raise_simulated_timeout(_endpoint: str, _headers: Mapping[str, str], _body: bytes) -> int:
    raise TimeoutError("simulated_endpoint_timeout")


# ---------------------------------------------------------------------------
# Full local suite (subprocess summary parsing only -- never raw output)
# ---------------------------------------------------------------------------

Invoke = Callable[[list[str], Mapping[str, str], Path], "subprocess.CompletedProcess[str]"]

# A known lower bound on this repository's suite size. `unittest discover`
# exits 0 and prints "Ran 0 tests in 0.000s" / "OK" when it finds nothing at
# all (wrong --repo-root, a renamed/broken tests/ directory, a discovery
# misconfiguration) -- that must never parse as a passing gate. This floor
# also catches a suite that has silently shrunk, not just an empty one.
# Update it deliberately when tests are intentionally removed in bulk; it is
# a lower bound, so the suite growing past it is always fine.
MIN_EXPECTED_TESTS_RUN = 100

_SUMMARY_RAN = re.compile(r"Ran (\d+) tests? in")
_SUMMARY_FAILED = re.compile(r"FAILED \(([^)]*)\)")
_FAILED_COUNT = re.compile(r"(failures|errors)=(\d+)")


def run_local_suite(repo_root: Path, *, invoke: Invoke | None = None) -> SuiteResult:
    """Run the complete existing unittest suite and return only aggregate counts.

    The raw subprocess transcript (which can contain tracebacks with
    absolute paths and individual test identities on failure) is discarded
    immediately after parsing; it is never stored on the returned
    ``SuiteResult`` or written to the evidence report.
    """
    command = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "src")
    runner = invoke or _default_invoke
    completed = runner(command, env, repo_root)
    return _parse_suite_result(completed)


def _default_invoke(command: list[str], env: Mapping[str, str], cwd: Path) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(command, cwd=cwd, env=dict(env), capture_output=True, text=True, timeout=600)


def _parse_suite_result(completed: "subprocess.CompletedProcess[str]") -> SuiteResult:
    output = f"{completed.stdout}\n{completed.stderr}"
    ran_match = _SUMMARY_RAN.search(output)
    tests_run = int(ran_match.group(1)) if ran_match else -1

    failures = 0
    errors = 0
    failed_match = _SUMMARY_FAILED.search(output)
    if failed_match:
        for key, value in _FAILED_COUNT.findall(failed_match.group(1)):
            if key == "failures":
                failures = int(value)
            elif key == "errors":
                errors = int(value)

    passed = (
        completed.returncode == 0
        and tests_run >= MIN_EXPECTED_TESTS_RUN
        and failures == 0
        and errors == 0
    )
    return SuiteResult(passed=passed, tests_run=tests_run, failures=failures, errors=errors)


# ---------------------------------------------------------------------------
# Report construction, rendering, and persistence
# ---------------------------------------------------------------------------

# Fixed, non-identifying capability-area labels for the "Automated gate" row
# -- what the full local suite exercises, in the vocabulary the plan's
# verification table uses, without naming any individual test.
AUTOMATED_GATE_CAPABILITY_AREAS: tuple[str, ...] = (
    "schema_v1_validation",
    "event_store_projection_and_replay",
    "ten_minute_offline_liveness",
    "retention_and_history_filtering",
    "notification_dedupe_and_incident_lifecycle",
    "http_ingest_and_dashboard_boundary",
    "actions_run_url_passthrough",
    "pr_check_and_rebuild_stage_fallback_projection",
    "fail_open_agent_delivery_and_cli_contract",
)


class GateCrashError(RuntimeError):
    """A local-gate run could not complete.

    Carries only a fixed, stable ``phase`` label and the crashing
    exception's *type name* -- never ``str(error)`` or a traceback, which
    can embed absolute paths or other diagnostic content the project-wide
    redaction contract forbids emitting.
    """

    def __init__(self, phase: str, cause: BaseException) -> None:
        super().__init__(phase)
        self.phase = phase
        self.cause_type = type(cause).__name__


def build_full_report(repo_root: Path) -> GateReport:
    """Run the full suite, every isolated drill, and the fail-open check for real.

    Each drill gets its own fresh temp-file database under a throwaway
    directory this function owns and always cleans up; nothing here ever
    opens a shared or named production database. Any unexpected failure in
    any stage is re-raised as a ``GateCrashError`` carrying only a stable
    phase label, so a caller can report a crash without leaking a traceback.
    """
    now = datetime.now(timezone.utc)
    try:
        suite = run_local_suite(repo_root)
    except Exception as error:
        raise GateCrashError("automated_gate_suite", error) from error

    try:
        with tempfile.TemporaryDirectory(prefix="runner-observability-gate-") as workdir:
            base = Path(workdir)
            drills = (
                drill_monitor_restart_recovers_projection(base / "restart.sqlite", now=now),
                drill_runner_and_job_offline_then_recovery(base / "offline-recovery.sqlite", started_at=now),
                drill_sqlite_integrity_failure_is_isolated(base / "sqlite-integrity-failure.sqlite", now=now),
                drill_cleanup_failure_is_isolated(base / "cleanup-failure.sqlite", now=now),
                drill_notification_failure_is_isolated(base / "notification-failure.sqlite", now=now),
            )
    except Exception as error:
        raise GateCrashError("isolated_fault_drills", error) from error

    try:
        fail_open = verify_fail_open_contract()
    except Exception as error:
        raise GateCrashError("fail_open_contract", error) from error

    return GateReport(
        generated_at=_iso(now),
        status=GATE_STATUS_NOT_READY,
        suite=suite,
        drills=drills,
        fail_open=fail_open,
        limitations=DEFAULT_LIMITATIONS,
    )


def render_report(report: GateReport) -> str:
    """Render the redacted Markdown evidence report for issue #5's local gate."""
    lines = [
        "# Local Verification Gate report (issue #5)",
        "",
        f"Generated at (monitor-owned, UTC): {report.generated_at}",
        f"Status: {report.status}",
        "",
        "This report is produced entirely by runner-independent local tests and",
        "isolated fault drills against throwaway SQLite databases. It contains no",
        "physical-runner, TLS/auth/firewall, or real-workflow evidence, and it is",
        "not a production-ready decision. That decision belongs solely to issue #6",
        "(HITL acceptance) -- see docs/canary-evidence-template.md.",
        "",
        "## Automated gate (full local suite)",
        f"- result: {_verdict(report.suite.passed)}",
        f"- tests_run: {report.suite.tests_run}",
        f"- failures: {report.suite.failures}",
        f"- errors: {report.suite.errors}",
        "- capability areas exercised:",
    ]
    lines.extend(f"  - {area}" for area in AUTOMATED_GATE_CAPABILITY_AREAS)
    lines += [
        "",
        "## Isolated fault drills",
    ]
    for drill in report.drills:
        lines.append(_drill_line(drill))
    lines += [
        "",
        "## Fail-open contract",
        _drill_line(report.fail_open),
        "",
        "## Known limitations",
    ]
    for limitation in report.limitations:
        lines.append(f"- {limitation}")
    lines += [
        "",
        "## HITL handoff",
        "Real-hardware, TLS/auth/firewall, and real-workflow acceptance evidence",
        "is owned exclusively by issue #6 (HITL). This report is not sufficient",
        "for, and does not attempt, a production-ready decision.",
        "",
        "## Next operator action",
        "Open issue #6 and run its HITL deployment/acceptance checklist against",
        "Monitor Host, Runner A, and Runner B using docs/canary-evidence-template.md.",
        "",
        f"Overall local gate result: {_verdict(report.local_gate_passed)} (status remains `{report.status}`)",
    ]
    return "\n".join(lines) + "\n"


def render_crash_report(phase: str, cause_type: str, *, generated_at: str) -> str:
    """Render a report for a run that did not complete.

    This is written in place of -- and only ever overwrites -- a prior run's
    report, so a crashed run can never leave a stale PASS/FAIL report on disk
    looking like this run's evidence. It carries only the fixed ``phase``
    label and the crashing exception's type name, never a message or
    traceback.
    """
    lines = [
        "# Local Verification Gate report (issue #5)",
        "",
        f"Generated at (monitor-owned, UTC): {generated_at}",
        f"Status: {GATE_STATUS_NOT_READY}",
        "",
        "## Gate run CRASHED -- no pass/fail evidence was produced",
        f"- phase: {phase}",
        f"- error_type: {cause_type}",
        "",
        "This run did not complete. Any report that existed before this run",
        "started has been removed; do not treat a prior run's report as",
        "evidence for this run. Diagnose the crash and re-run the gate.",
        "",
        "This crash report is not a production-ready decision either way --",
        "see issue #6 (HITL) for that decision.",
    ]
    return "\n".join(lines) + "\n"


def write_report(path: Path, text: str) -> None:
    """Persist the rendered report text verbatim."""
    path.write_text(text, encoding="utf-8")


def _drill_line(drill: DrillResult) -> str:
    suffix = f" ({', '.join(drill.reasons)})" if drill.reasons else ""
    return f"- {drill.capability}: {_verdict(drill.passed)}{suffix}"


def _verdict(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


# ---------------------------------------------------------------------------
# Sample event builders (drill fixtures only -- never sent over any network)
# ---------------------------------------------------------------------------


def _sample_job_event(event_type: str, *, sequence: int, now: datetime, outcome: str | None = None) -> ValidatedEvent:
    payload: dict[str, object] = {
        "schema_version": 1,
        "event_type": event_type,
        "event_id": _sequence_uuid(sequence),
        "runner_id": _SAMPLE_RUNNER_ID,
        "producer_id": "gate-drill",
        "producer_epoch": _SAMPLE_PRODUCER_EPOCH,
        "producer_sequence": sequence,
        "occurred_at": _iso(now),
        "job": {
            "repository": _SAMPLE_REPOSITORY,
            "workflow_run_id": _SAMPLE_WORKFLOW_RUN_ID,
            "run_attempt": _SAMPLE_RUN_ATTEMPT,
            "job_id": _SAMPLE_JOB_ID,
            "job_name": "gate-drill",
            "run_url": f"https://github.com/{_SAMPLE_REPOSITORY}/actions/runs/{_SAMPLE_WORKFLOW_RUN_ID}",
        },
    }
    if outcome is not None:
        payload["outcome"] = outcome
    return validate_event(payload)


def _sample_runner_event(event_type: str, *, sequence: int, now: datetime) -> ValidatedEvent:
    payload = {
        "schema_version": 1,
        "event_type": event_type,
        "event_id": _sequence_uuid(1000 + sequence),
        "runner_id": _SAMPLE_RUNNER_ID,
        "producer_id": "gate-drill",
        "producer_epoch": _SAMPLE_PRODUCER_EPOCH,
        "producer_sequence": sequence,
        "occurred_at": _iso(now),
    }
    return validate_event(payload)


def _sample_heartbeat_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "runner.heartbeat",
        "event_id": _sequence_uuid(9999),
        "runner_id": _SAMPLE_RUNNER_ID,
        "producer_id": "gate-drill",
        "producer_epoch": _SAMPLE_PRODUCER_EPOCH,
        "producer_sequence": 1,
        "occurred_at": "2026-09-18T01:00:00Z",
    }


def _sequence_uuid(sequence: int) -> str:
    return f"50000000-0000-4000-8000-{sequence:012d}"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# CLI entry point (invoked by scripts/Invoke-VerificationGate.ps1)
# ---------------------------------------------------------------------------


GATE_EXIT_CRASHED = 2  # Distinct from 0 (PASS) / 1 (ran, but FAIL) -- this run never completed.


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="runner-observability-gate")
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--report-path", default="gate-report.md")
    args = parser.parse_args(argv)

    repo_root = Path(args.repo_root).resolve()
    report_path = Path(args.report_path)

    # Never let a crash on this run leave a *previous* run's report sitting
    # on disk looking like this run's evidence -- remove it before doing
    # anything else, so even a hard crash after this point leaves no report
    # rather than a misleadingly stale one.
    try:
        report_path.unlink(missing_ok=True)
    except OSError:
        pass

    try:
        report = build_full_report(repo_root)
    except GateCrashError as crash:
        _write_crash_report(report_path, crash.phase, crash.cause_type)
        print(f"local_verification_gate status={GATE_STATUS_NOT_READY} result=CRASHED phase={crash.phase}")
        return GATE_EXIT_CRASHED
    except Exception as error:  # noqa: BLE001 - last-resort guard: never leak a bare traceback here
        _write_crash_report(report_path, "unexpected", type(error).__name__)
        print(f"local_verification_gate status={GATE_STATUS_NOT_READY} result=CRASHED phase=unexpected")
        return GATE_EXIT_CRASHED

    text = render_report(report)
    write_report(report_path, text)

    print(f"local_verification_gate status={report.status} result={_verdict(report.local_gate_passed)}")
    return 0 if report.local_gate_passed else 1


def _write_crash_report(report_path: Path, phase: str, cause_type: str) -> None:
    text = render_crash_report(phase, cause_type, generated_at=_iso(datetime.now(timezone.utc)))
    write_report(report_path, text)


if __name__ == "__main__":
    raise SystemExit(main())
