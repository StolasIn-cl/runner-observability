"""Monotonic SQLite projections for safe, validated lifecycle events."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping

from .contracts import (
    EVENT_JOB_FINISHED,
    EVENT_JOB_HEARTBEAT,
    EVENT_JOB_STARTED,
    EVENT_RUNNER_HEARTBEAT,
    EVENT_RUNNER_OFFLINE,
    ValidatedEvent,
)
from .health import recover_resource


def apply_event(
    connection: sqlite3.Connection,
    event: ValidatedEvent,
    received_at: str,
    *,
    manage_incidents: bool = True,
    manage_watermarks: bool = True,
) -> bool:
    """Apply an event only when it can advance current state.

    The caller still records rejected late events in append-only history, making
    a non-application diagnosable without allowing current state to regress.
    """
    if manage_watermarks and not _runner_accepts(connection, event):
        return False
    if event.event_type in {EVENT_JOB_STARTED, EVENT_JOB_HEARTBEAT, EVENT_JOB_FINISHED}:
        if not _job_accepts(connection, event) or _older_attempt_than_runner_current(connection, event):
            return False

    if event.event_type == EVENT_RUNNER_HEARTBEAT:
        _upsert_runner(connection, event, received_at, liveness="online", activity=None,
                       heartbeat_at=received_at, terminal_outcome=None, offline_reason=None)
        if manage_incidents:
            recover_resource(connection, "runner", event.runner_id, received_at)
        if manage_watermarks:
            _advance_watermark(connection, event)
        return True
    if event.event_type == EVENT_RUNNER_OFFLINE:
        _upsert_runner(connection, event, received_at, liveness="offline", activity=None,
                       heartbeat_at=None, terminal_outcome=None, offline_reason="explicit_shutdown")
        if manage_watermarks:
            _advance_watermark(connection, event)
        return True
    if event.event_type not in {EVENT_JOB_STARTED, EVENT_JOB_HEARTBEAT, EVENT_JOB_FINISHED}:
        return False

    finished = event.event_type == EVENT_JOB_FINISHED
    outcome = event.payload.get("outcome") if finished else None
    _upsert_runner(connection, event, received_at, liveness="online",
                   activity="idle" if finished else "running", heartbeat_at=None,
                   terminal_outcome=outcome if isinstance(outcome, str) else None, offline_reason=None)
    _upsert_job(connection, event, received_at, "finished" if finished else "running", outcome)
    if manage_incidents:
        recover_resource(connection, "runner", event.runner_id, received_at)
        recover_resource(connection, "job", _job_resource_id(event), received_at)
    if manage_watermarks:
        _advance_watermark(connection, event)
    return True


def _runner_accepts(connection: sqlite3.Connection, event: ValidatedEvent) -> bool:
    row = connection.execute(
        """SELECT producer_sequence FROM producer_watermarks
           WHERE runner_id = ? AND producer_id = ? AND producer_epoch = ?""",
        (event.runner_id, event.producer_id, event.producer_epoch),
    ).fetchone()
    if row is None:
        return True
    return event.producer_sequence > row["producer_sequence"]


def _advance_watermark(connection: sqlite3.Connection, event: ValidatedEvent) -> None:
    connection.execute(
        """INSERT INTO producer_watermarks (runner_id, producer_id, producer_epoch, producer_sequence)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(runner_id, producer_id, producer_epoch) DO UPDATE SET
               producer_sequence = excluded.producer_sequence""",
        (event.runner_id, event.producer_id, event.producer_epoch, event.producer_sequence),
    )


def _older_attempt_than_runner_current(connection: sqlite3.Connection, event: ValidatedEvent) -> bool:
    job = event.payload["job"]
    assert isinstance(job, Mapping)
    row = connection.execute(
        "SELECT current_repository, current_workflow_run_id, current_run_attempt FROM runner_state WHERE runner_id = ?",
        (event.runner_id,),
    ).fetchone()
    return bool(row is not None and row["current_repository"] == job["repository"]
                and row["current_workflow_run_id"] == job["workflow_run_id"]
                and row["current_run_attempt"] is not None and job["run_attempt"] < row["current_run_attempt"])


def _job_accepts(connection: sqlite3.Connection, event: ValidatedEvent) -> bool:
    job = event.payload["job"]
    assert isinstance(job, Mapping)
    row = connection.execute(
        """SELECT state FROM job_state WHERE repository = ? AND workflow_run_id = ?
           AND run_attempt = ? AND job_id = ?""",
        (job["repository"], job["workflow_run_id"], job["run_attempt"], job["job_id"]),
    ).fetchone()
    return row is None or row["state"] != "finished"


def _upsert_runner(
    connection: sqlite3.Connection,
    event: ValidatedEvent,
    received_at: str,
    *,
    liveness: str,
    activity: str | None,
    heartbeat_at: str | None,
    terminal_outcome: str | None,
    offline_reason: str | None,
) -> None:
    existing = connection.execute("SELECT * FROM runner_state WHERE runner_id = ?", (event.runner_id,)).fetchone()
    prior_activity = existing["activity"] if existing is not None else "idle"
    prior_heartbeat = existing["last_heartbeat_at"] if existing is not None else None
    prior_outcome = existing["last_job_outcome"] if existing is not None else None
    job = event.payload.get("job")
    is_job = isinstance(job, Mapping)
    connection.execute(
        """
        INSERT INTO runner_state (
            runner_id, producer_id, producer_epoch, producer_sequence, liveness,
            activity, last_received_at, last_heartbeat_at, last_job_outcome, last_event_id,
            offline_reason, current_repository, current_workflow_run_id, current_run_attempt, current_job_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(runner_id) DO UPDATE SET
            producer_id = excluded.producer_id,
            producer_epoch = excluded.producer_epoch,
            producer_sequence = excluded.producer_sequence,
            liveness = excluded.liveness,
            activity = excluded.activity,
            last_received_at = excluded.last_received_at,
            last_heartbeat_at = excluded.last_heartbeat_at,
            last_job_outcome = excluded.last_job_outcome,
            last_event_id = excluded.last_event_id,
            offline_reason = excluded.offline_reason,
            current_repository = excluded.current_repository,
            current_workflow_run_id = excluded.current_workflow_run_id,
            current_run_attempt = excluded.current_run_attempt,
            current_job_id = excluded.current_job_id
        """,
        (
            event.runner_id,
            event.producer_id,
            event.producer_epoch,
            event.producer_sequence,
            liveness,
            activity if activity is not None else prior_activity,
            received_at,
            heartbeat_at if heartbeat_at is not None else prior_heartbeat,
            terminal_outcome if terminal_outcome is not None else prior_outcome,
            event.event_id,
            offline_reason,
            job["repository"] if is_job else (existing["current_repository"] if existing else None),
            job["workflow_run_id"] if is_job else (existing["current_workflow_run_id"] if existing else None),
            job["run_attempt"] if is_job else (existing["current_run_attempt"] if existing else None),
            job["job_id"] if is_job else (existing["current_job_id"] if existing else None),
        ),
    )


def _upsert_job(
    connection: sqlite3.Connection,
    event: ValidatedEvent,
    received_at: str,
    state: str,
    outcome: object,
) -> None:
    job = event.payload["job"]
    assert isinstance(job, Mapping)  # narrowed by validate_event
    outcome_value = outcome if isinstance(outcome, str) else None
    connection.execute(
        """
        INSERT INTO job_state (
            repository, workflow_run_id, run_attempt, job_id, runner_id, job_name,
            run_url, state, outcome, last_received_at, last_event_id, liveness, last_heartbeat_at, offline_reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'online', ?, NULL)
        ON CONFLICT(repository, workflow_run_id, run_attempt, job_id) DO UPDATE SET
            runner_id = excluded.runner_id,
            job_name = excluded.job_name,
            run_url = excluded.run_url,
            state = excluded.state,
            outcome = excluded.outcome,
            last_received_at = excluded.last_received_at,
            last_event_id = excluded.last_event_id,
            liveness = 'online',
            last_heartbeat_at = excluded.last_heartbeat_at,
            offline_reason = NULL
        """,
        (
            job["repository"],
            job["workflow_run_id"],
            job["run_attempt"],
            job["job_id"],
            event.runner_id,
            job["job_name"],
            job["run_url"],
            state,
            outcome_value,
            received_at,
            event.event_id,
            received_at,
        ),
    )


def _job_resource_id(event: ValidatedEvent) -> str:
    job = event.payload["job"]
    assert isinstance(job, Mapping)
    return f"{job['repository']}:{job['workflow_run_id']}:{job['run_attempt']}:{job['job_id']}"
