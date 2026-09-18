"""Baseline SQLite projections for safe, validated lifecycle events."""

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


def apply_event(connection: sqlite3.Connection, event: ValidatedEvent, received_at: str) -> None:
    """Advance the generic runner/job views inside the caller's transaction."""
    if event.event_type == EVENT_RUNNER_HEARTBEAT:
        _upsert_runner(
            connection,
            event,
            received_at,
            liveness="online",
            activity=None,
            heartbeat_at=received_at,
            terminal_outcome=None,
        )
        return
    if event.event_type == EVENT_RUNNER_OFFLINE:
        _upsert_runner(
            connection,
            event,
            received_at,
            liveness="offline",
            activity=None,
            heartbeat_at=None,
            terminal_outcome=None,
        )
        return
    if event.event_type not in {EVENT_JOB_STARTED, EVENT_JOB_HEARTBEAT, EVENT_JOB_FINISHED}:
        return

    finished = event.event_type == EVENT_JOB_FINISHED
    outcome = event.payload.get("outcome") if finished else None
    _upsert_runner(
        connection,
        event,
        received_at,
        liveness="online",
        activity="idle" if finished else "running",
        heartbeat_at=None,
        terminal_outcome=outcome if isinstance(outcome, str) else None,
    )
    _upsert_job(connection, event, received_at, "finished" if finished else "running", outcome)


def _upsert_runner(
    connection: sqlite3.Connection,
    event: ValidatedEvent,
    received_at: str,
    *,
    liveness: str,
    activity: str | None,
    heartbeat_at: str | None,
    terminal_outcome: str | None,
) -> None:
    existing = connection.execute(
        "SELECT activity, last_heartbeat_at, last_job_outcome FROM runner_state WHERE runner_id = ?",
        (event.runner_id,),
    ).fetchone()
    prior_activity = existing[0] if existing is not None else "idle"
    prior_heartbeat = existing[1] if existing is not None else None
    prior_outcome = existing[2] if existing is not None else None
    connection.execute(
        """
        INSERT INTO runner_state (
            runner_id, producer_id, producer_epoch, producer_sequence, liveness,
            activity, last_received_at, last_heartbeat_at, last_job_outcome, last_event_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(runner_id) DO UPDATE SET
            producer_id = excluded.producer_id,
            producer_epoch = excluded.producer_epoch,
            producer_sequence = excluded.producer_sequence,
            liveness = excluded.liveness,
            activity = excluded.activity,
            last_received_at = excluded.last_received_at,
            last_heartbeat_at = excluded.last_heartbeat_at,
            last_job_outcome = excluded.last_job_outcome,
            last_event_id = excluded.last_event_id
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
            run_url, state, outcome, last_received_at, last_event_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(repository, workflow_run_id, run_attempt, job_id) DO UPDATE SET
            runner_id = excluded.runner_id,
            job_name = excluded.job_name,
            run_url = excluded.run_url,
            state = excluded.state,
            outcome = excluded.outcome,
            last_received_at = excluded.last_received_at,
            last_event_id = excluded.last_event_id
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
        ),
    )
