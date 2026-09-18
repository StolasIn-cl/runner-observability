"""Transactional SQLite event log and baseline current-state views."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from .contracts import ValidatedEvent, validate_event
from .projection import apply_event


@dataclass(frozen=True, slots=True)
class IngestResult:
    """The successful outcome of a new or idempotently retried event."""

    event_id: str
    accepted: bool
    duplicate: bool


class Store:
    """Own a local SQLite database containing safe events and generic views."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(database))
        self._connection.row_factory = sqlite3.Row
        self._migrate()

    def close(self) -> None:
        """Close the database connection owned by this store."""
        self._connection.close()

    def ingest(self, event: ValidatedEvent, received_at: datetime | str) -> IngestResult:
        """Atomically append a validated event and advance its projections once."""
        validated = _validated_event(event)
        monitor_received_at = _normalise_received_at(received_at)
        with self._connection:
            duplicate = self._connection.execute(
                "SELECT 1 FROM events WHERE event_id = ?", (validated.event_id,)
            ).fetchone()
            if duplicate is not None:
                return IngestResult(validated.event_id, accepted=True, duplicate=True)
            self._connection.execute(
                """
                INSERT INTO events (
                    event_id, event_type, runner_id, producer_id, producer_epoch,
                    producer_sequence, occurred_at, received_at, payload_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validated.event_id,
                    validated.event_type,
                    validated.runner_id,
                    validated.producer_id,
                    validated.producer_epoch,
                    validated.producer_sequence,
                    validated.occurred_at,
                    monitor_received_at,
                    json.dumps(_thaw(validated.payload), ensure_ascii=True, separators=(",", ":")),
                ),
            )
            apply_event(self._connection, validated, monitor_received_at)
        return IngestResult(validated.event_id, accepted=True, duplicate=False)

    def current_runner(self, runner_id: str) -> dict[str, Any] | None:
        """Return the baseline current view for one runner, if seen."""
        row = self._connection.execute(
            "SELECT * FROM runner_state WHERE runner_id = ?", (runner_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def current_job(
        self, repository: str, workflow_run_id: int, run_attempt: int, job_id: int
    ) -> dict[str, Any] | None:
        """Return the current view for a stable job-attempt key, if seen."""
        row = self._connection.execute(
            """
            SELECT * FROM job_state
            WHERE repository = ? AND workflow_run_id = ? AND run_attempt = ? AND job_id = ?
            """,
            (repository, workflow_run_id, run_attempt, job_id),
        ).fetchone()
        return dict(row) if row is not None else None

    def history(self) -> list[dict[str, Any]]:
        """Return append-only accepted event history in insertion order."""
        rows = self._connection.execute(
            "SELECT * FROM events ORDER BY event_row_id ASC"
        ).fetchall()
        history: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            item.pop("event_row_id")
            history.append(item)
        return history

    def _migrate(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_row_id INTEGER PRIMARY KEY,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    runner_id TEXT NOT NULL,
                    producer_id TEXT NOT NULL,
                    producer_epoch TEXT NOT NULL,
                    producer_sequence INTEGER NOT NULL,
                    occurred_at TEXT NOT NULL,
                    received_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runner_state (
                    runner_id TEXT PRIMARY KEY,
                    producer_id TEXT NOT NULL,
                    producer_epoch TEXT NOT NULL,
                    producer_sequence INTEGER NOT NULL,
                    liveness TEXT NOT NULL,
                    activity TEXT NOT NULL,
                    last_received_at TEXT NOT NULL,
                    last_heartbeat_at TEXT,
                    last_job_outcome TEXT,
                    last_event_id TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS job_state (
                    repository TEXT NOT NULL,
                    workflow_run_id INTEGER NOT NULL,
                    run_attempt INTEGER NOT NULL,
                    job_id INTEGER NOT NULL,
                    runner_id TEXT NOT NULL,
                    job_name TEXT NOT NULL,
                    run_url TEXT NOT NULL,
                    state TEXT NOT NULL,
                    outcome TEXT,
                    last_received_at TEXT NOT NULL,
                    last_event_id TEXT NOT NULL,
                    PRIMARY KEY (repository, workflow_run_id, run_attempt, job_id)
                );
                """
            )


def _validated_event(event: ValidatedEvent) -> ValidatedEvent:
    """Defend persistence from manually forged ``ValidatedEvent`` instances."""
    if not isinstance(event, ValidatedEvent):
        raise TypeError("event must be a ValidatedEvent")
    return validate_event(_thaw(event.payload))


def _thaw(value: object) -> object:
    """Copy immutable contract data into JSON-compatible validation input."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _normalise_received_at(received_at: datetime | str) -> str:
    """Accept only an aware monitor-owned timestamp and store a stable UTC form."""
    if isinstance(received_at, datetime):
        parsed = received_at
    elif isinstance(received_at, str):
        try:
            parsed = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise ValueError("invalid_received_at") from error
    else:
        raise TypeError("received_at must be an aware datetime or ISO-8601 string")
    if parsed.tzinfo is None:
        raise ValueError("invalid_received_at")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
