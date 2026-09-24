"""Transactional SQLite event log and baseline current-state views."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
from typing import Any

from .contracts import ValidatedEvent, validate_event
from .health import Notifier, notify_safely, open_incident
from .projection import apply_event


LIVENESS_TIMEOUT_SECONDS = 10 * 60
RETENTION_DAYS = 7


@dataclass(frozen=True, slots=True)
class IngestResult:
    """The successful outcome of a new or idempotently retried event."""

    event_id: str
    accepted: bool
    duplicate: bool
    projection_applied: bool = False
    producer_watermark: int | None = None


class Store:
    """Own a local SQLite database containing safe events and generic views."""

    def __init__(self, database: str | Path = ":memory:") -> None:
        # The monitor's HTTP server serializes Store calls with its own lock,
        # while serving them from request threads.
        self._connection = sqlite3.connect(str(database), check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        self._notifier: Notifier | None = None
        self._degraded_reasons: set[str] = set()
        self._migrate()
        self.check_integrity()
        self._replay_if_projections_are_missing()

    def close(self) -> None:
        """Close the database connection owned by this store."""
        self._connection.close()

    def ingest(self, event: ValidatedEvent, received_at: datetime | str) -> IngestResult:
        """Atomically append a validated event and advance its projections once."""
        validated = _validated_event(event)
        monitor_received_at = _normalise_received_at(received_at)
        notifications: list[dict[str, Any]] = []
        with self._connection:
            duplicate = self._connection.execute(
                "SELECT projection_applied FROM events WHERE event_id = ?", (validated.event_id,)
            ).fetchone()
            if duplicate is not None:
                return IngestResult(
                    validated.event_id,
                    accepted=True,
                    duplicate=True,
                    projection_applied=bool(duplicate["projection_applied"]),
                    producer_watermark=self._producer_watermark(validated),
                )
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
            applied = apply_event(self._connection, validated, monitor_received_at)
            self._connection.execute(
                "UPDATE events SET projection_applied = ? WHERE event_id = ?",
                (int(applied), validated.event_id),
            )
            if applied and validated.event_type == "runner.offline":
                incident = open_incident(
                    self._connection, "runner", validated.runner_id, "explicit_shutdown", monitor_received_at
                )
                if incident is not None:
                    notifications.append(incident)
        for incident in notifications:
            notify_safely(self._notifier, incident)
        return IngestResult(
            validated.event_id,
            accepted=True,
            duplicate=False,
            projection_applied=bool(applied),
            producer_watermark=self._producer_watermark(validated),
        )

    def _producer_watermark(self, event: ValidatedEvent) -> int | None:
        row = self._connection.execute(
            """SELECT producer_sequence FROM producer_watermarks
               WHERE runner_id = ? AND producer_id = ? AND producer_epoch = ?""",
            (event.runner_id, event.producer_id, event.producer_epoch),
        ).fetchone()
        return None if row is None else int(row["producer_sequence"])

    def current_runner(self, runner_id: str) -> dict[str, Any] | None:
        """Return the baseline current view for one runner, if seen."""
        row = self._connection.execute(
            "SELECT * FROM runner_state WHERE runner_id = ?", (runner_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def list_runners(self) -> list[dict[str, Any]]:
        """Return every known runner's current baseline view for read-only presentation."""
        rows = self._connection.execute(
            "SELECT * FROM runner_state ORDER BY last_received_at DESC, runner_id ASC"
        ).fetchall()
        return [dict(row) for row in rows]

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

    def history(self, filters: Mapping[str, object] | None = None) -> list[dict[str, Any]]:
        """Return append-only history, optionally filtered without claiming an audit archive."""
        active_filters = dict(filters or {})
        _validate_history_filters(active_filters)
        rows = self._connection.execute(
            "SELECT * FROM events ORDER BY event_row_id ASC"
        ).fetchall()
        history: list[dict[str, Any]] = []
        for row in rows:
            item = _history_item_from_row(row)
            if _matches_history_filters(item, active_filters):
                history.append(item)
        return history

    def history_page(
        self,
        filters: Mapping[str, object] | None = None,
        *,
        page: int = 1,
        page_size: int = 20,
        exclude_event_types: Collection[str] | None = None,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return one newest-first history page without materialising all retained events."""
        if page < 1 or page_size < 1:
            raise ValueError("invalid_history_pagination")

        active_filters = dict(filters or {})
        _validate_history_filters(active_filters)
        excluded = tuple(sorted(set(exclude_event_types or ())))
        clauses: list[str] = []
        parameters: list[object] = []
        if excluded:
            placeholders = ", ".join("?" for _ in excluded)
            clauses.append(f"event_type NOT IN ({placeholders})")
            parameters.extend(excluded)
        if "runner_id" in active_filters:
            clauses.append("runner_id = ?")
            parameters.append(active_filters["runner_id"])

        query = "SELECT * FROM events"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY event_row_id DESC"

        offset = (page - 1) * page_size
        matched = 0
        results: list[dict[str, Any]] = []
        for row in self._connection.execute(query, parameters):
            item = _history_item_from_row(row)
            if not _matches_history_filters(item, active_filters):
                continue
            if matched < offset:
                matched += 1
                continue
            results.append(item)
            if len(results) > page_size:
                break
        has_next = len(results) > page_size
        return results[:page_size], has_next

    def recent_events(
        self, limit: int, *, exclude_event_types: Collection[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return only the most recent bounded slice of the log, oldest of the slice first.

        Unlike ``history()``, this pushes the row-count bound into SQL via
        ``LIMIT`` so a live-view caller (the dashboard) never has to load and
        JSON-decode the entire retained log -- which, across seven days of
        retention and per-job heartbeats, can be tens of thousands of rows --
        just to look at the most recent activity.
        """
        excluded = tuple(sorted(set(exclude_event_types or ())))
        query = "SELECT * FROM events"
        parameters: list[object] = []
        if excluded:
            placeholders = ", ".join("?" for _ in excluded)
            query += f" WHERE event_type NOT IN ({placeholders})"
            parameters.extend(excluded)
        query += " ORDER BY event_row_id DESC LIMIT ?"
        parameters.append(limit)
        rows = self._connection.execute(query, parameters).fetchall()
        return [_history_item_from_row(row) for row in reversed(rows)]

    def recent_job_events(
        self,
        repository: str,
        workflow_run_id: int,
        run_attempt: int,
        job_id: int,
        *,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Return the newest bounded events for one stable job-attempt key.

        The job key lives inside the validated JSON payload rather than in
        separate event columns.  Filtering it in SQLite keeps a busy runner
        from crowding another runner's current-job timeline out of the live
        dashboard window.
        """
        if limit < 1:
            raise ValueError("invalid_recent_job_event_limit")
        rows = self._connection.execute(
            """
            SELECT * FROM events
            WHERE json_extract(payload_json, '$.job.repository') = ?
              AND json_extract(payload_json, '$.job.workflow_run_id') = ?
              AND json_extract(payload_json, '$.job.run_attempt') = ?
              AND json_extract(payload_json, '$.job.job_id') = ?
            ORDER BY event_row_id DESC
            LIMIT ?
            """,
            (repository, workflow_run_id, run_attempt, job_id, limit),
        ).fetchall()
        return [_history_item_from_row(row) for row in reversed(rows)]

    @property
    def degraded(self) -> bool:
        """Whether a non-destructive integrity, replay, or cleanup failure was observed."""
        return bool(self._degraded_reasons)

    def health(self) -> dict[str, object]:
        """Return monitor-owned health state suitable for a later read-only API."""
        return {"degraded": self.degraded, "reasons": tuple(sorted(self._degraded_reasons))}

    def set_notifier(self, notifier: Notifier | None) -> None:
        """Set an optional best-effort toast hook; it never participates in a transaction."""
        self._notifier = notifier

    def incidents(self, active_only: bool = False) -> list[dict[str, Any]]:
        """Return persisted incident records in stable creation order."""
        query = "SELECT * FROM incidents"
        if active_only:
            query += " WHERE active = 1"
        query += " ORDER BY incident_id ASC"
        entries = []
        for row in self._connection.execute(query).fetchall():
            item = dict(row)
            item["active"] = bool(item["active"])
            entries.append(item)
        return entries

    def refresh_liveness(self, now: datetime | str) -> list[dict[str, Any]]:
        """Mark stale runner/running-job views offline after ten monitor-owned minutes."""
        current = _normalise_received_at(now)
        cutoff = _parse_received_at(current) - timedelta(seconds=LIVENESS_TIMEOUT_SECONDS)
        notifications: list[dict[str, Any]] = []
        with self._connection:
            stale_runners = [
                row for row in self._connection.execute(
                    "SELECT runner_id, last_received_at FROM runner_state WHERE liveness = 'online'"
                ).fetchall()
                if _parse_received_at(row["last_received_at"]) < cutoff
            ]
            for row in stale_runners:
                runner_id = row["runner_id"]
                self._connection.execute(
                    "UPDATE runner_state SET liveness = 'offline', offline_reason = 'heartbeat_timeout' WHERE runner_id = ?",
                    (runner_id,),
                )
                created = open_incident(self._connection, "runner", runner_id, "heartbeat_timeout", current)
                if created is not None:
                    notifications.append(created)
            stale_jobs = [row for row in self._connection.execute(
                """SELECT repository, workflow_run_id, run_attempt, job_id, last_heartbeat_at FROM job_state
                   WHERE state = 'running' AND liveness = 'online'"""
            ).fetchall() if _parse_received_at(row["last_heartbeat_at"]) < cutoff]
            for row in stale_jobs:
                resource_id = _job_resource_id(row)
                self._connection.execute(
                    """UPDATE job_state SET liveness = 'offline', offline_reason = 'heartbeat_timeout'
                       WHERE repository = ? AND workflow_run_id = ? AND run_attempt = ? AND job_id = ?""",
                    (row["repository"], row["workflow_run_id"], row["run_attempt"], row["job_id"]),
                )
                created = open_incident(self._connection, "job", resource_id, "heartbeat_timeout", current)
                if created is not None:
                    notifications.append(created)
        for incident in notifications:
            notify_safely(self._notifier, incident)
        return notifications

    def replay(self) -> bool:
        """Rebuild projections transactionally from events, preserving readable state on failure."""
        if not self._history_is_complete():
            self._degraded_reasons.add("replay_incomplete_history")
            return False
        try:
            with self._connection:
                rows = self._connection.execute("SELECT * FROM events ORDER BY event_row_id ASC").fetchall()
                offline_runners = self._connection.execute(
                    "SELECT runner_id, offline_reason FROM runner_state WHERE liveness = 'offline'"
                ).fetchall()
                offline_jobs = self._connection.execute(
                    """SELECT repository, workflow_run_id, run_attempt, job_id, offline_reason FROM job_state
                       WHERE liveness = 'offline'"""
                ).fetchall()
                active_incidents = self._connection.execute(
                    "SELECT resource_kind, resource_id, condition FROM incidents WHERE active = 1"
                ).fetchall()
                self._connection.execute("DELETE FROM runner_state")
                self._connection.execute("DELETE FROM job_state")
                self._connection.execute("DELETE FROM producer_watermarks")
                for row in rows:
                    payload = json.loads(row["payload_json"])
                    validated = validate_event(payload)
                    applied = apply_event(
                        self._connection,
                        validated,
                        row["received_at"],
                        manage_incidents=False,
                    )
                    self._connection.execute(
                        "UPDATE events SET projection_applied = ? WHERE event_id = ?",
                        (int(applied), row["event_id"]),
                    )
                for row in offline_runners:
                    self._connection.execute(
                        "UPDATE runner_state SET liveness = 'offline', offline_reason = ? WHERE runner_id = ?",
                        (row["offline_reason"], row["runner_id"]),
                    )
                for row in offline_jobs:
                    self._connection.execute(
                        """UPDATE job_state SET liveness = 'offline', offline_reason = ?
                           WHERE repository = ? AND workflow_run_id = ? AND run_attempt = ? AND job_id = ?""",
                        (row["offline_reason"], row["repository"], row["workflow_run_id"], row["run_attempt"], row["job_id"]),
                    )
                self._restore_offline_incident_liveness(active_incidents)
        except (ValueError, TypeError, json.JSONDecodeError, sqlite3.DatabaseError):
            self._degraded_reasons.add("replay_failed")
            return False
        self._degraded_reasons.discard("replay_failed")
        self._degraded_reasons.discard("replay_incomplete_history")
        return True

    def prune_history(self, now: datetime | str) -> int:
        """Remove only event rows older than seven monitor-owned days."""
        cutoff = _parse_received_at(_normalise_received_at(now)) - timedelta(days=RETENTION_DAYS)
        try:
            with self._connection:
                expired = [
                    row["event_row_id"] for row in self._connection.execute(
                        "SELECT event_row_id, received_at FROM events"
                    ).fetchall() if _parse_received_at(row["received_at"]) < cutoff
                ]
                result = None
                if expired:
                    placeholders = ", ".join("?" for _ in expired)
                    result = self._connection.execute(f"DELETE FROM events WHERE event_row_id IN ({placeholders})", expired)
                    self._connection.execute(
                        "INSERT INTO monitor_meta (key, value) VALUES ('projection_history_complete', '0') "
                        "ON CONFLICT(key) DO UPDATE SET value = excluded.value"
                    )
        except sqlite3.DatabaseError:
            self._degraded_reasons.add("cleanup_failed")
            return 0
        self._degraded_reasons.discard("cleanup_failed")
        return result.rowcount if result is not None else 0

    def check_integrity(self) -> bool:
        """Run SQLite's integrity check and expose a degraded state without deleting data."""
        try:
            values = [row[0] for row in self._connection.execute("PRAGMA integrity_check").fetchall()]
        except sqlite3.DatabaseError:
            self._degraded_reasons.add("integrity_check_failed")
            return False
        if values != ["ok"]:
            self._degraded_reasons.add("integrity_check_failed")
            return False
        self._degraded_reasons.discard("integrity_check_failed")
        return True

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
                    payload_json TEXT NOT NULL,
                    projection_applied INTEGER NOT NULL DEFAULT 0
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
                    last_event_id TEXT NOT NULL,
                    offline_reason TEXT,
                    current_repository TEXT,
                    current_workflow_run_id INTEGER,
                    current_run_attempt INTEGER,
                    current_job_id INTEGER
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
                    liveness TEXT NOT NULL DEFAULT 'online',
                    last_heartbeat_at TEXT,
                    offline_reason TEXT,
                    PRIMARY KEY (repository, workflow_run_id, run_attempt, job_id)
                );
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id INTEGER PRIMARY KEY,
                    resource_kind TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    condition TEXT NOT NULL,
                    active INTEGER NOT NULL,
                    opened_at TEXT NOT NULL,
                    closed_at TEXT,
                    last_changed_at TEXT NOT NULL,
                    UNIQUE(resource_kind, resource_id, condition)
                );
                CREATE TABLE IF NOT EXISTS producer_watermarks (
                    runner_id TEXT NOT NULL,
                    producer_id TEXT NOT NULL,
                    producer_epoch TEXT NOT NULL,
                    producer_sequence INTEGER NOT NULL,
                    PRIMARY KEY (runner_id, producer_id, producer_epoch)
                );
                CREATE TABLE IF NOT EXISTS monitor_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._connection.execute(
                "INSERT OR IGNORE INTO monitor_meta (key, value) VALUES ('projection_history_complete', '1')"
            )
            _add_column_if_missing(self._connection, "events", "projection_applied", "INTEGER NOT NULL DEFAULT 0")
            _add_column_if_missing(self._connection, "runner_state", "offline_reason", "TEXT")
            _add_column_if_missing(self._connection, "runner_state", "current_repository", "TEXT")
            _add_column_if_missing(self._connection, "runner_state", "current_workflow_run_id", "INTEGER")
            _add_column_if_missing(self._connection, "runner_state", "current_run_attempt", "INTEGER")
            _add_column_if_missing(self._connection, "runner_state", "current_job_id", "INTEGER")
            _add_column_if_missing(self._connection, "job_state", "liveness", "TEXT NOT NULL DEFAULT 'online'")
            _add_column_if_missing(self._connection, "job_state", "last_heartbeat_at", "TEXT")
            _add_column_if_missing(self._connection, "job_state", "offline_reason", "TEXT")

    def _replay_if_projections_are_missing(self) -> None:
        try:
            event_count = self._connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        except sqlite3.DatabaseError:
            self._degraded_reasons.add("projection_check_failed")
            return
        if event_count:
            self.replay()

    def _history_is_complete(self) -> bool:
        row = self._connection.execute(
            "SELECT value FROM monitor_meta WHERE key = 'projection_history_complete'"
        ).fetchone()
        return row is None or row["value"] == "1"

    def _restore_offline_incident_liveness(self, incidents: list[sqlite3.Row]) -> None:
        """Keep replay from fabricating recovery for an active persisted incident."""
        for incident in incidents:
            if incident["resource_kind"] == "runner":
                self._connection.execute(
                    "UPDATE runner_state SET liveness = 'offline', offline_reason = ? WHERE runner_id = ?",
                    (incident["condition"], incident["resource_id"]),
                )
            elif incident["resource_kind"] == "job" and incident["condition"] == "heartbeat_timeout":
                job = _parse_job_resource_id(incident["resource_id"])
                if job is not None:
                    self._connection.execute(
                        """UPDATE job_state SET liveness = 'offline', offline_reason = 'heartbeat_timeout'
                           WHERE repository = ? AND workflow_run_id = ? AND run_attempt = ? AND job_id = ?""",
                        job,
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


def _parse_received_at(value: str) -> datetime:
    """Parse a canonical monitor timestamp produced by ``_normalise_received_at``."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _add_column_if_missing(connection: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def _job_resource_id(row: sqlite3.Row) -> str:
    return f"{row['repository']}:{row['workflow_run_id']}:{row['run_attempt']}:{row['job_id']}"


def _parse_job_resource_id(resource_id: str) -> tuple[str, int, int, int] | None:
    parts = resource_id.split(":")
    if len(parts) != 4:
        return None
    repository, workflow_run_id, run_attempt, job_id = parts
    try:
        return repository, int(workflow_run_id), int(run_attempt), int(job_id)
    except ValueError:
        return None


def _history_item_from_row(row: sqlite3.Row) -> dict[str, Any]:
    """Shared row-to-history-item transform used by both ``history()`` and ``recent_events()``."""
    item = dict(row)
    item["payload"] = json.loads(item.pop("payload_json"))
    item.pop("event_row_id")
    item["projection_applied"] = bool(item["projection_applied"])
    return item


def _matches_history_filters(item: Mapping[str, object], filters: Mapping[str, object]) -> bool:
    """Apply the intentionally small, safe history query vocabulary in memory."""
    payload = item["payload"]
    job = payload.get("job", {}) if isinstance(payload, Mapping) else {}
    if not isinstance(job, Mapping):
        job = {}
    for key, expected in filters.items():
        if key == "runner_id" and item["runner_id"] != expected:
            return False
        if key == "repository" and job.get("repository") != expected:
            return False
        if key == "workflow_run_id" and job.get("workflow_run_id") != expected:
            return False
        if key == "outcome" and payload.get("outcome") != expected:
            return False
        if key == "received_after" and _parse_received_at(item["received_at"]) < _parse_received_at(_normalise_received_at(expected)):
            return False
        if key == "received_before" and _parse_received_at(item["received_at"]) > _parse_received_at(_normalise_received_at(expected)):
            return False
    return True


def _validate_history_filters(filters: Mapping[str, object]) -> None:
    allowed = {"runner_id", "repository", "workflow_run_id", "outcome", "received_after", "received_before"}
    if any(key not in allowed for key in filters):
        raise ValueError("invalid_history_filter")
