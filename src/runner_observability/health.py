"""Persisted incident state and health primitives for the local monitor."""

from __future__ import annotations

from collections.abc import Callable
import sqlite3
from typing import Any


Notifier = Callable[[dict[str, Any]], None]


def open_incident(
    connection: sqlite3.Connection, resource_kind: str, resource_id: str, condition: str, now: str
) -> dict[str, Any] | None:
    """Persist one edge-triggered active incident, returning it only on the edge."""
    row = connection.execute(
        "SELECT * FROM incidents WHERE resource_kind = ? AND resource_id = ? AND condition = ?",
        (resource_kind, resource_id, condition),
    ).fetchone()
    if row is not None and row["active"]:
        return None
    if row is None:
        connection.execute(
            """INSERT INTO incidents (resource_kind, resource_id, condition, active, opened_at, closed_at, last_changed_at)
               VALUES (?, ?, ?, 1, ?, NULL, ?)""",
            (resource_kind, resource_id, condition, now, now),
        )
    else:
        connection.execute(
            """UPDATE incidents SET active = 1, opened_at = ?, closed_at = NULL, last_changed_at = ?
               WHERE resource_kind = ? AND resource_id = ? AND condition = ?""",
            (now, now, resource_kind, resource_id, condition),
        )
    created = connection.execute(
        "SELECT * FROM incidents WHERE resource_kind = ? AND resource_id = ? AND condition = ?",
        (resource_kind, resource_id, condition),
    ).fetchone()
    return dict(created) if created is not None else None


def recover_resource(connection: sqlite3.Connection, resource_kind: str, resource_id: str, now: str) -> None:
    """Close active offline incidents without producing a recovery notification."""
    connection.execute(
        """UPDATE incidents SET active = 0, closed_at = ?, last_changed_at = ?
           WHERE resource_kind = ? AND resource_id = ? AND active = 1""",
        (now, now, resource_kind, resource_id),
    )


def notify_safely(notifier: Notifier | None, incident: dict[str, Any]) -> None:
    """Notification is best effort and must not alter committed monitor state."""
    if notifier is None:
        return
    try:
        notifier(incident)
    except Exception:
        return
