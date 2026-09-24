"""Atomic, bounded, file-backed telemetry outbox storage."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import json
import math
import os
from pathlib import Path
import tempfile
import time
from typing import Any

from .contracts import ValidationError, validate_event


Diagnostic = Callable[[str], None]


@dataclass(frozen=True, slots=True)
class OutboxLimits:
    """Bounded storage and drain settings for one local outbox."""

    max_events: int = 1000
    max_bytes: int = 32 * 1024 * 1024
    max_drain_events: int = 100
    max_drain_seconds: float = 5.0

    def __post_init__(self) -> None:
        for value in (self.max_events, self.max_bytes, self.max_drain_events):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError("invalid_outbox_limits")
        if isinstance(self.max_drain_seconds, bool) or not isinstance(self.max_drain_seconds, (int, float)):
            raise ValueError("invalid_outbox_limits")
        if not math.isfinite(float(self.max_drain_seconds)) or self.max_drain_seconds <= 0:
            raise ValueError("invalid_outbox_limits")


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    """Safe result of an outbox enqueue attempt."""

    event_id: str
    status: str
    reason: str | None = None


@dataclass(frozen=True, slots=True)
class DrainResult:
    """Counts from one bounded outbox drain pass."""

    delivered: int
    retained: int
    dead_lettered: int
    corrupt: int


class DurableOutbox:
    """Persist validated events as atomic file-per-event queue entries."""

    def __init__(
        self,
        root: Path | str,
        *,
        limits: OutboxLimits = OutboxLimits(),
        diagnostic: Diagnostic | None = None,
    ) -> None:
        self.root = Path(root)
        self.pending_root = self.root / "pending"
        self.dead_letter_root = self.root / "dead-letter"
        self.limits = limits
        self._diagnostic = _safe_diagnostic(diagnostic or (lambda _message: None))

    def enqueue(self, event: object, *, queued_at: str | None = None) -> EnqueueResult:
        """Validate and atomically persist one event without storing credentials."""
        try:
            validated = validate_event(event)
        except ValidationError as error:
            return EnqueueResult("", "rejected", error.reason)

        event_payload = _json_payload(validated.payload)
        event_id = validated.event_id
        pending_path = self.pending_root / f"{event_id}.json"
        dead_letter_path = self.dead_letter_root / f"{event_id}.json"
        existing = self._existing_event(pending_path, dead_letter_path)
        if existing is not None:
            if existing == event_payload:
                return EnqueueResult(event_id, "duplicate")
            return EnqueueResult(event_id, "conflict", "outbox_event_conflict")

        queued_timestamp = _queued_timestamp(queued_at)
        if queued_timestamp is None:
            return EnqueueResult(event_id, "rejected", "outbox_invalid_timestamp")
        envelope = {"queued_at": queued_timestamp, "event": event_payload}
        encoded = _encode(envelope)
        try:
            existing_count, existing_bytes = self._capacity_usage()
        except OSError:
            self._diagnostic("outbox_capacity_check_failed")
            return EnqueueResult(event_id, "rejected", "outbox_storage_unavailable")
        if existing_count >= self.limits.max_events or existing_bytes + len(encoded) > self.limits.max_bytes:
            return EnqueueResult(event_id, "rejected", "outbox_capacity_exceeded")

        temporary_path: Path | None = None
        try:
            self.pending_root.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.pending_root,
                prefix=f".{event_id}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(encoded)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, pending_path)
            temporary_path = None
        except (OSError, TypeError):
            self._diagnostic("outbox_write_failed")
            return EnqueueResult(event_id, "rejected", "outbox_storage_unavailable")
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
        return EnqueueResult(event_id, "queued")

    def pending_events(self) -> tuple[list[tuple[Path, dict[str, object]]], int]:
        """Return valid pending envelopes and the number of corrupt files skipped."""
        valid: list[tuple[Path, dict[str, object]]] = []
        corrupt = 0
        for path in self._json_files(self.pending_root):
            envelope = self._read_envelope(path)
            if envelope is None:
                corrupt += 1
                self._diagnostic("outbox_corrupt_event")
                continue
            valid.append((path, envelope))
        valid.sort(key=lambda item: (str(item[1]["queued_at"]), str(item[1]["event"]["event_id"])))
        return valid, corrupt

    def drain(
        self,
        deliver: Callable[[object, str, str], Any],
        endpoint: str,
        token: str,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> DrainResult:
        """Deliver pending events within the configured count/time budget."""
        del sleeper  # The bounded delivery function owns its retry/backoff policy.
        started_at = clock()
        pending, corrupt = self.pending_events()
        delivered = 0
        retained = 0
        dead_lettered = 0
        for index, (path, envelope) in enumerate(pending):
            if index >= self.limits.max_drain_events or clock() - started_at >= self.limits.max_drain_seconds:
                retained += len(pending) - index
                break
            event = envelope["event"]
            try:
                result = deliver(event, endpoint, token)
            except Exception:
                self._diagnostic("outbox_delivery_failed")
                retained += 1
                continue
            if result.delivered:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                except OSError:
                    self._diagnostic("outbox_remove_failed")
                    retained += 1
                else:
                    delivered += 1
                continue
            reason = _safe_delivery_reason(getattr(result, "reason", None))
            if reason in _TRANSIENT_REASONS:
                retained += 1
                continue
            if self._move_to_dead_letter(path, envelope, reason):
                dead_lettered += 1
            else:
                retained += 1
        return DrainResult(delivered, retained, dead_lettered, corrupt)

    def _move_to_dead_letter(
        self, pending_path: Path, envelope: dict[str, object], reason: str
    ) -> bool:
        temporary_path: Path | None = None
        event_id = str(envelope["event"]["event_id"])
        destination = self.dead_letter_root / f"{event_id}.json"
        dead_letter = dict(envelope)
        dead_letter["dead_letter_reason"] = reason
        try:
            self.dead_letter_root.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.dead_letter_root,
                prefix=f".{event_id}.",
                suffix=".tmp",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                temporary.write(_encode(dead_letter))
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, destination)
            temporary_path = None
            pending_path.unlink()
            return True
        except (OSError, TypeError):
            self._diagnostic("outbox_dead_letter_failed")
            return False
        finally:
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass

    def _existing_event(self, *paths: Path) -> dict[str, object] | None:
        for path in paths:
            if not path.is_file():
                continue
            envelope = self._read_envelope(path)
            if envelope is None:
                return {}
            event = envelope.get("event")
            return event if isinstance(event, dict) else {}
        return None

    def _capacity_usage(self) -> tuple[int, int]:
        count = 0
        total_bytes = 0
        for directory in (self.pending_root, self.dead_letter_root):
            for path in self._json_files(directory):
                count += 1
                total_bytes += path.stat().st_size
        return count, total_bytes

    def _read_envelope(self, path: Path) -> dict[str, object] | None:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, Mapping) or not isinstance(raw.get("queued_at"), str):
                return None
            event = raw.get("event")
            validated = validate_event(event)
            normalized = _json_payload(validated.payload)
            if normalized != event:
                return None
            return {"queued_at": raw["queued_at"], "event": normalized}
        except (OSError, UnicodeError, json.JSONDecodeError, ValidationError, TypeError, ValueError):
            return None

    @staticmethod
    def _json_files(directory: Path) -> list[Path]:
        try:
            return sorted(path for path in directory.glob("*.json") if path.is_file())
        except OSError:
            return []


def _queued_timestamp(value: str | None) -> str | None:
    if value is None:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return value if isinstance(value, str) and value else None


_TRANSIENT_REASONS = frozenset({"temporary_network_failure", "temporary_http_failure"})
_KNOWN_DELIVERY_REASONS = _TRANSIENT_REASONS | frozenset(
    {"rejected_http_response", "transport_failure", "delivery_failed"}
)


def _safe_delivery_reason(reason: object) -> str:
    if isinstance(reason, str) and reason in _KNOWN_DELIVERY_REASONS:
        return reason
    return "delivery_failed"


def _encode(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _json_payload(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _json_payload(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_json_payload(item) for item in value]
    return value


def _safe_diagnostic(diagnostic: Diagnostic) -> Diagnostic:
    def report(message: str) -> None:
        try:
            diagnostic(message)
        except Exception:
            pass

    return report
