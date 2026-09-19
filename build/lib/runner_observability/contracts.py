"""Closed, typed validation for the runner-observability schema-v1 boundary."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import json
import re
from types import MappingProxyType
from typing import Any
from urllib.parse import urlparse
from uuid import UUID


SCHEMA_VERSION = 1
MAX_PAYLOAD_BYTES = 16 * 1024

EVENT_RUNNER_HEARTBEAT = "runner.heartbeat"
EVENT_RUNNER_OFFLINE = "runner.offline"
EVENT_JOB_STARTED = "job.started"
EVENT_JOB_HEARTBEAT = "job.heartbeat"
EVENT_JOB_FINISHED = "job.finished"
EVENT_JOB_PROGRESS = "job.progress"
EVENT_JOB_FALLBACK = "job.fallback"
EVENT_TYPES = frozenset({EVENT_RUNNER_HEARTBEAT, EVENT_RUNNER_OFFLINE, EVENT_JOB_STARTED, EVENT_JOB_HEARTBEAT, EVENT_JOB_FINISHED, EVENT_JOB_PROGRESS, EVENT_JOB_FALLBACK})

_COMMON_FIELDS = frozenset({"schema_version", "event_type", "event_id", "runner_id", "producer_id", "producer_epoch", "producer_sequence", "occurred_at"})
_JOB_FIELDS = frozenset({"repository", "workflow_run_id", "run_attempt", "job_id", "job_name", "run_url"})
_PROGRESS_FIELDS = frozenset({"stage_id", "stage_kind", "state", "determinate", "total", "completed", "failed", "pending", "fallback_group_count", "affected_test_count", "attempt"})
_FALLBACK_FIELDS = frozenset({"target_stage_id", "reason_code", "completed_groups", "total_groups", "fallback_group_count", "affected_test_count"})
_FORBIDDEN_FIELD_FRAGMENT = re.compile(r"(?:token|bearer|authorization|password|secret|raw_log|environment|command|(?:^|_)path(?:$|_)|pr_(?:title|body)|pull_request|test_(?:name|id)|group_(?:name|id)|fallback_reason)", re.IGNORECASE)
_SECRET_VALUE = re.compile(r"(?:\bbearer\s+\S+|\bgh[pousr]_[A-Za-z0-9_]+|\bgithub_pat_[A-Za-z0-9_]+)", re.IGNORECASE)
_ABSOLUTE_PATH = re.compile(r"(?:(?<![A-Za-z0-9])[A-Za-z]:[\\/]|\\\\|(?:^|\s)/)")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
_STAGE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_JOB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()\[\]&+,'-]*(?: / [A-Za-z0-9][A-Za-z0-9 ._()\[\]&+,'-]*)*$")


class ValidationError(ValueError):
    """A rejection with a safe, stable public reason code only."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ValidatedEvent:
    """An immutable event that is safe to hand to persistence and display layers."""

    schema_version: int
    event_type: str
    event_id: str
    runner_id: str
    producer_id: str
    producer_epoch: str
    producer_sequence: int
    occurred_at: str
    payload: Mapping[str, Any]


def validate_event(payload: object) -> ValidatedEvent:
    """Validate one complete schema-v1 envelope without retaining caller-owned data."""
    _validate_payload_size(payload)
    if not isinstance(payload, Mapping):
        _reject_invalid()
    _validate_no_forbidden_content(payload)
    schema_version = payload.get("schema_version")
    if type(schema_version) is not int or schema_version != SCHEMA_VERSION:
        raise ValidationError("unsupported_schema")
    event_type = _required_string(payload, "event_type", 64)
    if event_type not in EVENT_TYPES:
        _reject_invalid()
    _validate_envelope_fields(payload, event_type)
    event_id = _required_uuid(payload, "event_id")
    runner_id = _required_uuid(payload, "runner_id")
    producer_id = _required_identifier(payload, "producer_id")
    producer_epoch = _required_identifier(payload, "producer_epoch")
    producer_sequence = _required_positive_int(payload, "producer_sequence")
    occurred_at = _required_timestamp(payload, "occurred_at")
    if event_type in {EVENT_RUNNER_HEARTBEAT, EVENT_RUNNER_OFFLINE}:
        _validate_exact_keys(payload, _COMMON_FIELDS)
    else:
        _validate_job_event(payload, event_type)
    return ValidatedEvent(SCHEMA_VERSION, event_type, event_id, runner_id, producer_id, producer_epoch, producer_sequence, occurred_at, _freeze(payload))


def _validate_payload_size(payload: object) -> None:
    try:
        encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError):
        _reject_invalid()
    if len(encoded) > MAX_PAYLOAD_BYTES:
        raise ValidationError("payload_too_large")


def _validate_no_forbidden_content(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or _FORBIDDEN_FIELD_FRAGMENT.search(key):
                _reject_invalid()
            _validate_no_forbidden_content(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_no_forbidden_content(item)
    elif isinstance(value, str) and (_SECRET_VALUE.search(value) or _ABSOLUTE_PATH.search(value)):
        _reject_invalid()


def _validate_envelope_fields(payload: Mapping[str, object], event_type: str) -> None:
    expected = _COMMON_FIELDS
    if event_type in {EVENT_JOB_STARTED, EVENT_JOB_HEARTBEAT}:
        expected |= {"job"}
    elif event_type == EVENT_JOB_FINISHED:
        expected |= {"job", "outcome"}
    elif event_type == EVENT_JOB_PROGRESS:
        expected |= {"job", "progress"}
    elif event_type == EVENT_JOB_FALLBACK:
        expected |= {"job", "fallback"}
    _validate_exact_keys(payload, expected)


def _validate_job_event(payload: Mapping[str, object], event_type: str) -> None:
    job = payload.get("job")
    if not isinstance(job, Mapping):
        _reject_invalid()
    _validate_exact_keys(job, _JOB_FIELDS)
    repository = _required_string(job, "repository", 201)
    if not _REPOSITORY.fullmatch(repository):
        _reject_invalid()
    for key in ("workflow_run_id", "run_attempt", "job_id"):
        _required_positive_int(job, key)
    job_name = _required_string(job, "job_name", 200)
    if not _JOB_NAME.fullmatch(job_name):
        _reject_invalid()
    _required_run_url(job, "run_url")
    if event_type == EVENT_JOB_FINISHED:
        if _required_string(payload, "outcome", 16) not in {"succeeded", "failed", "cancelled"}:
            _reject_invalid()
    elif event_type == EVENT_JOB_PROGRESS:
        _validate_progress(payload.get("progress"))
    elif event_type == EVENT_JOB_FALLBACK:
        _validate_fallback(payload.get("fallback"))


def _validate_progress(progress: object) -> None:
    if not isinstance(progress, Mapping):
        _reject_invalid()
    _validate_exact_keys(progress, _PROGRESS_FIELDS)
    _required_stage_id(progress, "stage_id")
    _required_stage_id(progress, "stage_kind")
    if _required_string(progress, "state", 16) not in {"running", "completed", "failed", "cancelled"} or not isinstance(progress.get("determinate"), bool):
        _reject_invalid()
    for key in ("total", "completed", "failed", "pending", "fallback_group_count", "affected_test_count"):
        _required_nonnegative_int(progress, key)
    _required_positive_int(progress, "attempt")


def _validate_fallback(fallback: object) -> None:
    if not isinstance(fallback, Mapping):
        _reject_invalid()
    _validate_exact_keys(fallback, _FALLBACK_FIELDS)
    _required_stage_id(fallback, "target_stage_id")
    _required_stage_id(fallback, "reason_code")
    for key in ("completed_groups", "total_groups", "fallback_group_count", "affected_test_count"):
        _required_nonnegative_int(fallback, key)


def _validate_exact_keys(payload: Mapping[str, object], expected: frozenset[str]) -> None:
    if set(payload) != expected:
        _reject_invalid()


def _required_string(payload: Mapping[str, object], key: str, maximum: int) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value or len(value) > maximum:
        _reject_invalid()
    return value


def _required_uuid(payload: Mapping[str, object], key: str) -> str:
    value = _required_string(payload, key, 36)
    try:
        UUID(value)
    except (ValueError, AttributeError):
        _reject_invalid()
    return value


def _required_identifier(payload: Mapping[str, object], key: str) -> str:
    value = _required_string(payload, key, 64)
    if not _IDENTIFIER.fullmatch(value):
        _reject_invalid()
    return value


def _required_stage_id(payload: Mapping[str, object], key: str) -> str:
    value = _required_string(payload, key, 64)
    if not _STAGE_ID.fullmatch(value):
        _reject_invalid()
    return value


def _required_positive_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        _reject_invalid()
    return value


def _required_nonnegative_int(payload: Mapping[str, object], key: str) -> int:
    value = payload.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _reject_invalid()
    return value


def _required_timestamp(payload: Mapping[str, object], key: str) -> str:
    value = _required_string(payload, key, 35)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        _reject_invalid()
    if parsed.tzinfo is None:
        _reject_invalid()
    return value


def _required_run_url(payload: Mapping[str, object], key: str) -> str:
    value = _required_string(payload, key, 256)
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/actions/runs/[1-9][0-9]*", parsed.path):
        _reject_invalid()
    return value


def _freeze(value: object) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    return value


def _reject_invalid() -> None:
    raise ValidationError("invalid_event")
