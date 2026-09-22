"""Aggregation of monitor-owned state into a safe command-center snapshot.

``dashboard_snapshot`` never calls GitHub, never infers a run URL, and never
surfaces raw logs, secrets, individual test/group identities, or fallback
reason text. Every value it emits is read back from fields that
``contracts.validate_event`` already accepted, or is a small static display
label (approved phase ids and their unit names) chosen in this module --
except that ``contracts.validate_event`` only constrains ``stage_id``,
``stage_kind``, ``target_stage_id``, and ``reason_code`` to a charset, not to
the approved PERS-03 vocabulary. A sender is therefore free to put arbitrary
identifier-shaped text in those fields (e.g. a stage id that happens to spell
out a group or test name). This module is the last line of defense for that:
any such value that is not one of the fixed, approved phase ids is collapsed
to ``UNRECOGNISED_STAGE_ID`` before it is ever placed in a snapshot, a
timeline summary, or the event feed. ``reason_code`` is never rendered at
all -- the approved fallback summary (PERS-03 ticket 05) is defined as
completed/total groups, fallback group count, affected test count, and
target phase only; a free-text-shaped "reason" was never part of that
contract, so it is accepted at ingestion (contracts.py already forbids actual
secrets/paths there) but dropped here rather than displayed.

IMPORTANT -- this function is not purely read-only. It calls
``Store.refresh_liveness(now)`` before reading state, which can write
``runner_state``/``job_state`` and open/notify incidents. Nothing else in
this codebase currently runs a periodic ``refresh_liveness`` sweep (there is
no background timer in ``__main__.py``), so a dashboard load is, today, the
only place that ten-minute heartbeat timeout actually gets applied. This is
a deliberate choice to reuse the store's own already-tested, idempotent
liveness logic rather than inventing a second one here -- but it means a GET
of the dashboard has a real, bounded, side effect on persisted state, and
callers/tests should not describe it as read-only.

``job.progress``/``job.fallback`` events are appended to the append-only event
log by ``Store.ingest`` (see store.py) but are intentionally not folded into
the persisted ``runner_state``/``job_state`` projections by projection.py.
This module recomputes their aggregate presentation at read time from a
*bounded* recent slice of the log (``Store.recent_events``), not the full
retained history -- see ``DASHBOARD_EVENT_WINDOW`` below. It does not
re-derive liveness, attempt-guard, or terminal-outcome semantics, which stay
owned by the store.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta, timezone
from typing import Any

from .contracts import (
    EVENT_JOB_FALLBACK,
    EVENT_JOB_FINISHED,
    EVENT_JOB_HEARTBEAT,
    EVENT_JOB_PROGRESS,
    EVENT_JOB_STARTED,
    EVENT_RUNNER_HEARTBEAT,
)
from .store import Store, _parse_received_at


HISTORY_FILTER_KEYS = (
    "runner_id",
    "repository",
    "workflow_run_id",
    "outcome",
    "received_after",
    "received_before",
)
EVENT_FEED_LIMIT = 7
JOB_TIMELINE_LIMIT = 5
# Asia/Taipei has no daylight-saving transitions; a named fixed offset keeps
# the standard-library runtime independent of an external tzdata package.
DASHBOARD_TIME_ZONE = timezone(timedelta(hours=8), "Asia/Taipei")

# How many of the most recent events (across every runner/job) the live
# command-center view considers. This bounds both the SQL work (Store.
# recent_events pushes the LIMIT into the query) and the sorting/aggregation
# done here while the caller holds the store's request lock (see server.py).
# A job whose phase history is older than this window keeps its last-known
# phase/fallback values -- because those are only ever the *latest* update
# per stage/job, which is recent by definition for anything still relevant --
# but very old entries can drop out of that job's rendered timeline. Full,
# unbounded, filterable history remains available from GET /api/history,
# which is unaffected by this bound.
DASHBOARD_EVENT_WINDOW = 500

# Fixed phase ids approved by PERS-03 for the `pr_check` job's stage-level
# progress. `full_suite` is a `selective_test` mode, not a separate phase.
PR_CHECK_PHASE_IDS = (
    "lint_check",
    "selective_test",
    "parallel_4_group",
    "sequential_group_rerun",
    "parallel_4_tests_rerun",
    "sequential_tests_rerun",
    "merge_coverage",
)

# Only these two rebuild phases are detail-tracked per shard; `plan`, `cpp`,
# and `reduce` stay generic job-level lifecycle with no fabricated progress.
REBUILD_PHASE_IDS = ("rebuild_test_mapping", "unsafe_group_detect")

_ALL_APPROVED_STAGE_IDS = frozenset(PR_CHECK_PHASE_IDS) | frozenset(REBUILD_PHASE_IDS)

# Never rendered verbatim: any `stage_id`/`target_stage_id` that is not one of
# the ids above -- valid per contracts.py's charset check, but outside the
# PERS-03 approved vocabulary -- is replaced with this fixed label.
UNRECOGNISED_STAGE_ID = "unrecognised_stage"

_PHASE_UNIT_LABELS: Mapping[str, str] = {
    "lint_check": "files",
    "selective_test": "groups",
    "parallel_4_group": "groups",
    "sequential_group_rerun": "groups",
    "parallel_4_tests_rerun": "tests",
    "sequential_tests_rerun": "tests",
    "merge_coverage": "reports",
    "rebuild_test_mapping": "tests",
    "unsafe_group_detect": "folders",
}


def dashboard_snapshot(store: Store, now: datetime | str) -> dict[str, Any]:
    """Return one command-center snapshot of known runners and their jobs.

    Not read-only: refreshes liveness against the caller-supplied,
    monitor-owned ``now`` first (see the module docstring), so a dashboard
    load always reflects the ten-minute heartbeat timeout the store already
    enforces, without this module inventing its own freshness rule.
    """
    store.refresh_liveness(now)
    window = store.recent_events(DASHBOARD_EVENT_WINDOW)
    feed_window = store.recent_events(EVENT_FEED_LIMIT, exclude_event_types={EVENT_RUNNER_HEARTBEAT})
    health = store.health()
    runners = [_runner_view(store, row, window) for row in store.list_runners()]
    return {
        "generated_at": _display_time(now),
        "health": {"degraded": health["degraded"], "reasons": list(health["reasons"])},
        "history_filter_keys": list(HISTORY_FILTER_KEYS),
        "incidents": [_incident_view(item) for item in store.incidents()],
        # Keep all rows for history and diagnostics, but give the live rail a
        # projection that excludes retained offline identities from old
        # process-local runner IDs.
        "runners": runners,
        "active_runners": [runner for runner in runners if runner["liveness"] == "online"],
        "event_feed": _event_feed(feed_window),
    }


def _runner_view(store: Store, runner: Mapping[str, Any], window: list[dict[str, Any]]) -> dict[str, Any]:
    current_job = None
    if (
        runner["current_repository"] is not None
        and runner["current_workflow_run_id"] is not None
        and runner["current_run_attempt"] is not None
        and runner["current_job_id"] is not None
    ):
        job_row = store.current_job(
            runner["current_repository"],
            runner["current_workflow_run_id"],
            runner["current_run_attempt"],
            runner["current_job_id"],
        )
        if job_row is not None:
            current_job = _job_view(
                job_row,
                _job_history(window, job_row),
                store.recent_job_events(
                    job_row["repository"],
                    job_row["workflow_run_id"],
                    job_row["run_attempt"],
                    job_row["job_id"],
                    limit=JOB_TIMELINE_LIMIT,
                ),
            )
    return {
        "runner_id": runner["runner_id"],
        "alias": runner_alias(runner["runner_id"]),
        "liveness": runner["liveness"],
        "activity": runner["activity"],
        "offline_reason": runner["offline_reason"],
        "last_received_at": _display_time(runner["last_received_at"]),
        "last_heartbeat_at": _display_time(runner["last_heartbeat_at"]),
        "last_job_outcome": runner["last_job_outcome"],
        "current_job": current_job,
    }


def _job_view(
    job_row: Mapping[str, Any],
    job_history: list[dict[str, Any]],
    timeline_history: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "repository": job_row["repository"],
        "workflow_run_id": job_row["workflow_run_id"],
        "run_attempt": job_row["run_attempt"],
        "job_id": job_row["job_id"],
        "job_name": job_row["job_name"],
        "run_url": job_row["run_url"],
        "state": job_row["state"],
        "outcome": job_row["outcome"],
        "liveness": job_row["liveness"],
        "offline_reason": job_row["offline_reason"],
        "last_received_at": _display_time(job_row["last_received_at"]),
        "last_heartbeat_at": _display_time(job_row["last_heartbeat_at"]),
        "progress_unreported": _progress_unreported(job_row, job_history),
        "phases": _aggregate_phases(job_history),
        "fallback": _latest_fallback(job_history),
        "timeline": [_timeline_entry(item) for item in reversed(timeline_history)],
    }


def _job_history(window: list[dict[str, Any]], job_row: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Filter the bounded recent-events window down to one job's events, received order."""
    key = (job_row["repository"], job_row["workflow_run_id"], job_row["run_attempt"], job_row["job_id"])
    matches = []
    for item in window:
        job = _job_field(item)
        if job is None:
            continue
        if (job.get("repository"), job.get("workflow_run_id"), job.get("run_attempt"), job.get("job_id")) == key:
            matches.append(item)
    return matches


def _display_stage_id(stage_id: str) -> str:
    """Collapse anything outside the approved PERS-03 phase vocabulary to a fixed label."""
    return stage_id if stage_id in _ALL_APPROVED_STAGE_IDS else UNRECOGNISED_STAGE_ID


def _received_at_key(item: Mapping[str, Any]) -> datetime:
    """Order by monitor-owned received time, not sender-controlled producer sequence.

    ``producer_sequence`` is only monotonic within one (runner, producer,
    producer_epoch) triple (see projection.py's watermark logic); it resets
    after an agent restart changes the epoch. Using monitor-owned
    ``received_at`` -- parsed, not string-compared -- avoids an old epoch's
    higher sequence number ever outranking a genuinely newer update.
    """
    return _parse_received_at(item["received_at"])


def _aggregate_phases(job_history: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Keep only the latest `job.progress` per approved stage id, by received time."""
    progress_events = sorted(
        (item for item in job_history if item["event_type"] == EVENT_JOB_PROGRESS),
        key=_received_at_key,
    )
    phases: dict[str, dict[str, Any]] = {}
    for item in progress_events:
        progress = item["payload"]["progress"]
        display_id = _display_stage_id(progress["stage_id"])
        phases[display_id] = _phase_view(display_id, progress, item)
    return phases


def _phase_view(display_id: str, progress: Mapping[str, Any], item: Mapping[str, Any]) -> dict[str, Any]:
    if display_id in PR_CHECK_PHASE_IDS:
        category = "pr_check_phase"
    elif display_id in REBUILD_PHASE_IDS:
        category = "rebuild_phase"
    else:
        category = "generic"
    return {
        "stage_id": display_id,
        "category": category,
        "state": progress["state"],
        "determinate": progress["determinate"],
        "total": progress["total"],
        "completed": progress["completed"],
        "failed": progress["failed"],
        "pending": progress["pending"],
        "fallback_group_count": progress["fallback_group_count"],
        "affected_test_count": progress["affected_test_count"],
        "attempt": progress["attempt"],
        "unit_label": _PHASE_UNIT_LABELS.get(display_id, "units"),
        "received_at": _display_time(item["received_at"]),
        "occurred_at": _display_time(item["occurred_at"]),
    }


def _latest_fallback(job_history: list[dict[str, Any]]) -> dict[str, Any] | None:
    fallback_events = sorted(
        (item for item in job_history if item["event_type"] == EVENT_JOB_FALLBACK),
        key=_received_at_key,
    )
    if not fallback_events:
        return None
    latest = fallback_events[-1]
    fallback = latest["payload"]["fallback"]
    return {
        "target_stage_id": _display_stage_id(fallback["target_stage_id"]),
        "completed_groups": fallback["completed_groups"],
        "total_groups": fallback["total_groups"],
        "fallback_group_count": fallback["fallback_group_count"],
        "affected_test_count": fallback["affected_test_count"],
        "received_at": _display_time(latest["received_at"]),
        "occurred_at": _display_time(latest["occurred_at"]),
    }


def _progress_unreported(job_row: Mapping[str, Any], job_history: list[dict[str, Any]]) -> bool:
    """An informational hint only: a fresh heartbeat with no new quantifiable progress.

    Offline liveness always takes priority -- this is never true for a job the
    store has already marked offline, regardless of any progress history.
    """
    if job_row["liveness"] != "online" or job_row["state"] != "running":
        return False
    last_heartbeat_at = job_row["last_heartbeat_at"]
    if last_heartbeat_at is None:
        return False
    progress_events = [item for item in job_history if item["event_type"] == EVENT_JOB_PROGRESS]
    if not progress_events:
        return True
    latest_progress_received_at = max(_received_at_key(item) for item in progress_events)
    return latest_progress_received_at < _parse_received_at(last_heartbeat_at)


def _timeline_entry(item: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "event_type": item["event_type"],
        "received_at": _display_time(item["received_at"]),
        "occurred_at": _display_time(item["occurred_at"]),
        "summary": _summarize(item),
    }


def _summarize(item: Mapping[str, Any]) -> str:
    event_type = item["event_type"]
    payload = item["payload"]
    if event_type == EVENT_JOB_STARTED:
        return "job started"
    if event_type == EVENT_JOB_HEARTBEAT:
        return "heartbeat"
    if event_type == EVENT_JOB_FINISHED:
        return f"finished: {payload.get('outcome')}"
    if event_type == EVENT_JOB_PROGRESS:
        progress = payload["progress"]
        stage_id = _display_stage_id(progress["stage_id"])
        unit = _PHASE_UNIT_LABELS.get(stage_id, "units")
        if progress["determinate"]:
            return f"{stage_id}: {progress['state']} ({progress['completed']}/{progress['total']} {unit})"
        return f"{stage_id}: {progress['state']} (indeterminate)"
    if event_type == EVENT_JOB_FALLBACK:
        fallback = payload["fallback"]
        target = _display_stage_id(fallback["target_stage_id"])
        return (
            f"fallback -> {target} "
            f"({fallback['fallback_group_count']} groups, {fallback['affected_test_count']} tests)"
        )
    return event_type


def _event_feed(window: list[dict[str, Any]]) -> list[dict[str, Any]]:
    ordered = [
        item
        for item in sorted(window, key=_received_at_key, reverse=True)
        if item["event_type"] != EVENT_RUNNER_HEARTBEAT
    ][:EVENT_FEED_LIMIT]
    return [
        {
            "event_type": item["event_type"],
            "runner_id": item["runner_id"],
            "runner_alias": runner_alias(item["runner_id"]),
            "received_at": _display_time(item["received_at"]),
            "occurred_at": _display_time(item["occurred_at"]),
            "job_name": _job_field_value(item, "job_name"),
            "run_url": _job_field_value(item, "run_url"),
            "summary": _summarize(item),
        }
        for item in ordered
    ]


def _job_field(item: Mapping[str, Any]) -> Mapping[str, Any] | None:
    payload = item["payload"]
    job = payload.get("job") if isinstance(payload, Mapping) else None
    return job if isinstance(job, Mapping) else None


def _job_field_value(item: Mapping[str, Any], key: str) -> Any | None:
    job = _job_field(item)
    return job.get(key) if job is not None else None


def runner_alias(runner_id: str) -> str:
    """A stable, non-secret display label; v1 carries no operator-set alias field."""
    return f"runner-{runner_id[:8]}"


def _incident_view(incident: Mapping[str, Any]) -> dict[str, Any]:
    result = dict(incident)
    for key in ("opened_at", "closed_at", "last_changed_at"):
        if result.get(key) is not None:
            result[key] = _display_time(result[key])
    return result


def history_event_view(item: Mapping[str, Any]) -> dict[str, Any]:
    """Format one history item for the dashboard without changing stored data."""
    result = dict(item)
    result["runner_alias"] = runner_alias(str(item["runner_id"]))
    result["received_at"] = _display_time(str(item["received_at"]))
    result["occurred_at"] = _display_time(str(item["occurred_at"]))
    payload = item.get("payload")
    if isinstance(payload, Mapping):
        display_payload = dict(payload)
        if display_payload.get("occurred_at") is not None:
            display_payload["occurred_at"] = _display_time(str(display_payload["occurred_at"]))
        result["payload"] = display_payload
    return result


def _display_time(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    parsed = value if isinstance(value, datetime) else _parse_received_at(value)
    return parsed.astimezone(DASHBOARD_TIME_ZONE).strftime("%Y-%m-%d %H:%M:%S")
