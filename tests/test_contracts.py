"""Executable contract for the only accepted v1 telemetry envelope."""

from __future__ import annotations

import unittest

from runner_observability.contracts import (
    EVENT_JOB_FALLBACK,
    EVENT_JOB_FINISHED,
    EVENT_JOB_HEARTBEAT,
    EVENT_JOB_PROGRESS,
    EVENT_JOB_STARTED,
    EVENT_RUNNER_HEARTBEAT,
    EVENT_RUNNER_OFFLINE,
    EVENT_TYPES,
    ValidationError,
    ValidatedEvent,
    validate_event,
)


def lifecycle_event(event_type: str = "job.started") -> dict[str, object]:
    """Return a hand-authored, schema-v1 generic lifecycle event."""
    event: dict[str, object] = {
        "schema_version": 1,
        "event_type": event_type,
        "event_id": "550e8400-e29b-41d4-a716-446655440000",
        "runner_id": "c56a4180-65aa-42ec-a945-5fd21dec0538",
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": 7,
        "occurred_at": "2026-09-18T01:02:03Z",
        "job": {
            "repository": "CyberLink-Team/promeo-pc-promeo",
            "workflow_run_id": 123456789,
            "run_attempt": 2,
            "job_id": 987654321,
            "job_name": "PR validation",
            "run_url": "https://github.com/CyberLink-Team/promeo-pc-promeo/actions/runs/123456789",
        },
    }
    if event_type == "job.finished":
        event["outcome"] = "succeeded"
    return event


class ValidateEventTests(unittest.TestCase):
    def test_accepts_each_generic_lifecycle_event_as_a_typed_v1_envelope(self) -> None:
        """Catches a validator that drops an approved lifecycle event type."""
        payloads = [
            lifecycle_event(EVENT_RUNNER_HEARTBEAT),
            lifecycle_event(EVENT_RUNNER_OFFLINE),
            lifecycle_event(EVENT_JOB_STARTED),
            lifecycle_event(EVENT_JOB_HEARTBEAT),
            lifecycle_event(EVENT_JOB_FINISHED),
        ]
        del payloads[0]["job"]
        del payloads[1]["job"]

        for payload in payloads:
            with self.subTest(event_type=payload["event_type"]):
                event = validate_event(payload)
                self.assertIsInstance(event, ValidatedEvent)
                self.assertEqual(event.schema_version, 1)
                self.assertEqual(event.event_type, payload["event_type"])
                self.assertNotIn("received_at", event.payload)

        self.assertEqual(
            EVENT_TYPES,
            frozenset(
                {
                    EVENT_RUNNER_HEARTBEAT,
                    EVENT_RUNNER_OFFLINE,
                    EVENT_JOB_STARTED,
                    EVENT_JOB_HEARTBEAT,
                    EVENT_JOB_FINISHED,
                    EVENT_JOB_PROGRESS,
                    EVENT_JOB_FALLBACK,
                }
            ),
        )

    def test_rejects_non_v1_schema_with_a_sanitised_reason(self) -> None:
        """Catches accepting a schema the monitor has not explicitly versioned."""
        payload = lifecycle_event()
        payload["schema_version"] = 2

        with self.assertRaisesRegex(ValidationError, r"^unsupported_schema$") as raised:
            validate_event(payload)

        self.assertEqual(raised.exception.reason, "unsupported_schema")
        self.assertNotIn("2", str(raised.exception))

    def test_rejects_fractional_schema_version(self) -> None:
        """Catches Python numeric equality admitting a non-integer schema version."""
        payload = lifecycle_event()
        payload["schema_version"] = 1.0

        with self.assertRaisesRegex(ValidationError, r"^unsupported_schema$"):
            validate_event(payload)

    def test_rejects_job_events_without_the_complete_stable_job_key(self) -> None:
        """Catches accepting an event that cannot identify one job attempt."""
        payload = lifecycle_event()
        del payload["job"]["job_id"]  # type: ignore[index]

        with self.assertRaisesRegex(ValidationError, r"^invalid_event$"):
            validate_event(payload)

    def test_rejects_token_bearing_fields_without_echoing_the_secret(self) -> None:
        """Catches accidental admission or disclosure of credential material."""
        payload = lifecycle_event()
        payload["token"] = "ghp_verySecretValueMustNeverBeStored"

        with self.assertRaisesRegex(ValidationError, r"^invalid_event$") as raised:
            validate_event(payload)

        self.assertNotIn("verySecretValue", str(raised.exception))

    def test_rejects_forbidden_substrings_inside_allowed_job_text(self) -> None:
        """Catches secret or absolute-path data hidden inside an approved field name."""
        path_payload = lifecycle_event()
        path_payload["job"]["job_name"] = "retry C:\\runner\\work\\result.log"  # type: ignore[index]
        token_payload = lifecycle_event()
        token_payload["job"]["job_name"] = "diagnostic ghp_embeddedCredentialNeverStore"

        for case, payload in (("embedded_path", path_payload), ("embedded_token", token_payload)):
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValidationError, r"^invalid_event$") as raised:
                    validate_event(payload)
                self.assertNotIn("runner", str(raised.exception))
                self.assertNotIn("embeddedCredential", str(raised.exception))

    def test_rejects_punctuation_prefixed_unix_path_in_job_name(self) -> None:
        """Catches an absolute Unix path hidden after punctuation in job text."""
        payload = lifecycle_event()
        payload["job"]["job_name"] = "result=/var/lib/runner/output"  # type: ignore[index]

        with self.assertRaisesRegex(ValidationError, r"^invalid_event$"):
            validate_event(payload)

    def test_rejects_generic_credential_syntax_in_job_name(self) -> None:
        """Catches free-text key/value credential syntax hidden in a job name."""
        key_value_payload = lifecycle_event()
        key_value_payload["job"]["job_name"] = "credential=opaque-value"  # type: ignore[index]
        colon_payload = lifecycle_event()
        colon_payload["job"]["job_name"] = "token: opaque-value"  # type: ignore[index]

        for case, payload in (("key_value", key_value_payload), ("colon_value", colon_payload)):
            with self.subTest(case=case):
                with self.assertRaisesRegex(ValidationError, r"^invalid_event$"):
                    validate_event(payload)

    def test_rejects_monitor_owned_received_at(self) -> None:
        """Catches a sender being allowed to supply monitor freshness time."""
        payload = lifecycle_event()
        payload["received_at"] = "2026-09-18T01:02:04Z"

        with self.assertRaisesRegex(ValidationError, r"^invalid_event$"):
            validate_event(payload)

    def test_rejects_unapproved_type_and_raw_fallback_reason(self) -> None:
        """Catches a free-form event/fallback channel bypassing v1 controls."""
        payload = lifecycle_event("job.unreviewed")
        payload["fallback_reason"] = "C:\\secrets\\runner.log contains bearer credential"

        with self.assertRaisesRegex(ValidationError, r"^invalid_event$"):
            validate_event(payload)

    def test_rejects_oversized_payload_before_it_can_reach_storage(self) -> None:
        """Catches an input-size guard that permits raw-log-sized events."""
        payload = lifecycle_event()
        payload["job"]["job_name"] = "x" * (17 * 1024)  # type: ignore[index]

        with self.assertRaisesRegex(ValidationError, r"^payload_too_large$"):
            validate_event(payload)

    def test_accepts_controlled_progress_and_fallback_aggregates(self) -> None:
        """Catches later stage telemetry being forced through an unsafe free-text channel."""
        progress = lifecycle_event("job.progress")
        progress["progress"] = {
            "stage_id": "selective_test",
            "stage_kind": "phase",
            "state": "running",
            "determinate": True,
            "total": 12,
            "completed": 4,
            "failed": 0,
            "pending": 8,
            "fallback_group_count": 0,
            "affected_test_count": 0,
            "attempt": 1,
        }
        fallback = lifecycle_event("job.fallback")
        fallback["fallback"] = {
            "target_stage_id": "sequential_group_rerun",
            "reason_code": "parallel_group_failed",
            "completed_groups": 3,
            "total_groups": 6,
            "fallback_group_count": 1,
            "affected_test_count": 4,
        }

        self.assertEqual(validate_event(progress).event_type, "job.progress")
        self.assertEqual(validate_event(fallback).event_type, "job.fallback")

    def test_validated_payload_does_not_alias_the_caller_input(self) -> None:
        """Catches callers mutating a validated event after the boundary check."""
        payload = lifecycle_event()
        event = validate_event(payload)
        payload["job"]["job_name"] = "changed after validation"  # type: ignore[index]

        self.assertEqual(event.payload["job"]["job_name"], "PR validation")


if __name__ == "__main__":
    unittest.main()
