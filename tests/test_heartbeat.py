"""Runner heartbeat state, delivery, and scheduler contract tests."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runner_observability.agent import DeliveryResult
from runner_observability.heartbeat import (
    HeartbeatConfig,
    HeartbeatConfigError,
    HeartbeatLoop,
    HeartbeatState,
    HeartbeatStateError,
)


RUNNER_A = "20000000-0000-4000-8000-000000000001"
RUNNER_B = "20000000-0000-4000-8000-000000000002"


@dataclass
class FakeClock:
    value: float = 0.0

    def __call__(self) -> float:
        return self.value


class FakeStopEvent:
    def __init__(self, clock: FakeClock, stop_after_waits: int) -> None:
        self.clock = clock
        self.stop_after_waits = stop_after_waits
        self.wait_count = 0
        self.waits: list[float | None] = []
        self.stopped = False

    def is_set(self) -> bool:
        return self.stopped

    def wait(self, timeout: float | None = None) -> bool:
        self.waits.append(timeout)
        if timeout is not None:
            self.clock.value += timeout
        self.wait_count += 1
        if self.wait_count >= self.stop_after_waits:
            self.stopped = True
        return self.stopped


class HeartbeatTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="runner-heartbeat-test-")
        self.base = Path(self.temp.name)
        self.token_path = self.base / "token.txt"
        self.state_path = self.base / "state.json"
        self.token_path.write_text("secret-token\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def config(self, *, runner_id: str = RUNNER_A, **overrides: object) -> HeartbeatConfig:
        values: dict[str, object] = {
            "endpoint": "https://monitor.example.test:8765",
            "token_file": str(self.token_path),
            "runner_id": runner_id,
            "producer_id": "runner-heartbeat",
            "state_file": str(self.state_path),
            "interval_seconds": 60,
            "network_poll_seconds": 5,
        }
        values.update(overrides)
        return HeartbeatConfig(**values)

    def test_state_file_is_created_atomically_without_token_and_sequences_are_monotonic(self) -> None:
        config = self.config()

        state = HeartbeatState.load(config.state_file, config.runner_id, config.producer_id)
        next_state, sequence = state.reserve(config.state_file)

        saved = json.loads(self.state_path.read_text(encoding="utf-8"))
        self.assertEqual(sequence, 1)
        self.assertEqual(next_state.next_sequence, 2)
        self.assertEqual(saved["runner_id"], RUNNER_A)
        self.assertEqual(saved["next_sequence"], 2)
        self.assertNotIn("secret-token", self.state_path.read_text(encoding="utf-8"))

        reloaded = HeartbeatState.load(config.state_file, config.runner_id, config.producer_id)
        self.assertEqual(reloaded.producer_epoch, state.producer_epoch)
        self.assertEqual(reloaded.next_sequence, 2)

    def test_state_file_from_another_runner_is_rejected(self) -> None:
        state = HeartbeatState.load(self.state_path, RUNNER_A, "runner-heartbeat")

        with self.assertRaises(HeartbeatStateError) as error:
            HeartbeatState.load(self.state_path, RUNNER_B, "runner-heartbeat")

        self.assertEqual(error.exception.reason, "state_identity_mismatch")
        self.assertEqual(state.runner_id, RUNNER_A)

    def test_corrupt_state_file_starts_a_new_epoch(self) -> None:
        self.state_path.write_text("{}", encoding="utf-8")

        state = HeartbeatState.load(self.state_path, RUNNER_A, "runner-heartbeat")

        self.assertEqual(state.runner_id, RUNNER_A)
        self.assertEqual(state.next_sequence, 1)
        self.assertEqual(json.loads(self.state_path.read_text(encoding="utf-8"))["next_sequence"], 1)

    def test_insecure_endpoint_requires_explicit_opt_in(self) -> None:
        with self.assertRaises(HeartbeatConfigError) as error:
            self.config(endpoint="http://monitor.example.test:8765")
        self.assertEqual(error.exception.reason, "insecure_endpoint")

        config = self.config(endpoint="http://monitor.example.test:8765", allow_insecure_http=True)
        self.assertTrue(config.allow_insecure_http)

    def test_canonical_event_endpoint_is_not_appended_twice(self) -> None:
        endpoints: list[str] = []

        def deliver(event: object, endpoint: str, _token: str) -> DeliveryResult:
            endpoints.append(endpoint)
            return DeliveryResult(True, 1)

        loop = HeartbeatLoop(
            self.config(endpoint="https://monitor.example.test:8765/v1/events"),
            deliver=deliver,
            network_probe=lambda _endpoint, _timeout: True,
            diagnostic=lambda _message: None,
        )

        result = loop.emit_once()

        self.assertTrue(result.delivered)
        self.assertEqual(endpoints, ["https://monitor.example.test:8765/v1/events"])

    def test_scheduler_sends_immediately_then_every_sixty_seconds_without_delivery_drift(self) -> None:
        clock = FakeClock()
        stop = FakeStopEvent(clock, stop_after_waits=2)
        events: list[dict[str, object]] = []

        def deliver(event: object, _endpoint: str, _token: str) -> DeliveryResult:
            events.append(event)  # type: ignore[arg-type]
            clock.value += 7.0
            return DeliveryResult(True, 1)

        loop = HeartbeatLoop(
            self.config(),
            clock=clock,
            sleeper=lambda _seconds: None,
            network_probe=lambda _endpoint, _timeout: True,
            deliver=deliver,
            diagnostic=lambda _message: None,
        )

        result = loop.run(stop)

        self.assertEqual(result, 0)
        self.assertEqual([event["producer_sequence"] for event in events], [1, 2])
        self.assertEqual(stop.waits, [53.0, 53.0])
        self.assertEqual(json.loads(self.state_path.read_text(encoding="utf-8"))["next_sequence"], 3)

    def test_network_not_ready_waits_then_emits_and_delivery_failure_is_fail_open(self) -> None:
        clock = FakeClock()
        stop = FakeStopEvent(clock, stop_after_waits=2)
        probes = iter([False, True])
        diagnostics: list[str] = []
        events: list[dict[str, object]] = []

        def deliver(event: object, _endpoint: str, _token: str) -> DeliveryResult:
            events.append(event)  # type: ignore[arg-type]
            return DeliveryResult(False, 3, "temporary_network_failure")

        loop = HeartbeatLoop(
            self.config(),
            clock=clock,
            sleeper=lambda _seconds: None,
            network_probe=lambda _endpoint, _timeout: next(probes),
            deliver=deliver,
            diagnostic=diagnostics.append,
        )

        result = loop.run(stop)

        self.assertEqual(result, 0)
        self.assertEqual(len(events), 1)
        self.assertIn("heartbeat_network_unavailable", diagnostics)
        self.assertNotIn("secret-token", "\n".join(diagnostics))

    def test_failed_delivery_writes_safe_service_status(self) -> None:
        config = self.config()
        diagnostics: list[str] = []
        loop = HeartbeatLoop(
            config,
            deliver=lambda _event, _endpoint, _token: DeliveryResult(
                False, 3, "temporary_http_failure", 503
            ),
            diagnostic=diagnostics.append,
        )

        result = loop.emit_once()

        self.assertFalse(result.delivered)
        status_path = self.base / "heartbeat-status.json"
        self.assertTrue(status_path.is_file())
        status = json.loads(status_path.read_text(encoding="utf-8"))
        self.assertEqual(status["service_name"], config.service_name)
        self.assertEqual(status["runner_id"], RUNNER_A)
        self.assertEqual(status["last_result"], "failure")
        self.assertEqual(status["last_attempt_count"], 3)
        self.assertEqual(status["last_http_status_class"], "5xx")
        self.assertEqual(status["last_failure_reason"], "temporary_http_failure")
        self.assertNotIn("secret-token", status_path.read_text(encoding="utf-8"))

    def test_service_status_preserves_last_success_across_loop_restart(self) -> None:
        config = self.config()
        first_loop = HeartbeatLoop(
            config,
            deliver=lambda _event, _endpoint, _token: DeliveryResult(True, 1, http_status=202),
        )
        first_loop.emit_once()

        second_loop = HeartbeatLoop(
            config,
            deliver=lambda _event, _endpoint, _token: DeliveryResult(
                False, 3, "temporary_http_failure", 503
            ),
        )
        second_loop.emit_once()

        status = json.loads((self.base / "heartbeat-status.json").read_text(encoding="utf-8"))
        self.assertIsNotNone(status["last_success_at"])
        self.assertEqual(status["last_result"], "failure")

    def test_service_status_redacts_untrusted_delivery_reason(self) -> None:
        config = self.config()
        diagnostics: list[str] = []
        loop = HeartbeatLoop(
            config,
            deliver=lambda _event, _endpoint, _token: DeliveryResult(
                False, 1, "transport failed: token=secret-token"
            ),
            diagnostic=diagnostics.append,
        )

        loop.emit_once()

        status_text = (self.base / "heartbeat-status.json").read_text(encoding="utf-8")
        status = json.loads(status_text)
        self.assertEqual(status["last_failure_reason"], "delivery_failed")
        self.assertNotIn("secret-token", status_text)
        self.assertEqual(diagnostics, ["heartbeat_delivery_failed reason=delivery_failed"])

    def test_status_write_failure_does_not_break_fail_open_delivery(self) -> None:
        config = self.config()
        diagnostics: list[str] = []
        loop = HeartbeatLoop(
            config,
            deliver=lambda _event, _endpoint, _token: DeliveryResult(
                False, 1, "temporary_network_failure"
            ),
            diagnostic=diagnostics.append,
        )

        with patch(
            "runner_observability.heartbeat._write_status_atomic",
            side_effect=RuntimeError("status serialization failed"),
        ):
            result = loop.emit_once()

        self.assertFalse(result.delivered)
        self.assertEqual(
            diagnostics,
            [
                "heartbeat_status_write_failed",
                "heartbeat_delivery_failed reason=temporary_network_failure",
            ],
        )


if __name__ == "__main__":
    unittest.main()
