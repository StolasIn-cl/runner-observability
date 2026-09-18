"""Runner heartbeat state, delivery, and scheduler contract tests."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
