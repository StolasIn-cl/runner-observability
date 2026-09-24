"""CLI integration tests for the optional durable telemetry outbox."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runner_observability import __main__ as package_cli
from runner_observability.agent import main as agent_main
from runner_observability.outbox import OutboxLimits


RUNNER_ID = "20000000-0000-4000-8000-000000000001"


def heartbeat(*, event_id: str = "10000000-0000-0000-0000-000000000001") -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "runner.heartbeat",
        "event_id": event_id,
        "runner_id": RUNNER_ID,
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": 1,
        "occurred_at": "2026-09-18T01:00:00Z",
    }


class DurableOutboxCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="runner-observability-cli-outbox-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.endpoint = "https://monitor.invalid/v1/events"

    def test_emit_failure_keeps_pending_event_and_returns_zero(self) -> None:
        diagnostics: list[str] = []

        code = agent_main(
            [
                "emit",
                "--endpoint",
                self.endpoint,
                "--token",
                "secret-token",
                "--event-json",
                json.dumps(heartbeat()),
                "--outbox-dir",
                str(self.root),
            ],
            transport=lambda _url, _headers, _body: 503,
            clock=lambda: 0.0,
            sleeper=lambda _seconds: None,
            diagnostic=diagnostics.append,
        )

        self.assertEqual(code, 0)
        pending = list((self.root / "pending").glob("*.json"))
        self.assertEqual(len(pending), 1)
        self.assertNotIn("secret-token", pending[0].read_text(encoding="utf-8"))
        self.assertNotIn(self.endpoint, pending[0].read_text(encoding="utf-8"))
        self.assertNotIn("secret-token", "\n".join(diagnostics))

    def test_emit_success_removes_pending_event(self) -> None:
        code = agent_main(
            [
                "emit",
                "--endpoint",
                self.endpoint,
                "--token",
                "secret-token",
                "--event-json",
                json.dumps(heartbeat()),
                "--outbox-dir",
                str(self.root),
            ],
            transport=lambda _url, _headers, _body: 202,
            diagnostic=lambda _message: None,
        )

        self.assertEqual(code, 0)
        self.assertEqual(list((self.root / "pending").glob("*.json")), [])

    def test_flush_token_file_replays_pending_event_through_package_entrypoint(self) -> None:
        failed = agent_main(
            [
                "emit",
                "--endpoint",
                self.endpoint,
                "--token",
                "secret-token",
                "--event-json",
                json.dumps(heartbeat()),
                "--outbox-dir",
                str(self.root),
            ],
            transport=lambda _url, _headers, _body: 503,
            clock=lambda: 0.0,
            sleeper=lambda _seconds: None,
            diagnostic=lambda _message: None,
        )
        token_file = self.root / "monitor-token.txt"
        token_file.write_text("secret-token\n", encoding="utf-8")

        replayed = package_cli.main(
            [
                "flush",
                "--endpoint",
                self.endpoint,
                "--token-file",
                str(token_file),
                "--outbox-dir",
                str(self.root),
            ],
            transport=lambda _url, _headers, _body: 202,
            diagnostic=lambda _message: None,
        )

        self.assertEqual(failed, 0)
        self.assertEqual(replayed, 0)
        self.assertEqual(list((self.root / "pending").glob("*.json")), [])

    def test_queue_capacity_failure_remains_fail_open(self) -> None:
        first_event = heartbeat()
        second_event = heartbeat(event_id="20000000-0000-0000-0000-000000000002")
        common = [
            "emit",
            "--endpoint",
            self.endpoint,
            "--token",
            "secret-token",
            "--outbox-dir",
            str(self.root),
        ]

        with patch(
            "runner_observability.agent.DEFAULT_OUTBOX_LIMITS",
            OutboxLimits(max_events=1),
        ):
            first = agent_main(
                [*common, "--event-json", json.dumps(first_event)],
                transport=lambda _url, _headers, _body: 503,
                clock=lambda: 0.0,
                sleeper=lambda _seconds: None,
                diagnostic=lambda _message: None,
            )
            second = agent_main(
                [*common, "--event-json", json.dumps(second_event)],
                transport=lambda _url, _headers, _body: 503,
                clock=lambda: 0.0,
                sleeper=lambda _seconds: None,
                diagnostic=lambda _message: None,
            )

        self.assertEqual(first, 0)
        self.assertEqual(second, 0)
        self.assertEqual(len(list((self.root / "pending").glob("*.json"))), 1)


if __name__ == "__main__":
    unittest.main()
