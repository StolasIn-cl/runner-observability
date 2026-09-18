"""Fail-open sender tests using an injected transport and fake clock only."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import socketserver
from threading import Thread
import time
import unittest
from unittest.mock import patch

from runner_observability.agent import deliver_event, main
from runner_observability.__main__ import main as package_main


def heartbeat() -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "runner.heartbeat",
        "event_id": "10000000-0000-4000-8000-000000000001",
        "runner_id": "20000000-0000-4000-8000-000000000001",
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": 1,
        "occurred_at": "2026-09-18T01:00:00Z",
    }


@dataclass
class FakeClock:
    value: float = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class RunnerAgentTests(unittest.TestCase):
    def test_successful_delivery_returns_after_one_attempt(self) -> None:
        result = deliver_event(
            heartbeat(),
            "http://monitor/v1/events",
            "token",
            transport=lambda _url, _headers, _body: 202,
            diagnostic=lambda _message: None,
        )

        self.assertTrue(result.delivered)
        self.assertEqual(result.attempts, 1)
        self.assertIsNone(result.reason)

    def test_429_recovery_retries_once_and_delivers(self) -> None:
        clock = FakeClock()
        statuses = iter([429, 202])

        result = deliver_event(
            heartbeat(),
            "http://monitor/v1/events",
            "token",
            transport=lambda _url, _headers, _body: next(statuses),
            clock=clock,
            sleeper=clock.sleep,
            diagnostic=lambda _message: None,
        )

        self.assertTrue(result.delivered)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(clock.value, 1.0)

    def test_default_transport_never_follows_or_forwards_bearer_on_redirect(self) -> None:
        class RedirectHandler(BaseHTTPRequestHandler):
            redirected_authorizations: list[str | None] = []

            def do_POST(self) -> None:  # noqa: N802
                self.send_response(302)
                self.send_header("Location", "/redirected")
                self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                type(self).redirected_authorizations.append(self.headers.get("Authorization"))
                self.send_response(204)
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = deliver_event(
                heartbeat(),
                f"http://127.0.0.1:{server.server_address[1]}/source",
                "must-not-be-forwarded",
                diagnostic=lambda _message: None,
            )
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertFalse(result.delivered)
        self.assertEqual(result.attempts, 1)
        self.assertEqual(result.reason, "rejected_http_response")
        self.assertEqual(RedirectHandler.redirected_authorizations, [])

    def test_default_transport_enforces_deadline_against_a_trickled_response(self) -> None:
        class TrickledResponse(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.recv(8192)
                try:
                    for fragment in (b"HTTP/1.1 ", b"200 ", b"OK\r\n", b"Content-Length: 0\r\n\r\n"):
                        self.request.sendall(fragment)
                        time.sleep(0.02)
                except OSError:
                    pass

        class LocalServer(socketserver.ThreadingTCPServer):
            allow_reuse_address = True

        server = LocalServer(("127.0.0.1", 0), TrickledResponse)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with patch("runner_observability.agent.MAX_DELIVERY_SECONDS", 0.05):
                started_at = time.monotonic()
                result = deliver_event(
                    heartbeat(),
                    f"http://127.0.0.1:{server.server_address[1]}/v1/events",
                    "token",
                    diagnostic=lambda _message: None,
                )
                elapsed = time.monotonic() - started_at
        finally:
            server.shutdown()
            thread.join()
            server.server_close()

        self.assertFalse(result.delivered)
        self.assertLess(elapsed, 0.08)

    def test_default_transport_deadline_bounds_slow_resolution_and_connect(self) -> None:
        candidate = (2, 1, 6, "", ("127.0.0.1", 9))

        def fast_resolver(_host: str, _port: int) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            return [candidate]

        def slow_resolver(_host: str, _port: int) -> list[tuple[int, int, int, str, tuple[str, int]]]:
            time.sleep(0.12)
            return [candidate]

        def slow_connector(_candidate: object, _timeout: float) -> object:
            time.sleep(0.12)
            raise OSError("deliberately slow connect")

        for resolver, connector in ((slow_resolver, slow_connector), (fast_resolver, slow_connector)):
            with self.subTest(stage="resolve" if resolver is slow_resolver else "connect"):
                with patch("runner_observability.agent.MAX_DELIVERY_SECONDS", 0.03):
                    started_at = time.monotonic()
                    result = deliver_event(
                        heartbeat(),
                        "http://monitor.invalid/v1/events",
                        "token",
                        resolver=resolver,
                        connector=connector,
                        diagnostic=lambda _message: None,
                    )
                    elapsed = time.monotonic() - started_at

                self.assertFalse(result.delivered)
                self.assertEqual(result.attempts, 1)
                self.assertEqual(result.reason, "temporary_network_failure")
                self.assertLess(elapsed, 0.08)

    def test_temporary_503_retries_at_most_twice_then_records_safe_diagnostic(self) -> None:
        clock = FakeClock()
        statuses = iter([503, 503, 503])
        diagnostics: list[str] = []

        result = deliver_event(
            heartbeat(),
            "http://127.0.0.1:8765/v1/events",
            "not-for-logs",
            transport=lambda _url, _headers, _body: next(statuses),
            clock=clock,
            sleeper=clock.sleep,
            diagnostic=diagnostics.append,
        )

        self.assertFalse(result.delivered)
        self.assertEqual(result.attempts, 3)
        self.assertEqual(result.reason, "temporary_http_failure")
        self.assertEqual(diagnostics, ["telemetry_delivery_failed reason=temporary_http_failure"])

    def test_auth_and_schema_http_rejections_are_not_retried(self) -> None:
        for status in (401, 403, 400, 422):
            with self.subTest(status=status):
                attempts = 0

                def transport(_url: str, _headers: dict[str, str], _body: bytes) -> int:
                    nonlocal attempts
                    attempts += 1
                    return status

                result = deliver_event(
                    heartbeat(), "http://monitor/v1/events", "token", transport=transport, diagnostic=lambda _message: None
                )

                self.assertFalse(result.delivered)
                self.assertEqual(attempts, 1)
                self.assertEqual(result.reason, "rejected_http_response")

    def test_network_failure_does_not_start_a_retry_after_the_five_second_budget(self) -> None:
        clock = FakeClock(4.5)
        attempts = 0

        def unavailable(_url: str, _headers: dict[str, str], _body: bytes) -> int:
            nonlocal attempts
            attempts += 1
            clock.value += 4.5
            raise OSError("host unreachable")

        result = deliver_event(
            heartbeat(),
            "http://monitor/v1/events",
            "token",
            transport=unavailable,
            clock=clock,
            sleeper=clock.sleep,
            diagnostic=lambda _message: None,
        )

        self.assertFalse(result.delivered)
        self.assertEqual(attempts, 1)
        self.assertLessEqual(clock.value - 4.5, 5.0)

    def test_diagnostic_never_contains_payload_token_or_transport_exception_text(self) -> None:
        marker = "DO-NOT-LOG-THIS-PAYLOAD"
        event = heartbeat()
        event["producer_id"] = marker
        secret = "secret-token"
        diagnostics: list[str] = []

        result = deliver_event(
            event,
            "http://monitor/v1/events",
            secret,
            transport=lambda _url, _headers, _body: (_ for _ in ()).throw(OSError(secret)),
            diagnostic=diagnostics.append,
        )

        self.assertFalse(result.delivered)
        joined = "\n".join(diagnostics)
        self.assertNotIn(marker, joined)
        self.assertNotIn(secret, joined)

    def test_emit_cli_returns_zero_when_delivery_fails(self) -> None:
        code = main(
            [
                "emit",
                "--endpoint",
                "http://monitor/v1/events",
                "--token",
                "token",
                "--event-json",
                json.dumps(heartbeat()),
            ],
            transport=lambda _url, _headers, _body: 503,
            diagnostic=lambda _message: None,
        )

        self.assertEqual(code, 0)

    def test_closed_diagnostic_sink_cannot_break_fail_open_terminal_paths(self) -> None:
        def closed_sink(_message: str) -> None:
            raise OSError("stderr closed")

        auth_code = main(
            ["emit", "--endpoint", "http://monitor/v1/events", "--token", "token", "--event-json", json.dumps(heartbeat())],
            transport=lambda _url, _headers, _body: 401,
            diagnostic=closed_sink,
        )
        invalid = heartbeat()
        invalid["schema_version"] = 2
        schema_code = main(
            ["emit", "--endpoint", "http://monitor/v1/events", "--token", "token", "--event-json", json.dumps(invalid)],
            diagnostic=closed_sink,
        )

        self.assertEqual(auth_code, 0)
        self.assertEqual(schema_code, 0)

    def test_package_emit_entrypoint_keeps_delivery_failure_fail_open(self) -> None:
        code = package_main(
            [
                "emit",
                "--endpoint",
                "http://monitor/v1/events",
                "--token",
                "token",
                "--event-json",
                json.dumps(heartbeat()),
            ],
            transport=lambda _url, _headers, _body: 503,
            diagnostic=lambda _message: None,
        )

        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
