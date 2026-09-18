"""Local, runner-independent contract tests for the monitor HTTP boundary."""

from __future__ import annotations

from datetime import datetime, timezone
import http.client
import json
import socket
from threading import Thread
import unittest

from runner_observability.contracts import MAX_PAYLOAD_BYTES
from runner_observability.server import create_server
from runner_observability.store import Store


TOKEN = "local-monitor-token"


def heartbeat(*, event_id: str = "10000000-0000-4000-8000-000000000001") -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "runner.heartbeat",
        "event_id": event_id,
        "runner_id": "20000000-0000-4000-8000-000000000001",
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": 1,
        "occurred_at": "2026-09-18T01:00:00Z",
    }


class MonitorHttpTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = Store()
        self.logs: list[str] = []
        self.server = create_server(
            self.store,
            TOKEN,
            clock=lambda: datetime(2026, 9, 18, 1, 2, tzinfo=timezone.utc),
            diagnostic=self.logs.append,
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()

    def request(
        self, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None
    ) -> tuple[int, dict[str, object], str]:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        request_headers = dict(headers or {})
        if body:
            request_headers.setdefault("Content-Length", str(len(body)))
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.getheader("Content-Type", "")
        connection.close()
        if content_type.startswith("application/json"):
            return response.status, json.loads(raw), content_type
        return response.status, {}, raw.decode("utf-8")

    def test_ingest_requires_exact_bearer_token(self) -> None:
        body = json.dumps(heartbeat()).encode("utf-8")

        status, response, _ = self.request(
            "POST", "/v1/events", body, {"Content-Type": "application/json"}
        )

        self.assertEqual(status, 401)
        self.assertEqual(response, {"error": "unauthorized"})
        self.assertEqual(self.store.history(), [])

    def test_ingest_returns_safe_schema_error_without_retaining_payload(self) -> None:
        rejected = heartbeat()
        rejected["schema_version"] = 2
        body = json.dumps(rejected).encode("utf-8")

        status, response, _ = self.request(
            "POST",
            "/v1/events",
            body,
            {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
        )

        self.assertEqual(status, 422)
        self.assertEqual(response, {"error": "unsupported_schema"})
        self.assertEqual(self.store.history(), [])

    def test_ingest_rejects_oversized_body_before_json_parsing(self) -> None:
        connection = socket.create_connection(self.server.server_address, timeout=1)
        try:
            connection.sendall(
                (
                    "POST /v1/events HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    f"Authorization: Bearer {TOKEN}\r\n"
                    "Content-Type: application/json\r\n"
                    f"Content-Length: {MAX_PAYLOAD_BYTES + 1}\r\n\r\n"
                ).encode("ascii")
            )
            connection.settimeout(0.5)
            chunks: list[bytes] = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            raw_response = b"".join(chunks)

            self.assertIn(b"413", raw_response)
            self.assertIn(b'payload_too_large', raw_response)
            self.assertEqual(self.store.history(), [])
        finally:
            connection.close()

    def test_incomplete_request_body_cannot_block_the_health_endpoint(self) -> None:
        connection = socket.create_connection(self.server.server_address, timeout=1)
        try:
            connection.sendall(
                (
                    "POST /v1/events HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    f"Authorization: Bearer {TOKEN}\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: 100\r\n\r\n{"
                ).encode("ascii")
            )

            health_status, health, _ = self.request("GET", "/api/health")

            self.assertEqual(health_status, 200)
            self.assertEqual(health["degraded"], False)
        finally:
            connection.close()

    def test_malformed_authorization_and_hostile_json_receive_controlled_4xx(self) -> None:
        malformed_authorization = socket.create_connection(self.server.server_address, timeout=1)
        try:
            malformed_authorization.sendall(
                b"POST /v1/events HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
                b"Content-Length: 2\r\nAuthorization: Bearer \xff\r\n\r\n{}"
            )
            malformed_authorization.settimeout(1)
            self.assertIn(b"401", malformed_authorization.recv(4096))
        finally:
            malformed_authorization.close()

        for body in (b"[" * 2_000 + b"]" * 2_000, b"9" * 5_000):
            with self.subTest(body_kind="deep" if body.startswith(b"[") else "huge_int"):
                status, response, _ = self.request(
                    "POST",
                    "/v1/events",
                    body,
                    {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
                )
                self.assertEqual(status, 400)
                self.assertEqual(response, {"error": "invalid_json"})

    def test_authenticated_ingest_persists_a_validated_event(self) -> None:
        status, response, _ = self.request(
            "POST",
            "/v1/events",
            json.dumps(heartbeat()).encode("utf-8"),
            {"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
        )

        self.assertEqual(status, 202)
        self.assertEqual(response["accepted"], True)
        self.assertFalse(response["duplicate"])
        self.assertEqual(len(self.store.history()), 1)

    def test_ingest_diagnostics_never_include_request_payload_or_bearer_secret(self) -> None:
        marker = "DO-NOT-LOG-THIS-PAYLOAD"
        secret = "Bearer ultra-secret-token"
        body = json.dumps({"schema_version": 2, "marker": marker}).encode("utf-8")

        status, _, _ = self.request(
            "POST",
            "/v1/events",
            body,
            {"Content-Type": "application/json", "Authorization": secret},
        )

        self.assertEqual(status, 401)
        joined = "\n".join(self.logs)
        self.assertNotIn(marker, joined)
        self.assertNotIn(secret, joined)
        self.assertNotIn("ultra-secret-token", joined)

    def test_dashboard_and_api_views_are_read_only(self) -> None:
        status, _, html = self.request("GET", "/")
        health_status, health, _ = self.request("GET", "/api/health")
        history_status, history, _ = self.request("GET", "/api/history")

        self.assertEqual(status, 200)
        self.assertIn("Runner Observability", html)
        self.assertEqual(health_status, 200)
        self.assertEqual(health, {"degraded": False, "reasons": []})
        self.assertEqual(history_status, 200)
        self.assertEqual(history, {"events": []})


if __name__ == "__main__":
    unittest.main()
