"""Local standard-library HTTP boundary for the runner observability monitor."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
from threading import RLock
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .contracts import MAX_PAYLOAD_BYTES, ValidationError, validate_event
from .dashboard import dashboard_snapshot
from .store import Store


Diagnostic = Callable[[str], None]
Clock = Callable[[], datetime]
MAX_REJECTED_BODY_DRAIN_BYTES = MAX_PAYLOAD_BYTES + 1
REQUEST_READ_TIMEOUT_SECONDS = 1.0
STATIC_DIR = Path(__file__).parent / "static"


def create_server(
    store: Store,
    bearer_token: str,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    clock: Clock | None = None,
    diagnostic: Diagnostic | None = None,
) -> ThreadingHTTPServer:
    """Create an in-process monitor server without starting its serving loop.

    The caller owns both the returned server and the Store, which keeps tests and
    command-line lifecycle handling explicit.
    """
    if not bearer_token:
        raise ValueError("bearer_token must not be empty")
    request_clock = clock or (lambda: datetime.now(timezone.utc))
    report = diagnostic or (lambda _message: None)
    store_lock = RLock()
    dashboard_html = STATIC_DIR.joinpath("index.html").read_bytes()
    dashboard_css = STATIC_DIR.joinpath("app.css").read_bytes()
    dashboard_js = STATIC_DIR.joinpath("app.js").read_bytes()

    class MonitorHandler(BaseHTTPRequestHandler):
        server_version = "RunnerObservability/1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(REQUEST_READ_TIMEOUT_SECONDS)

        def log_message(self, _format: str, *_args: object) -> None:
            """Suppress BaseHTTPRequestHandler request logging, which is not redaction-safe."""

        def do_POST(self) -> None:  # noqa: N802 - required stdlib handler name
            if urlsplit(self.path).path != "/v1/events":
                self._json(404, {"error": "not_found"})
                return
            if not self._authorized():
                self._drain_small_declared_body()
                self._reject(401, "unauthorized")
                return
            content_length = self._content_length()
            if content_length is None:
                return
            if content_length > MAX_PAYLOAD_BYTES:
                self.close_connection = True
                self._reject(413, "payload_too_large")
                return
            try:
                body = self.rfile.read(content_length)
            except socket.timeout:
                self._reject(408, "request_timeout")
                return
            if len(body) != content_length:
                self._reject(400, "invalid_body")
                return
            try:
                payload = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError):
                self._reject(400, "invalid_json")
                return
            try:
                event = validate_event(payload)
            except ValidationError as error:
                status = 413 if error.reason == "payload_too_large" else 422
                self._reject(status, error.reason)
                return
            except RecursionError:
                self._reject(422, "invalid_event")
                return
            with store_lock:
                result = store.ingest(event, request_clock())
            self._json(
                202,
                {"accepted": result.accepted, "duplicate": result.duplicate, "event_id": result.event_id},
            )

        def do_GET(self) -> None:  # noqa: N802 - required stdlib handler name
            parsed = urlsplit(self.path)
            if parsed.path == "/":
                self._static(dashboard_html, "text/html; charset=utf-8")
                return
            if parsed.path == "/app.css":
                self._static(dashboard_css, "text/css; charset=utf-8")
                return
            if parsed.path == "/app.js":
                self._static(dashboard_js, "application/javascript; charset=utf-8")
                return
            if parsed.path == "/api/health":
                with store_lock:
                    health = store.health()
                self._json(200, {"degraded": health["degraded"], "reasons": list(health["reasons"])})
                return
            if parsed.path == "/api/history":
                try:
                    filters = _history_filters(parse_qs(parsed.query, keep_blank_values=True))
                    with store_lock:
                        events = store.history(filters)
                except ValueError:
                    self._reject(400, "invalid_history_filter")
                    return
                self._json(200, {"events": events})
                return
            if parsed.path == "/api/dashboard":
                try:
                    with store_lock:
                        snapshot = dashboard_snapshot(store, request_clock())
                except Exception:
                    report("dashboard_snapshot_failed")
                    self._json(500, {"error": "dashboard_unavailable"})
                    return
                self._json(200, snapshot)
                return
            self._json(404, {"error": "not_found"})

        def do_PUT(self) -> None:  # noqa: N802 - required stdlib handler name
            self._json(405, {"error": "method_not_allowed"})

        def do_DELETE(self) -> None:  # noqa: N802 - required stdlib handler name
            self._json(405, {"error": "method_not_allowed"})

        def _authorized(self) -> bool:
            supplied = self.headers.get("Authorization", "")
            if not supplied.isascii():
                return False
            try:
                return hmac.compare_digest(supplied, f"Bearer {bearer_token}")
            except TypeError:
                return False

        def _content_length(self) -> int | None:
            raw_value = self.headers.get("Content-Length")
            if raw_value is None:
                self._reject(411, "content_length_required")
                return None
            try:
                value = int(raw_value)
            except ValueError:
                self._reject(400, "invalid_content_length")
                return None
            if value < 0:
                self._reject(400, "invalid_content_length")
                return None
            return value

        def _drain_small_declared_body(self) -> None:
            """Let ordinary rejected clients receive 401 without retaining their body."""
            raw_value = self.headers.get("Content-Length")
            try:
                content_length = int(raw_value) if raw_value is not None else 0
            except ValueError:
                return
            if content_length < 0 or content_length > MAX_PAYLOAD_BYTES:
                return
            try:
                remaining = content_length
                while remaining:
                    chunk = self.rfile.read(min(8192, remaining))
                    if not chunk:
                        return
                    remaining -= len(chunk)
            except socket.timeout:
                return

        def _reject(self, status: int, reason: str) -> None:
            report(f"http_request_rejected reason={reason}")
            self._json(status, {"error": reason})

        def _json(self, status: int, body: dict[str, Any]) -> None:
            encoded = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(encoded)
            except OSError:
                pass

        def _static(self, body: bytes, content_type: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(body)
            except OSError:
                pass

    server = ThreadingHTTPServer((host, port), MonitorHandler)
    server.daemon_threads = True
    return server


def _history_filters(query: dict[str, list[str]]) -> dict[str, object]:
    """Translate a single-valued, limited query vocabulary into Store filters."""
    allowed = {"runner_id", "repository", "workflow_run_id", "outcome", "received_after", "received_before"}
    if any(key not in allowed or len(values) != 1 for key, values in query.items()):
        raise ValueError("invalid_history_filter")
    filters: dict[str, object] = {key: values[0] for key, values in query.items()}
    if "workflow_run_id" in filters:
        try:
            filters["workflow_run_id"] = int(str(filters["workflow_run_id"]))
        except ValueError as error:
            raise ValueError("invalid_history_filter") from error
    return filters
