"""Local standard-library HTTP boundary for the runner observability monitor."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import socket
import ssl
from threading import RLock
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .contracts import EVENT_RUNNER_HEARTBEAT, MAX_PAYLOAD_BYTES, ValidationError, validate_event
from .dashboard import dashboard_snapshot, history_event_view
from .store import Store


Diagnostic = Callable[[str], None]
Clock = Callable[[], datetime]
MAX_REJECTED_BODY_DRAIN_BYTES = MAX_PAYLOAD_BYTES + 1
REQUEST_READ_TIMEOUT_SECONDS = 1.0
STATIC_DIR = Path(__file__).parent / "static"
HISTORY_PAGE_SIZE = 20

# Stable, redacted TLS configuration reason codes (issue #7 PERS-07),
# following the same convention as ``deploy.py``'s ``REASON_*`` constants
# and ``contracts.ValidationError``: a caller may branch on ``.reason``,
# but the exception's string form is never anything except this code --
# never a configured path, never certificate/key contents, never the
# underlying ``ssl``/``OSError`` exception text.
REASON_TLS_PARTIAL_CONFIGURATION = "tls_partial_configuration"
REASON_TLS_CERTIFICATE_LOAD_FAILED = "tls_certificate_load_failed"


class TlsConfigurationError(ValueError):
    """A TLS certificate/key configuration failure with a safe, stable reason code only."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


def create_server(
    store: Store,
    bearer_token: str,
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    clock: Clock | None = None,
    diagnostic: Diagnostic | None = None,
    tls_cert_path: Path | str | None = None,
    tls_key_path: Path | str | None = None,
) -> ThreadingHTTPServer:
    """Create an in-process monitor server without starting its serving loop.

    The caller owns both the returned server and the Store, which keeps tests and
    command-line lifecycle handling explicit.

    ``tls_cert_path``/``tls_key_path`` are optional. When both are provided,
    the server's listening socket is wrapped with a real
    ``ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`` (stdlib ``ssl`` only, no
    third-party dependency) so the monitor actually serves HTTPS instead of
    plain HTTP -- closing the gap where the preflight "TLS certificate"
    check only ever proved a cert *file* existed. Providing only one of the
    pair is a controlled ``TlsConfigurationError`` (reason
    ``tls_partial_configuration``) raised before any socket is bound --
    never a half-started server. A certificate/key that cannot be loaded
    (missing file, malformed content, a mismatched key) is also a
    controlled ``TlsConfigurationError`` (reason
    ``tls_certificate_load_failed``); the configured path, file contents,
    and the underlying ``ssl``/``OSError`` exception text are never
    included in the raised error. Omitting both (the default) keeps
    today's plain-HTTP behavior completely unchanged.
    """
    if not bearer_token:
        raise ValueError("bearer_token must not be empty")
    # Presence is decided by "was a value supplied at all" (``is not None``),
    # never by truthiness: an explicitly empty string ("", e.g. from an
    # unset PowerShell variable expanding to a blank argument) is a
    # configured-but-invalid value, not the same as "omitted". Treating ""
    # as falsy here would let two blank strings silently skip both the
    # pairing check and the TLS-activation gate below and fall through to
    # plain HTTP with no error and no diagnostic -- the worst possible
    # failure mode for a security feature. A blank value is instead let
    # through to the real ``load_cert_chain`` call below, which rejects it
    # the same stable, non-leaking way it rejects any other invalid path.
    if (tls_cert_path is None) != (tls_key_path is None):
        raise TlsConfigurationError(REASON_TLS_PARTIAL_CONFIGURATION)
    tls_context: ssl.SSLContext | None = None
    if tls_cert_path is not None and tls_key_path is not None:
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Pin the floor explicitly rather than trusting whatever the
        # local OpenSSL build's own default happens to be today.
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            tls_context.load_cert_chain(certfile=str(tls_cert_path), keyfile=str(tls_key_path))
        except (OSError, ssl.SSLError):
            # Never chain/re-raise the original exception: it may carry the
            # configured absolute path or a PEM-parsing snippet of the file
            # content in its message, which would break the same redaction
            # guarantee ``deploy.py`` and ``contracts.py`` already enforce.
            raise TlsConfigurationError(REASON_TLS_CERTIFICATE_LOAD_FAILED) from None
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
                {
                    "accepted": result.accepted,
                    "duplicate": result.duplicate,
                    "projection_applied": result.projection_applied,
                    "producer_watermark": result.producer_watermark,
                    "event_id": result.event_id,
                },
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
                    page = _history_page_number(parsed.query)
                    filters = _history_filters(parse_qs(parsed.query, keep_blank_values=True))
                    with store_lock:
                        events, has_next = store.history_page(
                            filters,
                            page=page,
                            page_size=HISTORY_PAGE_SIZE,
                            exclude_event_types={EVENT_RUNNER_HEARTBEAT},
                        )
                except ValueError:
                    self._reject(400, "invalid_history_filter")
                    return
                self._json(
                    200,
                    {
                        "events": [history_event_view(event) for event in events],
                        "page": page,
                        "page_size": HISTORY_PAGE_SIZE,
                        "has_next": has_next,
                    },
                )
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

    def _handle_error(_request: object, _client_address: object) -> None:
        # socketserver's default handle_error() prints a raw traceback
        # (including this process's absolute paths) to stderr for any
        # exception that escapes a handler thread uncaught -- most notably
        # a client that speaks neither valid TLS nor valid HTTP against a
        # TLS-wrapped listener (see
        # tests/test_tls.py::test_a_hostile_plaintext_client_never_leaks_a_raw_traceback_to_stderr).
        # Report a single stable, redacted reason instead, matching every
        # other rejection path in this module; never re-raise or print the
        # original exception.
        report("http_connection_error")

    server.handle_error = _handle_error  # type: ignore[method-assign]
    if tls_context is not None:
        # do_handshake_on_connect=False is required, not optional: the
        # default (True) performs the full TLS handshake synchronously
        # inside SSLSocket.accept(), which runs on the single main
        # serve_forever() accept loop -- not a per-connection worker
        # thread -- with no timeout at all. A client that opens a TCP
        # connection and never sends a ClientHello (idle/slow/hostile)
        # would then block accept() indefinitely, starving every other
        # runner's ingest requests. With handshake deferred, the
        # handshake instead happens lazily on first read/write inside the
        # per-connection handler thread, where MonitorHandler.setup()
        # already applies REQUEST_READ_TIMEOUT_SECONDS to the connection
        # -- http.server's own handle_one_request() already catches the
        # resulting socket.timeout the same way it does for a slow plain-
        # HTTP client, so no other code path needed to change. See
        # tests/test_tls.py::test_an_idle_connection_that_never_sends_a_handshake_does_not_block_other_clients.
        server.socket = tls_context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    return server


def _history_filters(query: dict[str, list[str]]) -> dict[str, object]:
    """Translate a single-valued, limited query vocabulary into Store filters."""
    allowed = {"runner_id", "repository", "workflow_run_id", "outcome", "received_after", "received_before"}
    filters_query = {key: values for key, values in query.items() if key != "page"}
    if any(key not in allowed or len(values) != 1 for key, values in filters_query.items()):
        raise ValueError("invalid_history_filter")
    filters: dict[str, object] = {key: values[0] for key, values in filters_query.items()}
    if "workflow_run_id" in filters:
        try:
            filters["workflow_run_id"] = int(str(filters["workflow_run_id"]))
        except ValueError as error:
            raise ValueError("invalid_history_filter") from error
    return filters


def _history_page_number(query: str) -> int:
    values = parse_qs(query, keep_blank_values=True).get("page", ["1"])
    if len(values) != 1:
        raise ValueError("invalid_history_filter")
    try:
        page = int(values[0])
    except ValueError as error:
        raise ValueError("invalid_history_filter") from error
    if page < 1:
        raise ValueError("invalid_history_filter")
    return page
