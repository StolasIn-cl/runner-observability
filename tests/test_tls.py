"""TLS/HTTPS contract tests for the monitor HTTP boundary (issue #7 PERS-07).

These tests prove the ``create_server()`` TLS wrapping contract against a
throwaway, pre-generated self-signed certificate/key fixture pair under
``tests/fixtures/tls/`` -- never a real trusted certificate, never a
third-party certificate-generation library at runtime or test time. The
fixtures were produced once with the local ``openssl`` CLI (the same
approach CPython's own test suite uses for its SSL fixtures) and are
committed so the suite never depends on ``openssl`` being on PATH when
tests run.

Scope boundary (mirrors ``tests/test_deployment_docs.py`` and
``tests/test_http.py``): every server here binds to ``127.0.0.1`` on an
OS-assigned port and is torn down at the end of each test -- no shared
state, no real Runner Agent, no real network host.
"""

from __future__ import annotations

import contextlib
from datetime import datetime, timezone
import http.client
import io
import json
from pathlib import Path
import socket
import ssl
import tempfile
from threading import Thread
import time
import unittest

from runner_observability.server import (
    REASON_TLS_CERTIFICATE_LOAD_FAILED,
    REASON_TLS_PARTIAL_CONFIGURATION,
    TlsConfigurationError,
    create_server,
)
from runner_observability.store import Store


TOKEN = "local-monitor-tls-token"
FIXTURES = Path(__file__).parent / "fixtures" / "tls"
VALID_CERT = FIXTURES / "server-cert.pem"
VALID_KEY = FIXTURES / "server-key.pem"
MISMATCHED_KEY = FIXTURES / "other-key.pem"


def heartbeat(*, event_id: str = "10000000-0000-4000-8000-000000000009") -> dict[str, object]:
    return {
        "schema_version": 1,
        "event_type": "runner.heartbeat",
        "event_id": event_id,
        "runner_id": "20000000-0000-4000-8000-000000000009",
        "producer_id": "runner-agent",
        "producer_epoch": "2026-09-18T01",
        "producer_sequence": 1,
        "occurred_at": "2026-09-18T01:00:00Z",
    }


def _trusting_client_context() -> ssl.SSLContext:
    """A client SSLContext that trusts only our throwaway self-signed fixture cert."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=str(VALID_CERT))
    context.check_hostname = True
    return context


class HttpsIngestTests(unittest.TestCase):
    """(a) A valid cert/key pair serves real HTTPS; a plain HTTP client is rejected."""

    def setUp(self) -> None:
        self.store = Store()
        self.server = create_server(
            self.store,
            TOKEN,
            clock=lambda: datetime(2026, 9, 18, 1, 2, tzinfo=timezone.utc),
            tls_cert_path=VALID_CERT,
            tls_key_path=VALID_KEY,
        )
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.thread.join()
        self.server.server_close()
        self.store.close()

    def test_https_client_can_complete_a_real_event_ingest(self) -> None:
        body = json.dumps(heartbeat()).encode("utf-8")
        connection = http.client.HTTPSConnection(
            *self.server.server_address, timeout=2, context=_trusting_client_context()
        )
        try:
            connection.request(
                "POST",
                "/v1/events",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                    "Authorization": f"Bearer {TOKEN}",
                },
            )
            response = connection.getresponse()
            payload = json.loads(response.read())
        finally:
            connection.close()

        self.assertEqual(response.status, 202)
        self.assertTrue(payload["accepted"])
        self.assertEqual(len(self.store.history()), 1)

    def test_plain_http_client_against_the_same_port_is_rejected(self) -> None:
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
        try:
            with self.assertRaises((OSError, http.client.HTTPException)):
                connection.request("GET", "/")
                connection.getresponse()
        finally:
            connection.close()

    def test_a_hostile_plaintext_client_never_leaks_a_raw_traceback_to_stderr(self) -> None:
        # With the handshake deferred into the worker thread (fix-round-1,
        # Important #3), a client that speaks plaintext HTTP instead of TLS
        # now fails inside handle_one_request() rather than inside
        # accept() -- a different code path that, unless handled, reaches
        # socketserver's default handle_error(), which prints a raw
        # traceback (with this process's absolute paths) to stderr. That
        # would violate this module's redaction guarantee just as much as
        # a leaked cert path would.
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            connection = http.client.HTTPConnection(*self.server.server_address, timeout=2)
            try:
                with self.assertRaises((OSError, http.client.HTTPException)):
                    connection.request("GET", "/")
                    connection.getresponse()
            finally:
                connection.close()
            # Give the worker thread a moment to hit handle_error(), if it
            # was going to.
            time.sleep(0.3)
        output = captured.getvalue()
        self.assertNotIn("Traceback", output)

    def test_the_socket_used_by_the_server_is_a_real_ssl_socket(self) -> None:
        self.assertIsInstance(self.server.socket, ssl.SSLSocket)

    def test_the_minimum_tls_version_is_pinned_not_left_to_the_library_default(self) -> None:
        self.assertEqual(self.server.socket.context.minimum_version, ssl.TLSVersion.TLSv1_2)

    def test_a_client_that_does_not_trust_the_server_certificate_is_rejected(self) -> None:
        # Negative case for the happy-path ingest test above: a client
        # using the platform's default trust store (which never trusts a
        # throwaway self-signed fixture cert) must fail the handshake --
        # proving verification is actually enforced, not merely available
        # to opt into.
        untrusting_context = ssl.create_default_context()
        connection = http.client.HTTPSConnection(
            *self.server.server_address, timeout=2, context=untrusting_context
        )
        try:
            with self.assertRaises(ssl.SSLCertVerificationError):
                connection.request("GET", "/")
                connection.getresponse()
        finally:
            connection.close()

    def test_an_idle_connection_that_never_sends_a_handshake_does_not_block_other_clients(self) -> None:
        # Reviewer fix-round-1 finding (Important #3): wrapping the
        # listening socket with the default do_handshake_on_connect=True
        # means the TLS handshake for every new connection runs
        # synchronously on the single accept-loop thread with no timeout.
        # A client that opens a TCP connection and sends nothing (never
        # completes a TLS handshake) must not be able to stall every other
        # client's requests -- reproduced directly against the real
        # server: before the fix this legitimate HTTPS request hangs until
        # its own client-side timeout instead of completing quickly.
        idle = socket.create_connection(self.server.server_address, timeout=5)
        self.addCleanup(idle.close)

        started = time.monotonic()
        connection = http.client.HTTPSConnection(
            *self.server.server_address, timeout=3, context=_trusting_client_context()
        )
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            elapsed = time.monotonic() - started
        finally:
            connection.close()

        self.assertEqual(response.status, 200)
        # Generous bound (the per-connection read timeout is 1s): proves
        # the idle connection is not blocking the accept loop at all,
        # rather than merely finishing just under the client's own 3s
        # timeout.
        self.assertLess(elapsed, 2.0)


class TlsPairedArgumentTests(unittest.TestCase):
    """(b) --tls-cert / --tls-key (tls_cert_path / tls_key_path) must be provided as a pair."""

    def setUp(self) -> None:
        self.store = Store()
        self.addCleanup(self.store.close)

    def test_cert_without_key_is_a_controlled_error(self) -> None:
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=VALID_CERT, tls_key_path=None)
        self.assertEqual(context.exception.reason, REASON_TLS_PARTIAL_CONFIGURATION)

    def test_key_without_cert_is_a_controlled_error(self) -> None:
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=None, tls_key_path=VALID_KEY)
        self.assertEqual(context.exception.reason, REASON_TLS_PARTIAL_CONFIGURATION)

    def test_a_partial_configuration_never_binds_a_listening_socket(self) -> None:
        # A half-started server (a bound port nobody is told about) would be
        # worse than a clean failure -- this must never happen. Proof: the
        # exact same port can be bound immediately afterward.
        port = _free_local_port()
        with self.assertRaises(TlsConfigurationError):
            create_server(self.store, TOKEN, host="127.0.0.1", port=port, tls_cert_path=VALID_CERT, tls_key_path=None)
        server = create_server(self.store, TOKEN, host="127.0.0.1", port=port)
        server.server_close()

    def test_two_empty_strings_never_silently_fall_back_to_plain_http(self) -> None:
        # Reviewer fix-round-1 finding (Critical): an empty string is
        # falsy, so a truthiness-based pairing/activation check would treat
        # "" and "" as "not configured" and silently serve plaintext HTTP
        # even though the operator's command line named both flags -- e.g.
        # an unset PowerShell variable expanding to "". Both are non-None,
        # so this must be treated as configured-but-invalid, never as
        # "omitted".
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path="", tls_key_path="")
        self.assertEqual(context.exception.reason, REASON_TLS_CERTIFICATE_LOAD_FAILED)

    def test_empty_cert_with_a_real_key_is_never_silently_accepted(self) -> None:
        with self.assertRaises(TlsConfigurationError):
            create_server(self.store, TOKEN, tls_cert_path="", tls_key_path=VALID_KEY)

    def test_empty_key_with_a_real_cert_is_never_silently_accepted(self) -> None:
        with self.assertRaises(TlsConfigurationError):
            create_server(self.store, TOKEN, tls_cert_path=VALID_CERT, tls_key_path="")


class TlsBadCertificateTests(unittest.TestCase):
    """(c) Bad cert/key material fails closed with a stable reason code -- no leaks."""

    def setUp(self) -> None:
        self.store = Store()
        self.addCleanup(self.store.close)
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-tls-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_missing_cert_file_produces_the_stable_reason(self) -> None:
        missing_cert = self.base / "does-not-exist-cert.pem"
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=missing_cert, tls_key_path=VALID_KEY)
        self.assertEqual(context.exception.reason, REASON_TLS_CERTIFICATE_LOAD_FAILED)

    def test_missing_key_file_produces_the_stable_reason(self) -> None:
        missing_key = self.base / "does-not-exist-key.pem"
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=VALID_CERT, tls_key_path=missing_key)
        self.assertEqual(context.exception.reason, REASON_TLS_CERTIFICATE_LOAD_FAILED)

    def test_malformed_cert_content_produces_the_stable_reason(self) -> None:
        malformed = self.base / "malformed-cert.pem"
        malformed.write_text("this is not a certificate\n", encoding="utf-8")
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=malformed, tls_key_path=VALID_KEY)
        self.assertEqual(context.exception.reason, REASON_TLS_CERTIFICATE_LOAD_FAILED)

    def test_a_mismatched_key_produces_the_stable_reason(self) -> None:
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=VALID_CERT, tls_key_path=MISMATCHED_KEY)
        self.assertEqual(context.exception.reason, REASON_TLS_CERTIFICATE_LOAD_FAILED)

    def test_no_diagnostic_ever_leaks_the_configured_path(self) -> None:
        missing_cert = self.base / "super-secret-looking-path-marker.pem"
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=missing_cert, tls_key_path=VALID_KEY)
        serialized = f"{context.exception!r}{context.exception}"
        self.assertNotIn(str(missing_cert), serialized)
        self.assertNotIn("super-secret-looking-path-marker", serialized)
        self.assertNotIn(str(self.base), serialized)

    def test_no_diagnostic_ever_leaks_certificate_file_content(self) -> None:
        malformed = self.base / "malformed-cert.pem"
        secret_looking_content = "-----BEGIN PRIVATE KEY-----\nsuper-secret-material-marker\n"
        malformed.write_text(secret_looking_content, encoding="utf-8")
        with self.assertRaises(TlsConfigurationError) as context:
            create_server(self.store, TOKEN, tls_cert_path=malformed, tls_key_path=VALID_KEY)
        serialized = f"{context.exception!r}{context.exception}"
        self.assertNotIn("super-secret-material-marker", serialized)

    def test_bad_certificate_never_leaves_a_bound_listening_socket_either(self) -> None:
        port = _free_local_port()
        with self.assertRaises(TlsConfigurationError):
            create_server(
                self.store,
                TOKEN,
                host="127.0.0.1",
                port=port,
                tls_cert_path=self.base / "missing.pem",
                tls_key_path=VALID_KEY,
            )
        server = create_server(self.store, TOKEN, host="127.0.0.1", port=port)
        server.server_close()


class PlainHttpBackwardCompatibilityTests(unittest.TestCase):
    """(d) Omitting TLS args keeps today's plain-HTTP behavior completely unchanged."""

    def test_no_tls_arguments_yields_a_plain_tcp_socket_not_ssl(self) -> None:
        store = Store()
        server = create_server(store, TOKEN)
        try:
            self.assertNotIsInstance(server.socket, ssl.SSLSocket)
        finally:
            server.server_close()
            store.close()

    def test_explicit_none_tls_arguments_are_equivalent_to_omitting_them(self) -> None:
        store = Store()
        server = create_server(store, TOKEN, tls_cert_path=None, tls_key_path=None)
        try:
            self.assertNotIsInstance(server.socket, ssl.SSLSocket)
        finally:
            server.server_close()
            store.close()


def _free_local_port() -> int:
    """Ask the OS for one currently-unused loopback port, then release it."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]
    finally:
        probe.close()


if __name__ == "__main__":
    unittest.main()
