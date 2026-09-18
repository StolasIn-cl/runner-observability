"""CLI-boundary tests for the ``serve`` subcommand's TLS arguments (issue #7).

``runner_observability.__main__`` is a thin dispatcher -- the substantive TLS
wrapping/validation logic lives in and is already fully tested against
``runner_observability.server.create_server`` (see ``tests/test_tls.py``),
the same split this repo already uses for ``deploy.py`` vs. its PowerShell
wrappers. These tests only prove: (1) the CLI actually wires
``--tls-cert``/``--tls-key`` through to ``create_server``, (2) providing
only one of the pair is a controlled, redacted CLI error rather than a
raw traceback or a half-started server, and (3) a bad certificate reaches
the operator as a stable reason code, never a leaked path.

None of these tests ever call the real ``server.serve_forever()`` against a
live socket -- the error-path tests never reach it (validation fails before
the server is even created), and the wiring tests substitute a fake
``create_server`` whose ``serve_forever()`` returns immediately, so no test
here blocks on real network I/O.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runner_observability import __main__ as cli_module
from runner_observability.server import REASON_TLS_CERTIFICATE_LOAD_FAILED, REASON_TLS_PARTIAL_CONFIGURATION


FIXTURES = Path(__file__).parent / "fixtures" / "tls"
VALID_CERT = FIXTURES / "server-cert.pem"
VALID_KEY = FIXTURES / "server-key.pem"


class _FakeServer:
    """A drop-in create_server() stand-in that never opens a real socket."""

    def __init__(self) -> None:
        self.server_address = ("127.0.0.1", 0)
        self.closed = False

    def serve_forever(self) -> None:
        return None

    def server_close(self) -> None:
        self.closed = True


class ServeCliTlsArgumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-cli-test-")
        self.addCleanup(self._tmp.cleanup)
        self.database = str(Path(self._tmp.name) / "monitor.sqlite")

    def test_only_tls_cert_is_a_controlled_error_not_a_traceback(self) -> None:
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            exit_code = cli_module.main(
                [
                    "serve",
                    "--token",
                    "test-token",
                    "--database",
                    self.database,
                    "--tls-cert",
                    str(VALID_CERT),
                ]
            )
        output = captured.getvalue()
        self.assertNotEqual(exit_code, 0)
        self.assertIn(REASON_TLS_PARTIAL_CONFIGURATION, output)
        self.assertNotIn("Traceback", output)

    def test_a_partial_tls_configuration_never_creates_the_database_file(self) -> None:
        # Reviewer fix-round-1 finding (Minor, addressed): the pairing
        # check must run before Store(...) so a mistyped/partial
        # `serve --tls-cert <x>` call (the most likely real operator
        # mistake) never has the side effect of creating/migrating the
        # SQLite database file before failing.
        self.assertFalse(Path(self.database).exists())
        with contextlib.redirect_stderr(io.StringIO()):
            exit_code = cli_module.main(
                [
                    "serve",
                    "--token",
                    "test-token",
                    "--database",
                    self.database,
                    "--tls-cert",
                    str(VALID_CERT),
                ]
            )
        self.assertNotEqual(exit_code, 0)
        self.assertFalse(Path(self.database).exists())

    def test_only_tls_key_is_a_controlled_error_not_a_traceback(self) -> None:
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            exit_code = cli_module.main(
                [
                    "serve",
                    "--token",
                    "test-token",
                    "--database",
                    self.database,
                    "--tls-key",
                    str(VALID_KEY),
                ]
            )
        output = captured.getvalue()
        self.assertNotEqual(exit_code, 0)
        self.assertIn(REASON_TLS_PARTIAL_CONFIGURATION, output)
        self.assertNotIn("Traceback", output)

    def test_a_bad_certificate_reports_a_stable_reason_without_leaking_the_path(self) -> None:
        missing_cert = Path(self._tmp.name) / "does-not-exist-marker-cert.pem"
        captured = io.StringIO()
        with contextlib.redirect_stderr(captured):
            exit_code = cli_module.main(
                [
                    "serve",
                    "--token",
                    "test-token",
                    "--database",
                    self.database,
                    "--tls-cert",
                    str(missing_cert),
                    "--tls-key",
                    str(VALID_KEY),
                ]
            )
        output = captured.getvalue()
        self.assertNotEqual(exit_code, 0)
        self.assertIn(REASON_TLS_CERTIFICATE_LOAD_FAILED, output)
        self.assertNotIn("Traceback", output)
        self.assertNotIn(str(missing_cert), output)
        self.assertNotIn("does-not-exist-marker-cert", output)
        self.assertNotIn(self._tmp.name, output)

    def test_valid_tls_arguments_are_passed_through_to_create_server(self) -> None:
        fake = _FakeServer()
        captured_kwargs: dict[str, object] = {}

        def fake_create_server(store, bearer_token, **kwargs):  # type: ignore[no-untyped-def]
            captured_kwargs.update(kwargs)
            return fake

        with patch.object(cli_module, "create_server", side_effect=fake_create_server):
            exit_code = cli_module.main(
                [
                    "serve",
                    "--token",
                    "test-token",
                    "--database",
                    self.database,
                    "--tls-cert",
                    str(VALID_CERT),
                    "--tls-key",
                    str(VALID_KEY),
                ]
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(captured_kwargs.get("tls_cert_path"), str(VALID_CERT))
        self.assertEqual(captured_kwargs.get("tls_key_path"), str(VALID_KEY))
        self.assertTrue(fake.closed)

    def test_omitting_tls_arguments_passes_none_through(self) -> None:
        fake = _FakeServer()
        captured_kwargs: dict[str, object] = {}

        def fake_create_server(store, bearer_token, **kwargs):  # type: ignore[no-untyped-def]
            captured_kwargs.update(kwargs)
            return fake

        with patch.object(cli_module, "create_server", side_effect=fake_create_server):
            exit_code = cli_module.main(
                ["serve", "--token", "test-token", "--database", self.database]
            )

        self.assertEqual(exit_code, 0)
        self.assertIsNone(captured_kwargs.get("tls_cert_path"))
        self.assertIsNone(captured_kwargs.get("tls_key_path"))


if __name__ == "__main__":
    unittest.main()
