"""Runner-independent tests for the monitor service configuration seams."""

from __future__ import annotations

import json
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from runner_observability.service import (
    ServiceConfig,
    ServiceConfigError,
    build_monitor_command,
    build_service_bin_path,
)


class ServiceConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-service-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.config_path = self.base / "service-config.json"
        self.config = ServiceConfig(
            service_name="RunnerObservabilityMonitor",
            python_executable="C:/Python/python.exe",
            database="C:/secure/monitor.sqlite",
            token_file="C:/secure/token.txt",
            host="0.0.0.0",
            port=8765,
            tls_cert="C:/secure/cert.pem",
            tls_key="C:/secure/key.pem",
            release_root="C:/runner-observability",
        )

    def test_command_uses_token_file_and_never_token_value(self) -> None:
        command = build_monitor_command(self.config)
        self.assertIn("--token-file", command)
        self.assertIn("C:/secure/token.txt", command)
        self.assertIn("--tls-cert", command)
        self.assertIn("--tls-key", command)
        self.assertNotIn("secret-value", command)

        service_bin_path = build_service_bin_path(self.config_path, self.config.python_executable)
        self.assertIn("runner_observability.service", service_bin_path)
        self.assertIn(str(self.config_path), service_bin_path)
        self.assertNotIn("secret-value", service_bin_path)

    def test_partial_tls_pair_and_invalid_port_are_rejected(self) -> None:
        with self.assertRaises(ServiceConfigError) as tls_error:
            ServiceConfig.from_mapping({"token_file": "token.txt", "tls_cert": "cert.pem"})
        self.assertEqual(tls_error.exception.reason, "tls_partial_configuration")

        with self.assertRaises(ServiceConfigError) as port_error:
            ServiceConfig.from_mapping({"token_file": "token.txt", "port": 0})
        self.assertEqual(port_error.exception.reason, "invalid_service_configuration")

    def test_unknown_fields_and_empty_required_paths_are_rejected(self) -> None:
        with self.assertRaises(ServiceConfigError) as unknown_error:
            ServiceConfig.from_mapping({"token_file": "token.txt", "unknown": "value"})
        self.assertEqual(unknown_error.exception.reason, "invalid_service_configuration")

        with self.assertRaises(ServiceConfigError) as path_error:
            ServiceConfig.from_mapping({"token_file": ""})
        self.assertEqual(path_error.exception.reason, "invalid_service_configuration")

    def test_config_write_is_atomic_and_contains_no_token_value(self) -> None:
        self.config.write_atomic(self.config_path)

        text = self.config_path.read_text(encoding="utf-8")
        self.assertNotIn("secret-value", text)
        self.assertEqual(ServiceConfig.from_json(self.config_path), self.config)
        self.assertEqual(list(self.base.glob("*.tmp")), [])

    def test_json_loader_rejects_malformed_or_non_object_data(self) -> None:
        self.config_path.write_text("[]", encoding="utf-8")
        with self.assertRaises(ServiceConfigError) as error:
            ServiceConfig.from_json(self.config_path)
        self.assertEqual(error.exception.reason, "invalid_service_configuration")

        self.config_path.write_text(json.dumps({"token_file": "token.txt", "port": "8765"}), encoding="utf-8")
        with self.assertRaises(ServiceConfigError) as type_error:
            ServiceConfig.from_json(self.config_path)
        self.assertEqual(type_error.exception.reason, "invalid_service_configuration")


class _FakeChild:
    def __init__(self, exit_code: int | None, *, ignores_terminate: bool = False) -> None:
        self.exit_code = exit_code
        self.ignores_terminate = ignores_terminate
        self.terminate_calls = 0
        self.kill_calls = 0

    def poll(self) -> int | None:
        return self.exit_code

    def terminate(self) -> None:
        self.terminate_calls += 1
        if not self.ignores_terminate:
            self.exit_code = 0

    def wait(self, timeout: float | None = None) -> int:
        if self.exit_code is None:
            raise TimeoutError("still-running")
        return self.exit_code

    def kill(self) -> None:
        self.kill_calls += 1
        self.exit_code = -9


class _StopImmediately:
    def is_set(self) -> bool:
        return True

    def wait(self, timeout: float | None = None) -> bool:
        return True


class _NeverStop:
    def is_set(self) -> bool:
        return False

    def wait(self, timeout: float | None = None) -> bool:
        return False


class MonitorChildSupervisorTests(unittest.TestCase):
    def _supervisor(self, child: _FakeChild):
        from runner_observability.service import MonitorChildSupervisor

        return MonitorChildSupervisor(
            ("python", "-m", "runner_observability", "serve", "--token-file", "token.txt"),
            lambda command, **kwargs: child,
            stop_timeout=0.01,
            poll_interval=0.0,
        )

    def test_stop_terminates_child_and_waits_within_bound(self) -> None:
        child = _FakeChild(exit_code=None)

        result = self._supervisor(child).run(_StopImmediately())

        self.assertEqual(result, 0)
        self.assertEqual(child.terminate_calls, 1)
        self.assertEqual(child.kill_calls, 0)

    def test_stop_kills_a_child_that_does_not_exit(self) -> None:
        child = _FakeChild(exit_code=None, ignores_terminate=True)

        result = self._supervisor(child).run(_StopImmediately())

        self.assertEqual(result, -9)
        self.assertEqual(child.terminate_calls, 1)
        self.assertEqual(child.kill_calls, 1)

    def test_unexpected_child_exit_is_returned_as_failure(self) -> None:
        child = _FakeChild(exit_code=17)

        result = self._supervisor(child).run(_NeverStop())

        self.assertEqual(result, 17)

    def test_missing_windows_service_runtime_reports_a_stable_reason(self) -> None:
        from runner_observability import service as service_module

        config_path = Path(tempfile.gettempdir()) / "runner-observability-service-test-config.json"
        config = ServiceConfig(token_file="C:/secure/token.txt")
        config.write_atomic(config_path)
        self.addCleanup(config_path.unlink, missing_ok=True)
        captured = io.StringIO()

        with patch.object(service_module, "_load_service_api", return_value=None):
            with contextlib.redirect_stderr(captured):
                result = service_module.main(["run", "--config", str(config_path)])

        self.assertEqual(result, 2)
        self.assertEqual(captured.getvalue(), "service failed reason=windows_service_unavailable\n")
        self.assertNotIn(str(config_path), captured.getvalue())


if __name__ == "__main__":
    unittest.main()
