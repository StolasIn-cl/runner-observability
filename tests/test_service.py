"""Runner-independent tests for the monitor service configuration seams."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
