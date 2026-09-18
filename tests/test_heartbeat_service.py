"""Runner-independent contracts for the Windows heartbeat service host."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO

from runner_observability.heartbeat import HeartbeatConfig
from runner_observability.heartbeat_service import (
    REASON_WINDOWS_SERVICE_UNAVAILABLE,
    build_heartbeat_service_bin_path,
    run_service,
)


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "Install-RunnerHeartbeatService.ps1"
MODULE = ROOT / "scripts" / "RunnerHeartbeat.Service.psm1"
RUNBOOK = ROOT / "docs" / "runbook.md"


class HeartbeatServiceTests(unittest.TestCase):
    def test_config_round_trips_without_a_token_value(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runner-heartbeat-config-") as directory:
            path = Path(directory) / "heartbeat-config.json"
            config = HeartbeatConfig(
                endpoint="https://monitor.example.test:8765",
                token_file="C:/secure/token.txt",
                runner_id="20000000-0000-4000-8000-000000000001",
                state_file="C:/secure/runner-state.json",
            )
            config.write_atomic(path)
            loaded = HeartbeatConfig.from_json(path)
            serialized = path.read_text(encoding="utf-8")

        self.assertEqual(loaded, config)
        self.assertNotIn("token-value", serialized)

    def test_service_command_contains_only_config_path(self) -> None:
        command = build_heartbeat_service_bin_path("C:/secure/heartbeat-config.json", "C:/Python/python.exe")

        self.assertIn("runner_observability.heartbeat_service", command)
        self.assertIn("heartbeat-config.json", command)
        self.assertNotIn("--token", command)
        self.assertNotIn("secret-token", command)

    def test_non_windows_host_reports_stable_unavailable_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runner-heartbeat-config-") as directory:
            path = Path(directory) / "heartbeat-config.json"
            HeartbeatConfig(
                endpoint="https://monitor.example.test:8765",
                token_file="C:/secure/token.txt",
                runner_id="20000000-0000-4000-8000-000000000001",
                state_file="C:/secure/runner-state.json",
            ).write_atomic(path)
            captured = StringIO()
            with redirect_stderr(captured):
                result = run_service(path, service_api=None)

        self.assertEqual(result, 2)
        self.assertEqual(captured.getvalue(), f"service failed reason={REASON_WINDOWS_SERVICE_UNAVAILABLE}\n")

    def test_power_shell_lifecycle_contract_is_secret_safe(self) -> None:
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue(MODULE.is_file())
        source = (SCRIPT.read_text(encoding="utf-8") + MODULE.read_text(encoding="utf-8")).lower()
        for term in ("install", "start", "stop", "status", "restart", "uninstall", "tokenpath", "statepath", "endpoint", "start= auto", "sc.exe"):
            self.assertIn(term, source)
        self.assertIn("nt authority\\localservice", source)
        self.assertIn("heartbeat_service run --config", source)
        self.assertNotIn("--token ", source)

    def test_runbook_documents_runner_heartbeat_service(self) -> None:
        source = RUNBOOK.read_text(encoding="utf-8")
        for term in ("Runner Heartbeat Service", "Install-RunnerHeartbeatService.ps1", "60 seconds", "state file", "issue #9"):
            self.assertIn(term, source)


if __name__ == "__main__":
    unittest.main()
