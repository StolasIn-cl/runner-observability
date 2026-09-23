"""Runner-independent contracts for the Windows heartbeat service host."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
import subprocess
from unittest.mock import patch

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
POWERSHELL = Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")


def run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(POWERSHELL),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            "$ErrorActionPreference = 'Stop'\n" + script,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


class _FakeServiceManager:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object | None]] = []

    def Initialize(self) -> None:
        self.calls.append(("Initialize", None))

    def PrepareToHostSingle(self, service_class: object) -> None:
        self.calls.append(("PrepareToHostSingle", service_class))

    def StartServiceCtrlDispatcher(self) -> None:
        self.calls.append(("StartServiceCtrlDispatcher", None))


class _FakeServiceApi:
    def __init__(self) -> None:
        self.servicemanager = _FakeServiceManager()
        self.win32event = object()
        self.win32service = object()
        self.win32serviceutil = type(
            "FakeWin32ServiceUtil",
            (),
            {"ServiceFramework": object},
        )


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

    def test_service_command_contains_only_runtime_paths(self) -> None:
        command = build_heartbeat_service_bin_path(
            "C:/secure/heartbeat-config.json",
            "C:/Python/python.exe",
            "C:/runner-observability-agent/releases/1.0.0/src",
        )

        self.assertIn("runner_heartbeat_service.py", command)
        self.assertIn("releases\\1.0.0\\src", command)
        self.assertNotIn("heartbeat-config.json", command)
        self.assertNotIn(" --config ", command)
        self.assertNotIn(" run ", command)
        self.assertNotIn("--token", command)
        self.assertNotIn("secret-token", command)

    def test_managed_release_contains_the_service_launcher(self) -> None:
        launcher = ROOT / "src" / "runner_heartbeat_service.py"

        self.assertTrue(launcher.is_file())
        self.assertIn("runner_observability.heartbeat_service", launcher.read_text(encoding="utf-8"))

    def test_service_launcher_derives_config_for_a_bare_scm_command(self) -> None:
        launcher = ROOT / "src" / "runner_heartbeat_service.py"
        source = launcher.read_text(encoding="utf-8")

        self.assertIn("sys.argv", source)
        self.assertIn("parents[3]", source)
        self.assertIn('"heartbeat-config.json"', source)
        self.assertIn('"run", "--config"', source)

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
            with patch("runner_observability.heartbeat_service._load_service_api", return_value=None):
                with redirect_stderr(captured):
                    result = run_service(path, service_api=None)

        self.assertEqual(result, 2)
        self.assertEqual(captured.getvalue(), f"service failed reason={REASON_WINDOWS_SERVICE_UNAVAILABLE}\n")

    def test_service_host_connects_to_scm_without_command_line_usage(self) -> None:
        with tempfile.TemporaryDirectory(prefix="runner-heartbeat-service-host-") as directory:
            path = Path(directory) / "heartbeat-config.json"
            HeartbeatConfig(
                endpoint="https://monitor.example.test:8765",
                token_file="C:/secure/token.txt",
                runner_id="20000000-0000-4000-8000-000000000001",
                state_file="C:/secure/runner-state.json",
            ).write_atomic(path)
            api = _FakeServiceApi()

            result = run_service(path, service_api=api)

        self.assertEqual(result, 0)
        self.assertEqual(
            [name for name, _ in api.servicemanager.calls],
            ["Initialize", "PrepareToHostSingle", "StartServiceCtrlDispatcher"],
        )
        hosted_class = api.servicemanager.calls[1][1]
        self.assertEqual(hosted_class._svc_name_, "RunnerObservabilityHeartbeat")

    def test_power_shell_lifecycle_contract_is_secret_safe(self) -> None:
        self.assertTrue(SCRIPT.is_file())
        self.assertTrue(MODULE.is_file())
        source = (SCRIPT.read_text(encoding="utf-8") + MODULE.read_text(encoding="utf-8")).lower()
        for term in ("install", "start", "stop", "status", "restart", "uninstall", "tokenpath", "statepath", "endpoint", "start=", "sc.exe"):
            self.assertIn(term, source)
        self.assertIn("nt authority\\localservice", source)
        self.assertIn("runner_heartbeat_service.py", source)
        self.assertIn('"binpath="', source)
        self.assertIn('"obj="', source)
        self.assertIn('"failure"', source)
        self.assertIn('function set-runnerheartbeatdirectorytraverseacl', source)
        self.assertIn('"{0}:(x)"', source)
        self.assertIn('"set-runnerheartbeatdirectorytraverseacl"', source)
        self.assertIn("$backuppath", source)
        self.assertNotIn("replace($temporarypath, $path, $null)", source)
        self.assertNotIn("--token ", source)

    def test_install_rejects_an_existing_exact_service_before_writing_config(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        module = MODULE.read_text(encoding="utf-8")
        self.assertIn("Get-CimInstance", module)
        self.assertIn("Win32_Service", module)
        self.assertIn("service_already_exists", script + module)
        self.assertLess(
            script.index("Assert-RunnerHeartbeatServiceAbsent"),
            script.index("Write-RunnerHeartbeatConfigAtomic"),
        )

    def test_lifecycle_commands_use_bounded_actual_state_readback(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for term in (
            "TimeoutSeconds",
            "PollMilliseconds",
            "Stopwatch",
            "service_state_timeout",
            '-DesiredState "Running"',
            '-DesiredState "Stopped"',
            '-DesiredState "Absent"',
        ):
            with self.subTest(term=term):
                self.assertIn(term, source)
        self.assertIn('if ($state -eq "running")', source)
        self.assertIn('$state -eq "stopped"', source)

    def test_uninstall_stops_before_delete_and_verifies_absence(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        module = MODULE.read_text(encoding="utf-8")
        uninstall = script[script.index('"Uninstall"') :]
        self.assertLess(
            uninstall.index("Stop-RunnerHeartbeatService"),
            uninstall.index("Remove-RunnerHeartbeatService"),
        )
        remove_function = module[module.index("function Remove-RunnerHeartbeatService") :]
        self.assertIn('-DesiredState "Absent"', remove_function)

    def test_service_command_does_not_put_config_arguments_in_scm_binpath(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("runner_heartbeat_service.py", source)
        self.assertIn("$ModulePath", source)
        self.assertIn('$binPath = \'"{0}" "{1}"\' -f $PythonPath, $launcherPath', source)
        self.assertNotIn('run --config', source)
        self.assertNotIn("--token ", source)
        self.assertNotIn("--endpoint ", source)

    def test_exported_state_contract_is_lowercase_and_hides_pending_states(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        for state in ('"running"', '"stopped"', '"unknown"', '"absent"'):
            self.assertIn("return " + state, source)
        self.assertIn("start_pending", source)
        self.assertIn("stop_pending", source)

    def test_pending_states_are_polled_before_start_stop_or_delete_commands(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        start = source[source.index("function Start-RunnerHeartbeatService") :]
        stop = source[source.index("function Stop-RunnerHeartbeatService") :]
        remove = source[source.index("function Remove-RunnerHeartbeatService") :]
        self.assertLess(start.index('"start_pending"'), start.index('"start"'))
        self.assertLess(start.index('"stop_pending"'), start.index('"start"'))
        self.assertLess(stop.index('"start_pending"'), stop.index('"stop"'))
        self.assertLess(stop.index('"stop_pending"'), stop.index('"stop"'))
        self.assertIn("Stop-RunnerHeartbeatService", remove)
        self.assertLess(remove.index("Stop-RunnerHeartbeatService"), remove.index('"delete"'))

    def test_delayed_cim_read_cannot_satisfy_wait_after_deadline(self) -> None:
        if not POWERSHELL.is_file():
            self.skipTest("Windows PowerShell required")
        script = f"""
$module = Import-Module '{MODULE}' -Force -PassThru
& $module {{
    function Get-RunnerHeartbeatServiceRecord {{
        Start-Sleep -Milliseconds 1200
        return [pscustomobject]@{{ State = 'Running' }}
    }}
    try {{
        Wait-RunnerHeartbeatServiceState -ServiceName 'DelayedRead' -DesiredState Running -TimeoutSeconds 1 -PollMilliseconds 25
        exit 2
    }} catch {{
        if ($_.Exception.Message -ne 'service_state_timeout') {{ exit 3 }}
    }}
}}
exit 0
"""
        completed = run_powershell(script)
        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)

    def test_installer_reason_mapping_writes_direct_stderr_under_stop_preference(self) -> None:
        script = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("[System.Console]::Error.WriteLine", script)
        self.assertNotIn("Write-Error", script)
        self.assertIn("exit 2", script)
        for reason in ("service_already_exists", "service_state_timeout"):
            self.assertIn(reason, script)

    def test_runbook_documents_runner_heartbeat_service(self) -> None:
        source = RUNBOOK.read_text(encoding="utf-8")
        for term in ("Runner Heartbeat Service", "Install-RunnerHeartbeatService.ps1", "60 seconds", "state file", "issue #9"):
            self.assertIn(term, source)


if __name__ == "__main__":
    unittest.main()
