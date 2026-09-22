"""Static contract tests for the Windows service PowerShell boundary."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest

from runner_observability.deploy import WindowsScServiceLifecycle


ROOT = Path(__file__).parents[1]
SERVICE_MODULE = ROOT / "scripts" / "RunnerObservability.Service.psm1"
SERVICE_SCRIPT = ROOT / "scripts" / "Install-RunnerObservabilityService.ps1"
SERVICE_RUNTIME = ROOT / "src" / "runner_observability" / "service.py"
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


class ServiceScriptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module_text = SERVICE_MODULE.read_text(encoding="utf-8")
        cls.script_text = SERVICE_SCRIPT.read_text(encoding="utf-8")
        cls.runtime_text = SERVICE_RUNTIME.read_text(encoding="utf-8")

    def test_service_script_exposes_all_lifecycle_actions(self) -> None:
        self.assertTrue(SERVICE_MODULE.is_file())
        self.assertTrue(SERVICE_SCRIPT.is_file())
        for action in ("Install", "Start", "Stop", "Status", "Restart", "Uninstall"):
            self.assertIn(action, self.script_text)

    def test_service_script_uses_secret_safe_inputs(self) -> None:
        lowered = self.script_text.lower() + self.module_text.lower()
        self.assertIn("--token-file", self.runtime_text)
        self.assertIn("new-netfirewallrule", lowered)
        self.assertIn("icacls", lowered)
        self.assertNotIn("password", lowered)
        self.assertNotIn("--token ", self.module_text)

    def test_firewall_rule_is_scoped_to_runner_addresses_and_fixed_name(self) -> None:
        self.assertIn("-RemoteAddress $RunnerAddress", self.module_text)
        self.assertIn("Runner Observability Monitor TCP 8765", self.module_text)
        self.assertIn("Remove-NetFirewallRule", self.module_text)

    def test_service_command_configures_recovery_and_local_service_default(self) -> None:
        lowered = self.script_text.lower() + self.module_text.lower()
        self.assertIn("sc.exe", lowered)
        self.assertIn("failure", lowered)
        self.assertIn("nt authority\\localservice", lowered)
        self.assertIn("runner_observability.service run --config", lowered)

    def test_sc_options_pass_names_and_values_as_separate_arguments(self) -> None:
        for fragment in (
            '"binPath=", $binPath',
            '"start=", "auto"',
            '"DisplayName=", "Runner Observability Monitor"',
            '"obj=", $ServiceAccount',
            '"reset=", "86400"',
            '"actions=", "restart/5000/restart/30000/restart/60000"',
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, self.module_text)
        self.assertNotIn('"start= auto"', self.module_text)

    def test_acl_rules_separate_read_only_and_modify_access(self) -> None:
        self.assertIn('-Access "R"', self.script_text)
        self.assertIn('(OI)(CI)(M)', self.module_text)
        self.assertIn('(OI)(CI)(F)', self.module_text)
        self.assertIn("SYSTEM:(F)", self.module_text)
        self.assertIn("Administrators:(F)", self.module_text)

    def test_install_rejects_an_existing_exact_service_before_writing_config(self) -> None:
        self.assertIn("Get-CimInstance", self.module_text)
        self.assertIn("Win32_Service", self.module_text)
        self.assertIn("service_already_exists", self.module_text + self.script_text)
        absent_check = self.script_text.index("Assert-RunnerObservabilityServiceAbsent")
        config_write = self.script_text.index("Write-RunnerObservabilityConfigAtomic")
        self.assertLess(absent_check, config_write)

    def test_lifecycle_commands_use_bounded_actual_state_readback(self) -> None:
        for term in (
            "TimeoutSeconds",
            "PollMilliseconds",
            "Stopwatch",
            "service_state_timeout",
            "-DesiredState \"Running\"",
            "-DesiredState \"Stopped\"",
            "-DesiredState \"Absent\"",
        ):
            with self.subTest(term=term):
                self.assertIn(term, self.module_text)
        self.assertIn('if ($state -eq "running")', self.module_text)
        self.assertIn('$state -eq "stopped"', self.module_text)

    def test_uninstall_stops_before_delete_and_verifies_absence(self) -> None:
        uninstall = self.script_text[self.script_text.index('"Uninstall"') :]
        self.assertLess(
            uninstall.index("Stop-RunnerObservabilityService"),
            uninstall.index("Remove-RunnerObservabilityService"),
        )
        remove_function = self.module_text[self.module_text.index("function Remove-RunnerObservabilityService") :]
        self.assertIn('-DesiredState "Absent"', remove_function)

    def test_python_lifecycle_maps_a_successful_transitional_query_to_unknown(self) -> None:
        def runner(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(
                arguments,
                0,
                stdout="STATE : 2  START_PENDING",
                stderr="",
            )

        lifecycle = WindowsScServiceLifecycle("RunnerObservabilityMonitor", runner)

        self.assertEqual(lifecycle.status(), "unknown")

    def test_exported_state_contract_is_lowercase_and_hides_pending_states(self) -> None:
        for state in ('"running"', '"stopped"', '"unknown"', '"absent"'):
            self.assertIn("return " + state, self.module_text)
        self.assertIn("start_pending", self.module_text)
        self.assertIn("stop_pending", self.module_text)

    def test_pending_states_are_polled_before_start_stop_or_delete_commands(self) -> None:
        start = self.module_text[self.module_text.index("function Start-RunnerObservabilityService") :]
        stop = self.module_text[self.module_text.index("function Stop-RunnerObservabilityService") :]
        remove = self.module_text[self.module_text.index("function Remove-RunnerObservabilityService") :]
        self.assertLess(start.index('"start_pending"'), start.index('"start"'))
        self.assertLess(start.index('"stop_pending"'), start.index('"start"'))
        self.assertLess(stop.index('"start_pending"'), stop.index('"stop"'))
        self.assertLess(stop.index('"stop_pending"'), stop.index('"stop"'))
        self.assertIn("Stop-RunnerObservabilityService", remove)
        self.assertLess(remove.index("Stop-RunnerObservabilityService"), remove.index('"delete"'))

    def test_delayed_cim_read_cannot_satisfy_wait_after_deadline(self) -> None:
        self.skipTestUnlessPowerShell()
        script = f"""
$module = Import-Module '{SERVICE_MODULE}' -Force -PassThru
& $module {{
    function Get-RunnerObservabilityServiceRecord {{
        Start-Sleep -Milliseconds 1200
        return [pscustomobject]@{{ State = 'Running' }}
    }}
    try {{
        Wait-RunnerObservabilityServiceState -ServiceName 'DelayedRead' -DesiredState Running -TimeoutSeconds 1 -PollMilliseconds 25
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
        self.assertIn("[System.Console]::Error.WriteLine", self.script_text)
        self.assertNotIn("Write-Error", self.script_text)
        self.assertIn("exit 2", self.script_text)
        for reason in ("service_already_exists", "service_state_timeout"):
            self.assertIn(reason, self.script_text)

    @staticmethod
    def skipTestUnlessPowerShell() -> None:
        if not POWERSHELL.is_file():
            raise unittest.SkipTest("Windows PowerShell required")


if __name__ == "__main__":
    unittest.main()
