"""Contract tests for the one-command Runner rebuild wizard."""

from __future__ import annotations

from pathlib import Path
import subprocess
import unittest


ROOT = Path(__file__).parents[1]
WIZARD = ROOT / "scripts" / "Initialize-RunnerObservabilityRunner.ps1"
BOOTSTRAP = ROOT / "scripts" / "RunnerObservability.Bootstrap.psm1"
POWERSHELL = "powershell.exe"


def run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            POWERSHELL,
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
        timeout=15,
    )


class RunnerWizardContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WIZARD.read_text(encoding="utf-8") if WIZARD.is_file() else ""
        cls.bootstrap_text = BOOTSTRAP.read_text(encoding="utf-8") if BOOTSTRAP.is_file() else ""

    def test_wizard_exists_and_has_explicit_clean_rebuild_entrypoint(self) -> None:
        self.assertTrue(WIZARD.is_file())
        self.assertRegex(self.text, r"(?im)^\s*\[switch\]\$CleanRebuild\b")
        self.assertIn("$CleanRebuild", self.text)
        self.assertIn("RESET-RUNNER", self.text)

    def test_parameters_cover_operator_inputs_and_safe_preview(self) -> None:
        for parameter in (
            "MonitorIp",
            "MonitorHost",
            "InstallRoot",
            "SecretRoot",
            "SourceRoot",
            "CertificateTrustModel",
            "WhatIf",
            "NoWaitForSecrets",
        ):
            with self.subTest(parameter=parameter):
                self.assertRegex(self.text, rf"(?im)\$[{{(]?{parameter}\b")

    def test_inventory_is_the_first_operational_step_and_clean_reset_is_gated(self) -> None:
        operational_body = self.text.split("function Invoke-RunnerWizard {", 1)[1]
        elevation = operational_body.find("Assert-RunnerWizardAdministrator")
        inventory = operational_body.find("Get-RunnerObservabilityInventory")
        gate = operational_body.find("Assert-RunnerObservabilityInventoryGate")
        mutation_candidates = (
            operational_body.find("Remove-Item"),
            operational_body.find("Invoke-RunnerScript"),
            operational_body.find("SetEnvironmentVariable"),
        )
        mutation = min(index for index in mutation_candidates if index >= 0) if any(
            index >= 0 for index in mutation_candidates
        ) else -1
        self.assertGreaterEqual(inventory, 0)
        self.assertGreaterEqual(elevation, 0)
        self.assertGreaterEqual(gate, 0)
        self.assertGreaterEqual(mutation, 0)
        self.assertLess(elevation, inventory)
        self.assertLess(inventory, mutation)
        self.assertLess(gate, mutation)
        self.assertRegex(self.text, r"(?im)Read-Host.+RESET-RUNNER")

    def test_elevation_failure_is_stable_and_does_not_expose_acl_details(self) -> None:
        self.assertRegex(self.text, r"(?im)WindowsPrincipal")
        self.assertRegex(self.text, r"(?im)IsInRole")
        self.assertIn('New-RunnerWizardError -Reason "administrator_required"', self.text)
        self.assertIn('New-RunnerWizardError -Reason "secret_inventory_access_denied"', self.text)

    def test_secret_inventory_converts_access_denied_into_metadata(self) -> None:
        self.assertRegex(self.bootstrap_text, r"(?im)AccessDenied\s*=")
        self.assertRegex(
            self.bootstrap_text,
            r"(?is)SecretFiles.+?Test-Path.+?-ErrorAction\s+Stop.+?AccessDenied",
        )
        self.assertRegex(self.text, r"(?im)SecretFiles\s*\|\s*Where-Object.+AccessDenied")

    def test_hosts_cleanup_accepts_a_missing_mapping(self) -> None:
        self.assertRegex(self.text, r"(?im)AllowEmptyCollection")
        self.assertRegex(self.text, r"(?im)Mappings\.Count\s*-eq\s*0")

    def test_secret_gate_requires_token_and_certificate_without_printing_contents(self) -> None:
        self.assertIn("monitor-token.txt", self.text)
        self.assertIn("monitor.crt", self.text)
        self.assertIn("monitor.key", self.text)
        self.assertRegex(self.text, r"(?im)WAITING_FOR_MONITOR_FILES")
        self.assertRegex(self.text, r"(?im)\$tokenPath\s*=.+monitor-token\.txt")
        self.assertRegex(self.text, r"(?im)\$certificatePath\s*=.+monitor\.crt")
        self.assertRegex(self.text, r"(?im)Test-Path\s+-LiteralPath\s+\$tokenPath")
        self.assertRegex(self.text, r"(?im)Test-Path\s+-LiteralPath\s+\$certificatePath")
        self.assertIn('New-RunnerWizardError -Reason "monitor_key_not_allowed"', self.text)
        self.assertNotRegex(
            self.text,
            r"(?im)(Write-(Output|Host|Verbose|Debug)|ConvertTo-Json).*(Get-Content|ReadAllText).*(token|secret)",
        )

    def test_release_uses_current_git_head_and_requires_heartbeat_launcher(self) -> None:
        self.assertRegex(self.text, r"(?im)git\s+-C\s+\$SourceRoot\s+rev-parse(?:\s+--verify)?\s+HEAD")
        self.assertIn("runner_heartbeat_service.py", self.text)
        self.assertRegex(self.text, r"(?im)current-release\.txt")
        self.assertNotIn("d3d73b5", self.text)

    def test_python_runtime_is_executed_before_clean_reset(self) -> None:
        resolver = self.text.split("function Resolve-RunnerWizardPython", 1)[1].split(
            "function Get-RunnerWizardCertificateSha256", 1
        )[0]
        self.assertIn("--version", resolver)
        self.assertIn("$versionOutput", resolver)
        self.assertIn("$versionExitCode", resolver)
        self.assertIn("python_execute_exit_code", resolver)
        self.assertIn("-1073741790", resolver)
        self.assertIn("python_execute_access_denied", resolver)
        self.assertIn("win32serviceutil", resolver)
        self.assertIn("windows_service_runtime_unavailable", resolver)
        wizard = self.text.split("function Invoke-RunnerWizard {", 1)[1]
        self.assertLess(wizard.index("Resolve-RunnerWizardPython"), wizard.index('Invoke-RunnerScript -Action "Uninstall"'))

    def test_wizard_delegates_lifecycle_to_existing_runner_installer(self) -> None:
        for action in ("Uninstall", "Preflight", "Configure", "Start"):
            with self.subTest(action=action):
                self.assertRegex(
                    self.text,
                    rf"(?is)-Action\s+['\"]?{action}\b",
                )
        self.assertRegex(self.text, r"(?im)Install-RunnerObservabilityRunner\.ps1")

    def test_child_runner_action_clears_stale_power_shell_exit_code(self) -> None:
        invoke = self.text.split("function Invoke-RunnerScript {", 1)[1].split(
            "function Invoke-RunnerWizardSmokeTest {", 1
        )[0]
        self.assertIn("$global:LASTEXITCODE = 0", invoke)
        self.assertLess(invoke.index("$global:LASTEXITCODE = 0"), invoke.index("& $runnerScript"))

    def test_clean_reset_repairs_only_managed_install_root_acl_after_delete_denial(self) -> None:
        self.assertIn("function Remove-RunnerWizardInstallRoot", self.text)
        cleanup = self.text.split("function Remove-RunnerWizardInstallRoot", 1)[1].split(
            "function Invoke-RunnerWizardSmokeTest", 1
        )[0]
        self.assertIn("takeown.exe", cleanup)
        self.assertIn("icacls.exe", cleanup)
        self.assertIn("reset_install_root_cleanup_failed", cleanup)
        wizard = self.text.split("function Invoke-RunnerWizard {", 1)[1]
        self.assertIn("Remove-RunnerWizardInstallRoot", wizard)

    def test_clean_reset_uses_native_rd_for_managed_install_root_cleanup(self) -> None:
        cleanup = self.text.split("function Remove-RunnerWizardInstallRoot", 1)[1].split(
            "function Invoke-RunnerWizardSmokeTest", 1
        )[0]
        self.assertRegex(cleanup, r'(?im)&\s*cmd\.exe\s+/d\s+/c\s+rd\s+/s\s+/q\s+"\$InstallRoot"')
        self.assertIn("$nativeDeleteExitCode", cleanup)

    def test_wizard_clears_only_owned_machine_environment_variables(self) -> None:
        for name in (
            "RUNNER_OBSERVABILITY_INSTALL_ROOT",
            "RUNNER_OBSERVABILITY_ENDPOINT",
            "RUNNER_OBSERVABILITY_TOKEN_PATH",
            "RUNNER_OBSERVABILITY_RUNNER_ID",
        ):
            with self.subTest(name=name):
                self.assertIn(name, self.text)
        self.assertRegex(self.text, r"(?im)SetEnvironmentVariable\([^\n]+,\s*\$null,\s*['\"]Machine['\"]\)")

    def test_wizard_never_deletes_runner_registration_or_accepts_private_key(self) -> None:
        self.assertNotRegex(self.text, r"(?im)Remove-Item[^\n]*actions-runner")
        self.assertNotRegex(self.text, r"(?im)Remove-Item[^\n]*monitor\.key")
        self.assertRegex(self.text, r"(?im)monitor\.key")


@unittest.skipUnless(Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe").is_file(), "Windows PowerShell required")
class RunnerWizardPowerShellTests(unittest.TestCase):
    def test_wizard_parses_as_windows_powershell(self) -> None:
        completed = run_powershell(
            f"$tokens = $null; $errors = $null; "
            f"[void][System.Management.Automation.Language.Parser]::ParseFile(" +
            f"'{WIZARD}', [ref]$tokens, [ref]$errors); "
            f"if ($errors.Count -gt 0) {{ throw $errors[0].Message }}"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
