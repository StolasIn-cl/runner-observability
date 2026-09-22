"""Contract tests for the shared Windows onboarding bootstrap module."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
BOOTSTRAP_MODULE = ROOT / "scripts" / "RunnerObservability.Bootstrap.psm1"
POWERSHELL = "powershell.exe"


def run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    guarded_script = "$ErrorActionPreference = 'Stop'\n" + script
    return subprocess.run(
        [
            POWERSHELL,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            guarded_script,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
    )


def powershell_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


class BootstrapModuleStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.module_text = (
            BOOTSTRAP_MODULE.read_text(encoding="utf-8")
            if BOOTSTRAP_MODULE.is_file()
            else ""
        )

    def test_module_exports_the_shared_bootstrap_interface(self) -> None:
        self.assertTrue(BOOTSTRAP_MODULE.is_file())
        for function in (
            "Get-RunnerObservabilityInventory",
            "Assert-RunnerObservabilityInventoryGate",
            "New-RunnerObservabilityTokenFile",
            "Set-RunnerObservabilityFileAcl",
            "Set-RunnerObservabilityDirectoryAcl",
            "Set-RunnerObservabilityRuntimeAcl",
            "Set-RunnerObservabilityHostsMapping",
            "Set-RunnerObservabilityMachineEnvironment",
            "Wait-RunnerObservabilityServiceState",
            "Assert-RunnerObservabilityServiceAbsent",
            "Invoke-RunnerObservabilityServiceAction",
        ):
            with self.subTest(function=function):
                self.assertRegex(
                    self.module_text,
                    rf"(?im)^function\s+{re.escape(function)}\b",
                )
                self.assertRegex(
                    self.module_text,
                    rf"(?s)Export-ModuleMember.+[\"']{re.escape(function)}[\"']",
                )

    def test_inventory_contract_is_read_only_and_complete(self) -> None:
        for field in (
            "ComputerName",
            "UserName",
            "PowerShellVersion",
            "PythonCommand",
            "PythonVersion",
            "MachineConfiguration",
            "CandidateRoots",
            "ReleaseState",
            "SecretFiles",
            "MatchingServices",
            "RunnerProcesses",
        ):
            with self.subTest(field=field):
                self.assertIn(field, self.module_text)
        self.assertIn("current-release.txt", self.module_text)
        for state in ("new", "existing", "inspect-before-use"):
            self.assertIn(state, self.module_text)

    def test_secret_creation_uses_secure_input_randomness_and_atomic_write(self) -> None:
        self.assertIn("Read-Host -AsSecureString", self.module_text)
        self.assertIn("RandomNumberGenerator", self.module_text)
        self.assertRegex(self.module_text, r"(?i)WriteAllText")
        self.assertRegex(self.module_text, r"(?i)(File\]::Replace|File\]::Move)")
        self.assertRegex(
            self.module_text,
            r"(?is)monitor\.key.{0,300}(not_allowed|rejected|forbidden)",
        )

    def test_acl_contract_separates_secret_runtime_and_state_access(self) -> None:
        self.assertIn("icacls.exe", self.module_text)
        self.assertIn("SYSTEM:(F)", self.module_text)
        self.assertIn("Administrators:(F)", self.module_text)
        self.assertRegex(self.module_text, r"\{0\}:\(R\)")
        self.assertRegex(self.module_text, r"\{0\}:\(OI\)\(CI\)\(RX\)")
        self.assertRegex(self.module_text, r"\{0\}:\(OI\)\(CI\)\(M\)")
        self.assertNotRegex(
            self.module_text,
            r"(?i)(ServiceAccount[^\r\n]{0,100}FullControl|\{0\}:.*\(F\))",
        )

    def test_runtime_acl_removes_inheritance_before_granting_read_execute(self) -> None:
        runtime_acl = self.module_text.split(
            "function Set-RunnerObservabilityRuntimeAcl", 1
        )[1].split("function New-RunnerObservabilityTokenFile", 1)[0]
        self.assertIn('"/inheritance:r"', runtime_acl)
        self.assertIn('"SYSTEM:(OI)(CI)(F)"', runtime_acl)
        self.assertIn('"Administrators:(OI)(CI)(F)"', runtime_acl)
        self.assertLess(
            runtime_acl.index('"/inheritance:r"'), runtime_acl.index("$serviceGrant,")
        )

    def test_machine_environment_and_hosts_changes_have_explicit_contracts(self) -> None:
        self.assertRegex(
            self.module_text,
            r"SetEnvironmentVariable\([^\r\n]+['\"]Machine['\"]\)",
        )
        self.assertIn("AllowHostsChange", self.module_text)
        self.assertIn("monitor-test.local", self.module_text)
        self.assertRegex(self.module_text, r"(?i)hosts_mapping_conflict")

    def test_service_state_polling_is_bounded(self) -> None:
        self.assertIn("TimeoutSeconds", self.module_text)
        self.assertIn("PollMilliseconds", self.module_text)
        self.assertRegex(self.module_text, r"(?i)Stopwatch")
        self.assertRegex(self.module_text, r"(?i)service_state_timeout")

    def test_source_never_embeds_or_emits_secret_bearing_forms(self) -> None:
        lowered = self.module_text.lower()
        self.assertNotIn("--token ", lowered)
        self.assertNotRegex(self.module_text, r"(?i)Bearer\s+<value>")
        self.assertNotRegex(
            self.module_text,
            r"(?is)Copy-Item[^\r\n]*(monitor\.key)|monitor\.key[^\r\n]*Copy-Item",
        )
        self.assertNotRegex(
            self.module_text,
            r"(?i)(Write-(Output|Host|Verbose|Debug)|Out-String)[^\r\n]*(token|secret)",
        )

    def test_inventory_redacts_credentials_from_service_command_lines(self) -> None:
        self.assertRegex(
            self.module_text,
            r"(?i)--token\\s\+\)\\S\+.+<redacted>",
        )
        self.assertRegex(
            self.module_text,
            r"(?i)Bearer\\s\+\)\\S\+.+<redacted>",
        )

    def test_default_service_inventory_matches_step_zero_terms(self) -> None:
        inventory_signature = self.module_text.split(
            "function Get-RunnerObservabilityInventory", 1
        )[1].split("$pythonCommand", 1)[0]
        for pattern in ("*action*", "*runner*", "*observability*", "*promeo*"):
            with self.subTest(pattern=pattern):
                self.assertIn(f'"{pattern}"', inventory_signature.lower())

    def test_token_temp_file_is_protected_before_plaintext_and_always_cleaned(self) -> None:
        token_function = self.module_text.split(
            "function New-RunnerObservabilityTokenFile", 1
        )[1].split("function Test-RunnerObservabilityMonitorIp", 1)[0]
        self.assertIn("WriteAllBytes", token_function)
        create_empty = token_function.index("WriteAllBytes")
        apply_acl = token_function.index("Set-RunnerObservabilityFileAcl")
        write_plaintext = token_function.index("WriteAllText")
        self.assertLess(create_empty, apply_acl)
        self.assertLess(apply_acl, write_plaintext)
        self.assertRegex(
            token_function,
            r"(?s)finally\s*\{.*Test-Path.+\$temporaryPath.*Remove-Item.+\$temporaryPath",
        )


@unittest.skipUnless(Path(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe").is_file(), "Windows PowerShell required")
class BootstrapModuleBehaviorContractTests(unittest.TestCase):
    def test_inventory_classifies_release_roots_without_reading_secret_contents(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing"
            existing = root / "existing"
            ambiguous = root / "ambiguous"
            traversal = root / "traversal"
            missing_source = root / "missing-source"
            secret = root / "secrets"
            existing.mkdir()
            ambiguous.mkdir()
            traversal.mkdir()
            missing_source.mkdir()
            secret.mkdir()
            (existing / "current-release.txt").write_text("rev-42\n", encoding="utf-8")
            (existing / "releases" / "rev-42" / "src").mkdir(parents=True)
            (ambiguous / "unexpected.txt").write_text("data", encoding="utf-8")
            (traversal / "current-release.txt").write_text("..\\outside\n", encoding="utf-8")
            (traversal / "releases").mkdir()
            (traversal / "outside" / "src").mkdir(parents=True)
            (missing_source / "current-release.txt").write_text(
                "rev-missing\n", encoding="utf-8"
            )
            marker = "NEVER-PRINT-THIS-SECRET"
            (secret / "monitor-token.txt").write_text(marker, encoding="utf-8")
            paths = [
                str(missing),
                str(existing),
                str(ambiguous),
                str(traversal),
                str(missing_source),
            ]
            install_roots = ",".join(powershell_literal(path) for path in paths)
            script = f"""
Import-Module {powershell_literal(BOOTSTRAP_MODULE)} -Force
$result = Get-RunnerObservabilityInventory `
    -CandidateRunnerRoots @() `
    -CandidateInstallRoots @({install_roots}) `
    -CandidateSecretRoots @({powershell_literal(secret)}) `
    -ServiceNamePatterns @()
$result | ConvertTo-Json -Depth 8 -Compress
"""
            completed = run_powershell(script)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(marker, completed.stdout)
            payload = json.loads(completed.stdout.strip())
            states = {
                item["Path"]: item["ReleaseState"]
                for item in payload["InstallRoots"]
            }
            self.assertEqual(states[str(missing)], "new")
            self.assertEqual(states[str(existing)], "existing")
            self.assertEqual(states[str(ambiguous)], "inspect-before-use")
            self.assertEqual(states[str(traversal)], "inspect-before-use")
            self.assertEqual(states[str(missing_source)], "inspect-before-use")

    def test_hosts_mapping_requires_gate_is_exact_and_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text(
                "127.0.0.1 localhost\n192.0.2.9 monitor-test.local.example\n",
                encoding="utf-8",
            )
            script = f"""
Import-Module {powershell_literal(BOOTSTRAP_MODULE)} -Force
$blocked = $null
try {{
    Set-RunnerObservabilityHostsMapping -HostsPath {powershell_literal(hosts)} -MonitorIp '192.0.2.10'
}} catch {{
    $blocked = $_.Exception.Message
}}
$first = Set-RunnerObservabilityHostsMapping -HostsPath {powershell_literal(hosts)} -MonitorIp '192.0.2.10' -AllowHostsChange
$second = Set-RunnerObservabilityHostsMapping -HostsPath {powershell_literal(hosts)} -MonitorIp '192.0.2.10' -AllowHostsChange
[pscustomobject]@{{ Blocked = $blocked; First = $first; Second = $second; Contents = [IO.File]::ReadAllText({powershell_literal(hosts)}) }} |
    ConvertTo-Json -Compress
"""
            completed = run_powershell(script)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            payload = json.loads(completed.stdout.strip())
            self.assertEqual(payload["Blocked"], "hosts_change_not_allowed")
            self.assertTrue(payload["First"]["Changed"])
            self.assertFalse(payload["Second"]["Changed"])
            self.assertIn("192.0.2.9 monitor-test.local.example", payload["Contents"])
            exact_hostname_lines = [
                line
                for line in payload["Contents"].splitlines()
                if "monitor-test.local" in line.split()
            ]
            self.assertEqual(exact_hostname_lines, ["192.0.2.10\tmonitor-test.local"])

    def test_hosts_replacement_preserves_other_aliases_comments_and_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts"
            hosts.write_text(
                "192.0.2.11 alpha monitor-test.local omega # 保留註解\n"
                "192.0.2.12 unrelated # café\n",
                encoding="utf-8",
            )
            script = f"""
Import-Module {powershell_literal(BOOTSTRAP_MODULE)} -Force
Set-RunnerObservabilityHostsMapping `
    -HostsPath {powershell_literal(hosts)} `
    -MonitorIp '192.0.2.10' `
    -AllowHostsChange `
    -ReplaceConflicting | Out-Null
"""
            completed = run_powershell(script)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            contents = hosts.read_text(encoding="utf-8")
            self.assertIn("alpha", contents)
            self.assertIn("omega", contents)
            self.assertIn("# 保留註解", contents)
            self.assertIn("unrelated # café", contents)
            exact_hostname_lines = [
                line
                for line in contents.splitlines()
                if "monitor-test.local" in line.split()
            ]
            self.assertEqual(exact_hostname_lines, ["192.0.2.10\tmonitor-test.local"])

    def test_wait_for_missing_service_times_out_with_stable_reason(self) -> None:
        script = f"""
Import-Module {powershell_literal(BOOTSTRAP_MODULE)} -Force
try {{
    Wait-RunnerObservabilityServiceState `
        -ServiceName 'RunnerObservabilityDefinitelyMissing' `
        -DesiredState Running `
        -TimeoutSeconds 1 `
        -PollMilliseconds 50
    exit 2
}} catch {{
    if ($_.Exception.Message -ne 'service_state_timeout') {{ exit 3 }}
}}
exit 0
"""
        completed = run_powershell(script)

        self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)


if __name__ == "__main__":
    unittest.main()
