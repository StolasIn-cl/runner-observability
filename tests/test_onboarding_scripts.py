"""Contract tests for the shared Windows onboarding bootstrap module."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
BOOTSTRAP_MODULE = ROOT / "scripts" / "RunnerObservability.Bootstrap.psm1"
MONITOR_SCRIPT = ROOT / "scripts" / "Install-RunnerObservabilityMonitor.ps1"
RUNNER_SCRIPT = ROOT / "scripts" / "Install-RunnerObservabilityRunner.ps1"
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
            "Set-RunnerObservabilityRuntimeFileAcl",
            "Set-RunnerObservabilityRuntimeParentTraverseAcl",
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
        self.assertIn("Get-RunnerObservabilityCurrentAccount", runtime_acl)
        self.assertIn("$runtimeUserGrant", runtime_acl)
        self.assertIn("$runtimeFileServiceGrant", runtime_acl)
        self.assertIn("$runtimeFileUserGrant", runtime_acl)
        self.assertIn("WindowsIdentity]::GetCurrent()", self.module_text)
        self.assertLess(
            runtime_acl.index('"/inheritance:r"'), runtime_acl.index("$serviceGrant,")
        )

    def test_runtime_acl_checks_native_recursive_failures_and_exact_files(self) -> None:
        self.assertIn("Failed processing", self.module_text)
        self.assertIn("Access is denied", self.module_text)
        self.assertIn("function Set-RunnerObservabilityRuntimeFileAcl", self.module_text)

        runner = RUNNER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Set-RunnerObservabilityRuntimeFileAcl -Path $PythonPath", runner)
        self.assertGreaterEqual(runner.count("Set-RunnerObservabilityRuntimeFileAcl"), 2)
        self.assertIn("Join-Path $releaseSource", runner)
        self.assertIn("Set-RunnerHeartbeatDirectoryTraverseAcl", runner)

    def test_per_user_runtime_grants_only_parent_traverse_access(self) -> None:
        self.assertIn("function Set-RunnerObservabilityRuntimeParentTraverseAcl", self.module_text)
        traverse = self.module_text.split(
            "function Set-RunnerObservabilityRuntimeParentTraverseAcl", 1
        )[1].split("function Set-RunnerObservabilityRuntimeFileAcl", 1)[0]
        self.assertIn("Split-Path -Parent", traverse)
        self.assertIn("(X)", traverse)
        self.assertIn("runtime_parent_acl_failed", traverse)

        runner = RUNNER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Set-RunnerObservabilityRuntimeParentTraverseAcl", runner)

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


class MonitorRoleScriptStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script_text = (
            MONITOR_SCRIPT.read_text(encoding="utf-8")
            if MONITOR_SCRIPT.is_file()
            else ""
        )
        cls.lowered = cls.script_text.lower()
        cls.readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.runbook_text = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")

    def test_monitor_entry_point_exposes_required_parameters_and_actions(self) -> None:
        self.assertTrue(MONITOR_SCRIPT.is_file())
        for parameter in (
            "Action",
            "PythonPath",
            "ConfigPath",
            "DatabasePath",
            "SecretRoot",
            "TokenPath",
            "TlsCertPath",
            "TlsKeyPath",
            "CertificateMode",
            "RunnerAddress",
            "ServiceName",
            "ServiceAccount",
            "AllowDevSelfSigned",
            "TrustSelfSignedCertificate",
            "WhatIf",
        ):
            with self.subTest(parameter=parameter):
                self.assertRegex(self.script_text, rf"\$({parameter})\b")
        for action in (
            "Preflight",
            "Install",
            "RepairPermissions",
            "Start",
            "Stop",
            "Restart",
            "Status",
            "Uninstall",
        ):
            with self.subTest(action=action):
                self.assertIn(action, self.script_text)

    def test_monitor_script_runs_inventory_before_mutations(self) -> None:
        self.assertIn("RunnerObservability.Bootstrap.psm1", self.script_text)
        self.assertIn("RunnerObservability.Service.psm1", self.script_text)
        inventory = self.script_text.index("Get-RunnerObservabilityInventory")
        gate = self.script_text.index("Assert-RunnerObservabilityInventoryGate")
        mutation = self.script_text.index("New-RunnerObservabilityTokenFile")
        self.assertLess(inventory, gate)
        self.assertLess(gate, mutation)
        self.assertIn('Operation "Troubleshooting"', self.script_text)
        self.assertIn('Role "Monitor"', self.script_text)

    def test_monitor_certificate_modes_are_explicit_and_self_signed_is_native(self) -> None:
        for mode in ("PublicCa", "PrivateCa", "SelfSigned", "Existing"):
            with self.subTest(mode=mode):
                self.assertIn(mode, self.script_text)
        for marker in (
            "CertificateRequest",
            "RSA]::Create",
            "2048",
            "CreateSelfSigned",
            "X509ContentType]::Cert",
            "ConvertTo-MonitorPkcs8Pem",
            "ExportParameters",
            "New-SelfSignedCertificate",
            "KeyExportPolicy",
            "Label \"CERTIFICATE\"",
            "Label \"PRIVATE KEY\"",
            "certificate_generation_unavailable",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, self.script_text)
        self.assertNotIn("openssl", self.lowered)
        self.assertNotIn("openssl.exe", self.lowered)
        self.assertIn("Write-MonitorProtectedTextAtomically", self.script_text)
        self.assertLess(
            self.script_text.index("WriteAllBytes($temporaryPath"),
            self.script_text.index("Set-RunnerObservabilityFileAcl -Path $temporaryPath"),
        )
        self.assertLess(
            self.script_text.index("Set-RunnerObservabilityFileAcl -Path $temporaryPath"),
            self.script_text.index("WriteAllText($temporaryPath"),
        )

    def test_monitor_self_signed_trust_is_explicit_and_runs_after_generation(self) -> None:
        self.assertIn("TrustSelfSignedCertificate", self.script_text)
        self.assertIn("Import-Certificate", self.script_text)
        self.assertIn('Cert:\\CurrentUser\\Root', self.script_text)
        self.assertIn('certificate_trust_import_failed', self.script_text)
        install = self.script_text[
            self.script_text.index("function Invoke-MonitorInstall") :
            self.script_text.index("function Invoke-MonitorRepairPermissions")
        ]
        self.assertLess(
            install.index("New-MonitorSelfSignedCertificate"),
            install.index("Import-MonitorSelfSignedCertificate"),
        )

    def test_monitor_docs_describe_browser_trust_for_clean_self_signed_install(self) -> None:
        combined = (self.readme_text + "\n" + self.runbook_text).lower()
        for term in (
            "-trustselfsignedcertificate",
            "currentuser\\root",
            "https://monitor-test.local:8765/",
            "certificate trust",
        ):
            with self.subTest(term=term):
                self.assertIn(term, combined)

    def test_monitor_self_signed_preflight_supports_windows_powershell_crypto_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = f"""
& {powershell_literal(MONITOR_SCRIPT)} `
    -Action Preflight `
    -PythonPath (Get-Command python).Source `
    -ConfigPath {powershell_literal(root / 'config' / 'service-config.json')} `
    -DatabasePath {powershell_literal(root / 'data' / 'monitor.sqlite')} `
    -SecretRoot {powershell_literal(root / 'secrets')} `
    -CertificateMode SelfSigned `
    -AllowDevSelfSigned `
    -RunnerAddress '192.0.2.1'
"""
            completed = run_powershell(script)

            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            payload = json.loads(completed.stdout.strip().splitlines()[-1])
            self.assertEqual(payload["Reason"], "preflight_passed")

    def test_monitor_self_signed_generates_python_tls_compatible_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cert_path = root / "secrets" / "monitor.crt"
            key_path = root / "secrets" / "monitor.key"
            script = f"""
$parameters = @{{
    Action = 'Preflight'
    PythonPath = (Get-Command python).Source
    ConfigPath = {powershell_literal(root / 'config' / 'service-config.json')}
    DatabasePath = {powershell_literal(root / 'data' / 'monitor.sqlite')}
    SecretRoot = {powershell_literal(root / 'secrets')}
    CertificateMode = 'SelfSigned'
    AllowDevSelfSigned = $true
    RunnerAddress = @('192.0.2.1')
    ServiceAccount = 'CurrentUser'
}}
. {powershell_literal(MONITOR_SCRIPT)} @parameters | Out-Null
function Set-RunnerObservabilityFileAcl {{
    param([string]$Path, [string]$ServiceAccount)
}}
$metadata = New-MonitorSelfSignedCertificate `
    -CertificatePath {powershell_literal(cert_path)} `
    -PrivateKeyPath {powershell_literal(key_path)}
[pscustomobject]@{{
    FingerprintLength = $metadata.Fingerprint.Length
    CertificateExists = Test-Path -LiteralPath {powershell_literal(cert_path)} -PathType Leaf
    PrivateKeyExists = Test-Path -LiteralPath {powershell_literal(key_path)} -PathType Leaf
    CertificatePem = ([IO.File]::ReadAllText({powershell_literal(cert_path)})).Trim().StartsWith('-----BEGIN CERTIFICATE-----')
    PrivateKeyPem = ([IO.File]::ReadAllText({powershell_literal(key_path)})).Trim().StartsWith('-----BEGIN PRIVATE KEY-----')
}} | ConvertTo-Json -Compress
"""
            completed = run_powershell(script)

            self.assertEqual(completed.returncode, 0, completed.stderr + completed.stdout)
            payload = json.loads(completed.stdout.strip().splitlines()[-1])
            self.assertEqual(payload["FingerprintLength"], 64)
            self.assertTrue(payload["CertificateExists"])
            self.assertTrue(payload["PrivateKeyExists"])
            self.assertTrue(payload["CertificatePem"])
            self.assertTrue(payload["PrivateKeyPem"])

            tls_check = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import ssl, sys; ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_cert_chain(sys.argv[1], sys.argv[2])",
                    str(cert_path),
                    str(key_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(tls_check.returncode, 0, tls_check.stderr)

    def test_monitor_script_keeps_token_and_private_key_out_of_commands_and_output(self) -> None:
        self.assertNotRegex(self.script_text, r"(?im)^\s*\[string\]\$Token\b")
        self.assertNotRegex(self.script_text, r"(?i)-Token\s+\$|--token\s+\$|--token\s+\S+")
        self.assertIn("--token-file", self.script_text)
        self.assertNotRegex(
            self.script_text,
            r"(?is)(Copy-Item|Copy-File|Move-Item)[^\r\n]*(monitor\.key)|monitor\.key[^\r\n]*(Copy-Item|Copy-File|Move-Item)",
        )
        self.assertNotRegex(
            self.script_text,
            r"(?im)Write-(Host|Output|Verbose|Debug)[^\r\n]*(token|monitor\.key|private key|certificate content)",
        )
        self.assertIn("fingerprint", self.lowered)
        self.assertIn("expiry", self.lowered)
        self.assertIn("reason", self.lowered)

    def test_monitor_install_uses_existing_service_adapter_and_safe_uninstall(self) -> None:
        for term in (
            "Assert-RunnerObservabilityServiceAbsent",
            "Register-RunnerObservabilityService",
            "Start-RunnerObservabilityService",
            "Stop-RunnerObservabilityService",
            "Get-RunnerObservabilityServiceState",
            "Remove-RunnerObservabilityService",
            "Ensure-RunnerObservabilityFirewallRule",
            "Remove-RunnerObservabilityFirewallRule",
            "Write-RunnerObservabilityConfigAtomic",
            "Set-RunnerObservabilityFileAcl",
            "Set-RunnerObservabilityDirectoryAcl",
        ):
            with self.subTest(term=term):
                self.assertIn(term, self.script_text)
        uninstall = self.script_text[self.script_text.index('"Uninstall"') :]
        self.assertLess(
            uninstall.index("Remove-RunnerObservabilityService"),
            uninstall.index("Remove-RunnerObservabilityFirewallRule"),
        )
        self.assertIn("preserve", self.lowered)

    def test_monitor_reinstall_repairs_existing_config_before_atomic_replace(self) -> None:
        self.assertIn('"service_config_write_failed"', self.script_text)
        install = self.script_text[
            self.script_text.index("function Invoke-MonitorInstall") :
            self.script_text.index("function Invoke-MonitorRepairPermissions")
        ]
        repair_config_acl = install.index("Set-RunnerObservabilityFileAcl -Path $ConfigPath")
        config_write = install.index("Write-RunnerObservabilityConfigAtomic")
        self.assertLess(repair_config_acl, config_write)

    def test_docs_describe_monitor_first_order_and_certificate_fallback(self) -> None:
        combined = (self.readme_text + "\n" + self.runbook_text).lower()
        for term in (
            "install-runnerobservabilitymonitor.ps1",
            "-action preflight",
            "-action install",
            "-action repairpermissions",
            "-action status",
            "-action stop",
            "-action start",
            "-action restart",
            "-action uninstall",
            "selfsigned",
            "certificaterequest",
            "certificate_generation_unavailable",
            "monitor.key",
            "do not copy",
            "runner",
            "inventory",
        ):
            with self.subTest(term=term):
                self.assertIn(term, combined)


class RunnerRoleScriptStaticContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script_text = RUNNER_SCRIPT.read_text(encoding="utf-8") if RUNNER_SCRIPT.is_file() else ""
        cls.lowered = cls.script_text.lower()
        cls.readme_text = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.runbook_text = (ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")

    def test_runner_entry_point_exposes_required_parameters_and_actions(self) -> None:
        self.assertTrue(RUNNER_SCRIPT.is_file())
        for parameter in (
            "Action", "PythonPath", "InstallRoot", "Endpoint", "TokenPath", "RunnerId",
            "StatePath", "MonitorHost", "MonitorIp", "CertificateTrustModel",
            "MonitorCertificatePath", "ExpectedCertificateSha256", "ImportCertificate",
            "AllowHostsChange", "RunnerAccount", "ServiceAccount", "ServiceName",
            "AllowInsecureHttp",
        ):
            with self.subTest(parameter=parameter):
                self.assertRegex(self.script_text, rf"\$({parameter})\b")
        for action in (
            "Preflight", "Configure", "RepairPermissions", "Start", "Stop", "Restart", "Status", "Uninstall"
        ):
            with self.subTest(action=action):
                self.assertIn(action, self.script_text)

    def test_runner_uses_inventory_and_service_config_path_without_token_value(self) -> None:
        self.assertIn("RunnerObservability.Bootstrap.psm1", self.script_text)
        self.assertIn("RunnerHeartbeat.Service.psm1", self.script_text)
        self.assertIn("Get-RunnerObservabilityInventory", self.script_text)
        self.assertIn("Assert-RunnerObservabilityInventoryGate", self.script_text)
        self.assertIn("Register-RunnerHeartbeatService", self.script_text)
        self.assertIn("Get-RunnerReleaseSource", self.script_text)
        self.assertIn("-ModulePath $releaseSource", self.script_text)
        self.assertIn("Write-RunnerHeartbeatConfigAtomic", self.script_text)
        self.assertNotRegex(self.script_text, r"(?im)^\s*\[string\]\$Token\b")
        self.assertNotRegex(self.script_text, r"(?i)--token\s+\$|--token\s+\S+")
        self.assertNotIn("monitor.key", self.lowered.replace('"monitor.key"', ""))
        self.assertIn("monitor_key_not_allowed", self.script_text)

    def test_runner_preflight_checks_the_windows_service_runtime(self) -> None:
        self.assertIn("_load_service_api", self.script_text)
        self.assertIn("windows_service_runtime_unavailable", self.script_text)

    def test_runner_requires_confirmed_monitor_address_and_rejects_key_copy(self) -> None:
        self.assertIn("Test-RunnerObservabilityMonitorIp", self.script_text)
        self.assertIn("monitor_ip_invalid", self.script_text)
        self.assertIn("monitor_host_invalid", self.script_text)
        self.assertIn("AllowHostsChange", self.script_text)
        self.assertIn("Set-RunnerObservabilityHostsMapping", self.script_text)
        self.assertNotRegex(
            self.script_text,
            r"(?is)(Copy-Item|Copy-File|Move-Item)[^\r\n]*(monitor\.key)|monitor\.key[^\r\n]*(Copy-Item|Copy-File|Move-Item)",
        )

    def test_runner_certificate_import_requires_sha256_before_import(self) -> None:
        self.assertIn("ExpectedCertificateSha256", self.script_text)
        self.assertIn("certificate_fingerprint_mismatch", self.script_text)
        self.assertIn("Import-Certificate", self.script_text)
        self.assertLess(
            self.script_text.index("certificate_fingerprint_mismatch"),
            self.script_text.index("Import-Certificate"),
        )
        self.assertIn("-PromptForToken", self.script_text)
        self.assertIn("Read-Host -AsSecureString", (BOOTSTRAP_MODULE.read_text(encoding="utf-8")))
        self.assertIn("New-RunnerObservabilityTokenFile", self.script_text)

    def test_runner_grants_token_access_to_the_direct_listener_account(self) -> None:
        bootstrap = BOOTSTRAP_MODULE.read_text(encoding="utf-8")
        heartbeat_service = (ROOT / "scripts" / "RunnerHeartbeat.Service.psm1").read_text(encoding="utf-8")

        self.assertIn("function Resolve-RunnerAccount", self.script_text)
        self.assertIn("GetOwner", self.script_text)
        self.assertIn("runner_account_discovery_failed", self.script_text)
        self.assertIn("AdditionalReadAccount", bootstrap)
        self.assertIn("AdditionalReadAccount", heartbeat_service)
        self.assertIn("-AdditionalReadAccount $RunnerAccount", self.script_text)
        self.assertIn("Set-RunnerHeartbeatDirectoryTraverseAcl", self.script_text)
        self.assertNotRegex(
            (bootstrap + heartbeat_service),
            r"(?i)Everyone:\(.*R",
        )

    def test_runner_permission_repair_canonicalizes_existing_ci_endpoint(self) -> None:
        repair = self.script_text.split("function Invoke-RunnerRepairPermissions", 1)[1].split(
            "function Invoke-RunnerLifecycle", 1
        )[0]

        self.assertIn("RUNNER_OBSERVABILITY_ENDPOINT", repair)
        self.assertIn("Assert-RunnerEndpoint", repair)
        self.assertIn("Write-RunnerHeartbeatConfigAtomic", repair)
        self.assertIn("Set-RunnerObservabilityMachineEnvironment", repair)

    def test_docs_describe_monitor_then_runner_order(self) -> None:
        combined = (self.readme_text + "\n" + self.runbook_text).lower()
        for term in (
            "install-runnerobservabilityrunner.ps1",
            "-action preflight",
            "-action configure",
            "-action repairpermissions",
            "-action status",
            "-action stop",
            "-action start",
            "-action restart",
            "-action uninstall",
            "monitor first",
            "runner",
            "monitor.key",
        ):
            with self.subTest(term=term):
                self.assertIn(term, combined)


if __name__ == "__main__":
    unittest.main()
