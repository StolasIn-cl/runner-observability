"""Static contract tests for the Windows service PowerShell boundary."""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]
SERVICE_MODULE = ROOT / "scripts" / "RunnerObservability.Service.psm1"
SERVICE_SCRIPT = ROOT / "scripts" / "Install-RunnerObservabilityService.ps1"
SERVICE_RUNTIME = ROOT / "src" / "runner_observability" / "service.py"


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

    def test_acl_rules_separate_read_only_and_modify_access(self) -> None:
        self.assertIn('-Access "R"', self.script_text)
        self.assertIn('(OI)(CI)(M)', self.module_text)
        self.assertIn('(OI)(CI)(F)', self.module_text)
        self.assertIn("SYSTEM:(F)", self.module_text)
        self.assertIn("Administrators:(F)", self.module_text)


if __name__ == "__main__":
    unittest.main()
