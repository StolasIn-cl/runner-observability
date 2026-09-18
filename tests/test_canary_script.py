"""Contract tests for the operator-facing Runner canary script."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "Invoke-RunnerCanary.ps1"
RUNBOOK = ROOT / "docs" / "runbook.md"


class CanaryScriptContractTests(unittest.TestCase):
    def test_script_exists(self) -> None:
        self.assertTrue(SCRIPT.is_file(), "the Runner canary script is missing")

    def test_script_has_the_approved_modes_and_https_default(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for mode in ("Smoke", "OfflineRecovery", "Auth", "NetworkFailure"):
            self.assertIn(mode, source)
        self.assertIn("AllowInsecureHttp", source)
        self.assertIn("https", source.lower())
        self.assertIn("ValidateSet", source)

    def test_script_reads_secret_and_persists_monotonic_event_identity(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        for term in ("TokenPath", "StatePath", "producer_epoch", "producer_sequence"):
            self.assertIn(term, source)
        self.assertIn("LOCALAPPDATA", source)
        self.assertNotIn("Write-Host $Token", source)
        self.assertNotIn("Write-Output $Token", source)

    def test_script_has_the_offline_wait_and_recovery_assertion(self) -> None:
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("OfflineWaitSeconds", source)
        self.assertIn("heartbeat_timeout", source)
        self.assertIn('"online"', source)
        self.assertIn('"offline"', source)

    def test_runbook_documents_pull_and_run_flow(self) -> None:
        source = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("Invoke-RunnerCanary.ps1", source)
        self.assertIn("OfflineRecovery", source)
        self.assertIn("AllowInsecureHttp", source)
        self.assertIn("issue #7", source)


if __name__ == "__main__":
    unittest.main()
