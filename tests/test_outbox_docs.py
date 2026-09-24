"""Runbook contract tests for durable telemetry outbox operation."""

from pathlib import Path
import unittest


RUNBOOK = Path(__file__).resolve().parents[1] / "docs" / "runbook.md"


class OutboxRunbookTests(unittest.TestCase):
    def test_runbook_documents_redacted_outbox_operation_and_replay(self) -> None:
        source = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("## Runner job telemetry outbox", source)
        section = source.split("## Runner job telemetry outbox", 1)[1]

        for term in (
            "--outbox-dir",
            "flush",
            "--token-file",
            "pending",
            "dead-letter",
            "1,000",
            "32 MiB",
            "secrets root",
            "token",
            "payload",
            "HITL",
        ):
            with self.subTest(term=term):
                self.assertIn(term, section)

        self.assertNotIn("--token <", section)
        self.assertIn("Get-ChildItem", section)
        self.assertIn("ConvertFrom-Json", section)


if __name__ == "__main__":
    unittest.main()
