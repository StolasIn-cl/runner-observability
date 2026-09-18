"""Tests for the redacted monitor credential-file boundary."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from runner_observability.credentials import CredentialFileError, read_token_file


class CredentialFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-credential-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_token_file_returns_only_the_trimmed_token(self) -> None:
        token_path = self.base / "token.txt"
        token_path.write_text("secret-value\n", encoding="utf-8")

        self.assertEqual(read_token_file(token_path), "secret-value")

    def test_missing_or_empty_token_file_has_a_stable_reason(self) -> None:
        with self.assertRaises(CredentialFileError) as missing:
            read_token_file(self.base / "missing.txt")
        self.assertEqual(missing.exception.reason, "auth_credential_file_missing")

        empty = self.base / "empty.txt"
        empty.write_text("\n", encoding="utf-8")
        with self.assertRaises(CredentialFileError) as blank:
            read_token_file(empty)
        self.assertEqual(blank.exception.reason, "auth_credential_invalid")

    def test_multiline_token_file_is_rejected_without_echoing_content_or_path(self) -> None:
        token_path = self.base / "secret-marker-token.txt"
        token_path.write_text("first-secret\nsecond-secret\n", encoding="utf-8")

        with self.assertRaises(CredentialFileError) as error:
            read_token_file(token_path)

        self.assertEqual(error.exception.reason, "auth_credential_invalid")
        self.assertNotIn("first-secret", repr(error.exception))
        self.assertNotIn(str(token_path), repr(error.exception))


if __name__ == "__main__":
    unittest.main()
