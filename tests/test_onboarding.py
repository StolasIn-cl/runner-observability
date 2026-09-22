import tempfile
import unittest
from pathlib import Path

from runner_observability.onboarding import (
    OnboardingValidationError,
    inspect_install_root,
    safe_reason,
    upsert_hosts_mapping,
    validate_certificate_mode,
    validate_monitor_ip,
)


class InstallRootInspectionTests(unittest.TestCase):
    def test_missing_root_is_new(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"

            self.assertEqual(inspect_install_root(missing).state, "new")

    def test_current_release_pointer_is_existing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "current-release.txt").write_text("2026.09.22\n", encoding="utf-8")

            inspection = inspect_install_root(root)

            self.assertEqual(inspection.state, "existing")
            self.assertEqual(inspection.revision, "2026.09.22")

    def test_non_empty_root_without_pointer_requires_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unexpected.txt").write_text("data", encoding="utf-8")

            self.assertEqual(inspect_install_root(root).state, "inspect-before-use")


class ValidationTests(unittest.TestCase):
    def test_rejects_monitor_placeholder(self):
        with self.assertRaises(OnboardingValidationError):
            validate_monitor_ip("<monitor-host>")

    def test_accepts_confirmed_unicast_ipv4(self):
        self.assertEqual(validate_monitor_ip("192.168.24.10"), "192.168.24.10")

    def test_rejects_non_unicast_ipv4_addresses(self):
        for value in ("127.0.0.1", "0.0.0.0", "255.255.255.255", "224.0.0.1"):
            with self.subTest(value=value):
                with self.assertRaises(OnboardingValidationError):
                    validate_monitor_ip(value)

    def test_certificate_modes_require_the_right_files(self):
        validate_certificate_mode(
            "public-ca", cert_present=True, key_present=True, allow_dev_self_signed=False
        )
        validate_certificate_mode(
            "private-ca", cert_present=True, key_present=True, allow_dev_self_signed=False
        )

        with self.assertRaises(OnboardingValidationError):
            validate_certificate_mode(
                "private-ca", cert_present=True, key_present=False, allow_dev_self_signed=False
            )

    def test_self_signed_requires_explicit_development_permission(self):
        with self.assertRaises(OnboardingValidationError):
            validate_certificate_mode(
                "self-signed", cert_present=True, key_present=True, allow_dev_self_signed=False
            )

        validate_certificate_mode(
            "self-signed", cert_present=True, key_present=True, allow_dev_self_signed=True
        )

    def test_safe_reason_returns_bounded_reason_code(self):
        self.assertEqual(safe_reason(OnboardingValidationError("invalid_monitor_ip")), "invalid_monitor_ip")
        self.assertEqual(safe_reason("invalid_monitor_ip"), "invalid_monitor_ip")
        self.assertLessEqual(len(safe_reason("x" * 500)), 96)

    def test_safe_reason_collapses_untrusted_strings_to_unknown(self):
        for value in (
            r"C:\runner-observability-secrets\monitor-token.txt",
            "Bearer super-secret-token",
            "raw exception: connection failed at C:/private/source.py:42",
        ):
            with self.subTest(value=value):
                reason = safe_reason(value)
                self.assertEqual(reason, "unknown_error")
                self.assertNotIn("token", reason)
                self.assertNotIn("runner-observability", reason)


class HostsMappingTests(unittest.TestCase):
    def test_adds_missing_hostname_mapping(self):
        update = upsert_hosts_mapping(
            "127.0.0.1 localhost\n",
            hostname="monitor-test.local",
            monitor_ip="192.168.24.10",
        )

        self.assertTrue(update.changed)
        self.assertIn("192.168.24.10\tmonitor-test.local\n", update.contents)

    def test_matching_hostname_mapping_is_idempotent(self):
        contents = "192.168.24.10 monitor-test.local\n"

        update = upsert_hosts_mapping(
            contents,
            hostname="monitor-test.local",
            monitor_ip="192.168.24.10",
        )

        self.assertFalse(update.changed)
        self.assertEqual(update.contents, contents)

    def test_matching_hostname_mapping_is_case_insensitive(self):
        contents = "192.168.24.10 MONITOR-TEST.LOCAL\n"

        update = upsert_hosts_mapping(
            contents,
            hostname="monitor-test.local",
            monitor_ip="192.168.24.10",
        )

        self.assertFalse(update.changed)
        self.assertEqual(update.contents, contents)

    def test_conflicting_hostname_mapping_fails_closed(self):
        with self.assertRaises(OnboardingValidationError):
            upsert_hosts_mapping(
                "192.168.24.11 monitor-test.local\n",
                hostname="monitor-test.local",
                monitor_ip="192.168.24.10",
            )

    def test_explicit_replacement_changes_only_the_exact_hostname_line(self):
        contents = "192.168.24.11 monitor-test.local\n192.168.24.11 monitor-test.local.example\n"

        update = upsert_hosts_mapping(
            contents,
            hostname="monitor-test.local",
            monitor_ip="192.168.24.10",
            replace_conflicting=True,
        )

        self.assertTrue(update.changed)
        self.assertIn("192.168.24.10 monitor-test.local\n", update.contents)
        self.assertIn("192.168.24.11 monitor-test.local.example\n", update.contents)


if __name__ == "__main__":
    unittest.main()
