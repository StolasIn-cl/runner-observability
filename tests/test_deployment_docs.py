"""Local deployment/rollback CONTRACT tests (issue #4 PERS-04 gap, not issue #6 HITL).

Everything here proves the *contract* -- pinned revision handling, preflight
diagnostics, atomic switch, smoke-test-triggered rollback, and bounded
retry/CLI behavior -- against fake fixture filesystem trees and
injected/mocked probes. Nothing in this file ever opens a real socket,
touches a real certificate store, a real Windows Service, or a real firewall
API. `docs/runbook.md` and `docs/canary-evidence-template.md` are checked
only for document *shape* (required sections/keywords present, no secret or
absolute-path-looking content, explicit issue #6 handoff language) -- never
for whether real deployment happened, which no automated test may assert.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import tempfile
import unittest

from runner_observability import deploy


REPO_ROOT = Path(__file__).resolve().parent.parent


# ---------------------------------------------------------------------------
# Pinned revision handling
# ---------------------------------------------------------------------------


class RevisionValidationTests(unittest.TestCase):
    def test_a_simple_revision_identifier_is_accepted(self) -> None:
        self.assertEqual(deploy.validate_revision("1.2.3"), "1.2.3")
        self.assertEqual(deploy.validate_revision("a1b2c3d4"), "a1b2c3d4")

    def test_empty_revision_is_rejected(self) -> None:
        with self.assertRaises(deploy.InvalidRevisionError):
            deploy.validate_revision("")

    def test_path_traversal_revision_is_rejected(self) -> None:
        for bad in ("../escape", "..\\escape", "a/../b", "a\\..\\b"):
            with self.subTest(bad=bad):
                with self.assertRaises(deploy.InvalidRevisionError):
                    deploy.validate_revision(bad)

    def test_revision_with_path_separators_is_rejected(self) -> None:
        for bad in ("a/b", "a\\b", "C:\\Users\\x"):
            with self.subTest(bad=bad):
                with self.assertRaises(deploy.InvalidRevisionError):
                    deploy.validate_revision(bad)

    def test_floating_tag_like_latest_is_still_just_a_string_but_traversal_chars_are_the_only_thing_rejected(self) -> None:
        # The contract does not know which strings are "floating" tags in a
        # real registry (that is an operator/process discipline documented
        # in the runbook) -- it only guarantees the identifier is a safe,
        # non-empty, path-traversal-free token.
        self.assertEqual(deploy.validate_revision("latest"), "latest")

    def test_non_string_revision_is_rejected(self) -> None:
        with self.assertRaises(deploy.InvalidRevisionError):
            deploy.validate_revision(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Preflight checks -- each must produce an actionable, stable diagnostic
# ---------------------------------------------------------------------------


class PythonVersionCheckTests(unittest.TestCase):
    def test_a_supported_version_passes(self) -> None:
        result = deploy.check_python_version(actual=(3, 11), minimum=(3, 11))
        self.assertTrue(result.passed)
        self.assertEqual(result.reason, "")

    def test_a_newer_supported_version_passes(self) -> None:
        result = deploy.check_python_version(actual=(3, 12), minimum=(3, 11))
        self.assertTrue(result.passed)

    def test_an_unsupported_older_version_fails_with_a_stable_reason(self) -> None:
        result = deploy.check_python_version(actual=(3, 9), minimum=(3, 11))
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_UNSUPPORTED_PYTHON_VERSION)


class TlsCertificateCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_a_present_non_empty_cert_file_passes(self) -> None:
        cert = self.base / "cert.pem"
        cert.write_text("fake-cert-bytes-not-a-real-certificate", encoding="utf-8")
        result = deploy.check_tls_certificate_file(cert)
        self.assertTrue(result.passed)

    def test_a_missing_cert_file_fails_with_a_stable_reason(self) -> None:
        result = deploy.check_tls_certificate_file(self.base / "does-not-exist.pem")
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_TLS_CERT_FILE_MISSING)

    def test_no_cert_path_configured_fails_with_a_stable_reason(self) -> None:
        result = deploy.check_tls_certificate_file(None)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_TLS_CERT_FILE_MISSING)

    def test_an_empty_cert_file_fails(self) -> None:
        cert = self.base / "empty.pem"
        cert.write_text("", encoding="utf-8")
        result = deploy.check_tls_certificate_file(cert)
        self.assertFalse(result.passed)

    def test_the_check_never_reads_or_returns_cert_file_contents(self) -> None:
        cert = self.base / "cert.pem"
        secret_looking_content = "-----BEGIN PRIVATE KEY-----\nsuper-secret-material\n"
        cert.write_text(secret_looking_content, encoding="utf-8")
        result = deploy.check_tls_certificate_file(cert)
        self.assertNotIn("super-secret-material", repr(result))


class AuthCredentialCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_a_present_non_empty_token_file_passes(self) -> None:
        token_file = self.base / "token.txt"
        token_file.write_text("gha_fake_token_value_not_real", encoding="utf-8")
        result = deploy.check_auth_credential_file(token_file)
        self.assertTrue(result.passed)

    def test_a_missing_token_file_fails_with_a_stable_reason(self) -> None:
        result = deploy.check_auth_credential_file(self.base / "missing-token.txt")
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_AUTH_CREDENTIAL_MISSING)

    def test_the_check_never_reads_or_returns_the_token_value(self) -> None:
        token_file = self.base / "token.txt"
        secret_token = "Bearer super-secret-token-value-12345"
        token_file.write_text(secret_token, encoding="utf-8")
        result = deploy.check_auth_credential_file(token_file)
        self.assertNotIn("super-secret-token-value-12345", repr(result))
        self.assertNotIn(secret_token, repr(result))


class FirewallCheckTests(unittest.TestCase):
    def test_an_unconfigured_probe_fails_closed_with_a_stable_reason(self) -> None:
        result = deploy.check_firewall_port(None)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_FIREWALL_CHECK_NOT_CONFIGURED)

    def test_a_passing_probe_passes(self) -> None:
        result = deploy.check_firewall_port(lambda: True)
        self.assertTrue(result.passed)

    def test_a_failing_probe_fails_with_a_stable_reason(self) -> None:
        result = deploy.check_firewall_port(lambda: False)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_FIREWALL_PORT_BLOCKED)

    def test_a_probe_that_raises_fails_closed_rather_than_crashing(self) -> None:
        def _boom() -> bool:
            raise OSError("simulated firewall probe failure")

        result = deploy.check_firewall_port(_boom)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_FIREWALL_PORT_BLOCKED)
        self.assertNotIn("simulated firewall probe failure", repr(result))


class HostReachabilityCheckTests(unittest.TestCase):
    def test_an_unconfigured_probe_fails_closed_with_a_stable_reason_and_no_retries(self) -> None:
        result = deploy.check_host_reachable(None, max_attempts=3)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_HOST_CHECK_NOT_CONFIGURED)

    def test_a_probe_that_succeeds_on_the_first_attempt_passes_without_extra_calls(self) -> None:
        calls: list[int] = []

        def probe() -> bool:
            calls.append(1)
            return True

        result = deploy.check_host_reachable(probe, max_attempts=3)
        self.assertTrue(result.passed)
        self.assertEqual(len(calls), 1)

    def test_a_probe_that_succeeds_after_transient_failures_passes_within_the_bound(self) -> None:
        calls: list[int] = []

        def probe() -> bool:
            calls.append(1)
            return len(calls) >= 3

        result = deploy.check_host_reachable(probe, max_attempts=3, sleeper=lambda _seconds: None)
        self.assertTrue(result.passed)
        self.assertEqual(len(calls), 3)

    def test_a_probe_that_never_succeeds_stops_after_exactly_max_attempts_never_retries_forever(self) -> None:
        calls: list[int] = []

        def probe() -> bool:
            calls.append(1)
            return False

        result = deploy.check_host_reachable(probe, max_attempts=3, sleeper=lambda _seconds: None)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_HOST_UNREACHABLE)
        self.assertEqual(len(calls), 3)

    def test_a_probe_that_always_raises_is_bounded_and_fails_closed(self) -> None:
        calls: list[int] = []

        def probe() -> bool:
            calls.append(1)
            raise TimeoutError("simulated unreachable host")

        result = deploy.check_host_reachable(probe, max_attempts=3, sleeper=lambda _seconds: None)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_HOST_UNREACHABLE)
        self.assertEqual(len(calls), 3)
        self.assertNotIn("simulated unreachable host", repr(result))


class RunPreflightAggregationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)
        self.cert = self.base / "cert.pem"
        self.cert.write_text("fake-cert", encoding="utf-8")
        self.token = self.base / "token.txt"
        self.token.write_text("fake-token", encoding="utf-8")

    def test_all_checks_passing_yields_a_passing_report(self) -> None:
        report = deploy.run_preflight(
            python_version=(3, 11),
            tls_cert_path=self.cert,
            auth_token_path=self.token,
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
        )
        self.assertTrue(report.passed)
        self.assertEqual(report.failure_reasons, ())
        self.assertEqual(len(report.checks), 5)

    def test_one_failing_check_fails_the_whole_report_with_its_reason(self) -> None:
        report = deploy.run_preflight(
            python_version=(3, 9),
            tls_cert_path=self.cert,
            auth_token_path=self.token,
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
        )
        self.assertFalse(report.passed)
        self.assertIn(deploy.REASON_UNSUPPORTED_PYTHON_VERSION, report.failure_reasons)

    def test_every_configured_failure_reason_is_collected_not_just_the_first(self) -> None:
        report = deploy.run_preflight(
            python_version=(3, 9),
            tls_cert_path=None,
            auth_token_path=None,
            firewall_probe=None,
            host_reachable_probe=None,
        )
        self.assertFalse(report.passed)
        self.assertEqual(len(report.failure_reasons), 5)

    def test_report_never_contains_the_configured_absolute_paths(self) -> None:
        report = deploy.run_preflight(
            python_version=(3, 11),
            tls_cert_path=self.cert,
            auth_token_path=self.token,
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
        )
        serialized = repr(report)
        self.assertNotIn(str(self.cert), serialized)
        self.assertNotIn(str(self.token), serialized)
        self.assertNotIn(str(self.base), serialized)


# ---------------------------------------------------------------------------
# Release layout / atomic switch
# ---------------------------------------------------------------------------


class ReleaseLayoutTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.install_root = Path(self._tmp.name) / "install"
        self.layout = deploy.ReleaseLayout(self.install_root)
        self.source_a = Path(self._tmp.name) / "source-a"
        self.source_a.mkdir()
        (self.source_a / "marker.txt").write_text("release-a", encoding="utf-8")
        self.source_b = Path(self._tmp.name) / "source-b"
        self.source_b.mkdir()
        (self.source_b / "marker.txt").write_text("release-b", encoding="utf-8")

    def test_current_revision_is_none_before_any_activation(self) -> None:
        self.assertIsNone(self.layout.current_revision())

    def test_stage_then_activate_makes_current_revision_readable(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_activating_an_unstaged_revision_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.layout.activate("9.9.9")

    def test_switching_between_two_staged_revisions_updates_current_revision_atomically(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.stage_release("2.0.0", self.source_b)
        self.layout.activate("1.0.0")
        self.assertEqual(self.layout.current_revision(), "1.0.0")
        self.layout.activate("2.0.0")
        self.assertEqual(self.layout.current_revision(), "2.0.0")

    def test_a_previously_activated_release_directory_is_retained_after_switching_away(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        self.layout.stage_release("2.0.0", self.source_b)
        self.layout.activate("2.0.0")
        self.assertTrue(self.layout.release_path("1.0.0").exists())
        self.assertTrue((self.layout.release_path("1.0.0") / "marker.txt").exists())

    def test_a_failed_atomic_switch_never_leaves_a_partially_written_pointer(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")

        self.layout.stage_release("2.0.0", self.source_b)
        original_replace = deploy.os.replace

        def _boom(_src: object, _dst: object) -> None:
            raise OSError("simulated crash during atomic switch")

        deploy.os.replace = _boom  # type: ignore[assignment]
        try:
            with self.assertRaises(OSError):
                self.layout.activate("2.0.0")
        finally:
            deploy.os.replace = original_replace  # type: ignore[assignment]

        # The pointer must still read the last successfully activated
        # revision -- never half-written, never silently switched.
        self.assertEqual(self.layout.current_revision(), "1.0.0")
        leftover_temp_files = [p for p in self.install_root.glob(".current-release-*") if p.is_file()]
        self.assertEqual(leftover_temp_files, [])

    def test_deactivate_clears_current_revision(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        self.layout.deactivate()
        self.assertIsNone(self.layout.current_revision())

    def test_deactivate_when_nothing_is_active_is_a_safe_no_op(self) -> None:
        self.layout.deactivate()
        self.assertIsNone(self.layout.current_revision())

    def test_a_failed_restaging_of_the_active_revision_never_deletes_its_existing_content(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")

        missing_source = Path(self._tmp.name) / "does-not-exist"
        with self.assertRaises(OSError):
            self.layout.stage_release("1.0.0", missing_source)

        # The previously staged (and currently active) release must be
        # completely untouched by the failed re-staging attempt.
        self.assertTrue(self.layout.release_path("1.0.0").exists())
        self.assertEqual(
            (self.layout.release_path("1.0.0") / "marker.txt").read_text(encoding="utf-8"),
            "release-a",
        )
        self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_staging_never_leaves_a_leftover_staging_directory_behind(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        leftovers = list(self.layout.releases_dir.glob(".*.staging-*"))
        self.assertEqual(leftovers, [])


# ---------------------------------------------------------------------------
# Deploy orchestration: preflight gate, smoke test, rollback
# ---------------------------------------------------------------------------


class DeployReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.install_root = Path(self._tmp.name) / "install"
        self.layout = deploy.ReleaseLayout(self.install_root)
        self.source_a = Path(self._tmp.name) / "source-a"
        self.source_a.mkdir()
        (self.source_a / "marker.txt").write_text("release-a", encoding="utf-8")
        self.source_b = Path(self._tmp.name) / "source-b"
        self.source_b.mkdir()
        (self.source_b / "marker.txt").write_text("release-b", encoding="utf-8")

    def _passing_preflight(self) -> "deploy.PreflightReport":
        return deploy.PreflightReport(checks=(deploy.CheckResult("stub", True, ""),))

    def _failing_preflight(self) -> "deploy.PreflightReport":
        return deploy.PreflightReport(checks=(deploy.CheckResult("stub", False, "stub_failed"),))

    def test_a_preflight_failure_blocks_the_deploy_and_leaves_no_active_release(self) -> None:
        result = deploy.deploy_release(
            self.layout, "1.0.0", self.source_a, preflight_report=self._failing_preflight()
        )
        self.assertFalse(result.success)
        self.assertFalse(result.rolled_back)
        self.assertEqual(result.failure_reason, "stub_failed")
        self.assertIsNone(self.layout.current_revision())

    def test_a_preflight_failure_on_an_upgrade_leaves_the_previous_version_active(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")

        result = deploy.deploy_release(
            self.layout, "2.0.0", self.source_b, preflight_report=self._failing_preflight()
        )
        self.assertFalse(result.success)
        self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_a_clean_deploy_with_passing_checks_activates_the_new_revision(self) -> None:
        result = deploy.deploy_release(
            self.layout,
            "1.0.0",
            self.source_a,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", lambda: True),),
        )
        self.assertTrue(result.success)
        self.assertFalse(result.rolled_back)
        self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_a_first_install_with_a_failing_smoke_test_rolls_back_to_no_active_release(self) -> None:
        result = deploy.deploy_release(
            self.layout,
            "1.0.0",
            self.source_a,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", lambda: False),),
        )
        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertIsNone(result.restored_revision)
        self.assertEqual(result.failure_reason, "smoke_test_failed")
        self.assertIsNone(self.layout.current_revision())

    def test_an_upgrade_with_a_failing_smoke_test_rolls_back_and_retains_the_previous_version(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", lambda: False),),
        )
        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertEqual(result.restored_revision, "1.0.0")
        self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_a_service_start_failure_also_triggers_rollback_before_smoke_test_runs(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        smoke_test_calls: list[int] = []

        def smoke_test() -> bool:
            smoke_test_calls.append(1)
            return True

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(
                ("service_start", lambda: False),
                ("smoke_test", smoke_test),
            ),
        )
        self.assertFalse(result.success)
        self.assertEqual(result.failure_reason, "service_start_failed")
        self.assertEqual(self.layout.current_revision(), "1.0.0")
        self.assertEqual(smoke_test_calls, [])  # short-circuits, does not run later checks

    def test_rollback_is_repeatable_across_consecutive_failed_upgrade_attempts(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")

        for _ in range(3):
            result = deploy.deploy_release(
                self.layout,
                "2.0.0",
                self.source_b,
                preflight_report=self._passing_preflight(),
                post_activation_checks=(("smoke_test", lambda: False),),
            )
            self.assertFalse(result.success)
            self.assertTrue(result.rolled_back)
            self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_a_pruned_previous_release_directory_never_leaves_the_broken_revision_active(self) -> None:
        # Reproduces the reviewer's fix-round-1 finding: the runbook
        # explicitly documents pruning old release directories as an
        # allowed manual operator decision. If the operator prunes the
        # *previous* (rollback target) revision's directory and a later
        # update then fails its smoke test, deploy_release must not raise
        # FileNotFoundError out of layout.activate() and must never leave
        # the just-activated, known-broken revision active.
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        shutil.rmtree(self.layout.release_path("1.0.0"))
        self.assertFalse(self.layout.release_exists("1.0.0"))

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", lambda: False),),
        )
        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertIsNone(result.restored_revision)
        self.assertEqual(result.failure_reason, deploy.REASON_ROLLBACK_TARGET_MISSING)
        # The broken 2.0.0 must never be left active.
        self.assertNotEqual(self.layout.current_revision(), "2.0.0")
        self.assertIsNone(self.layout.current_revision())

    def test_a_pruned_previous_release_directory_is_repeatable_across_attempts(self) -> None:
        # The first failed attempt reports the distinct
        # REASON_ROLLBACK_TARGET_MISSING (it still had a recorded previous
        # revision whose directory turned out to be gone) and deactivates.
        # Every attempt after that behaves like a fresh "nothing active"
        # deploy (there is no longer any previous revision on record at
        # all), reporting the ordinary check-failed reason instead -- the
        # safety property that matters is that the broken revision is
        # *never* left active, on any attempt.
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        shutil.rmtree(self.layout.release_path("1.0.0"))

        for attempt in range(3):
            result = deploy.deploy_release(
                self.layout,
                "2.0.0",
                self.source_b,
                preflight_report=self._passing_preflight(),
                post_activation_checks=(("smoke_test", lambda: False),),
            )
            self.assertFalse(result.success)
            self.assertTrue(result.rolled_back)
            self.assertIsNone(result.restored_revision)
            self.assertNotEqual(self.layout.current_revision(), "2.0.0")
            self.assertIsNone(self.layout.current_revision())
            if attempt == 0:
                self.assertEqual(result.failure_reason, deploy.REASON_ROLLBACK_TARGET_MISSING)
            else:
                self.assertEqual(result.failure_reason, "smoke_test_failed")

    def test_a_post_activation_check_that_raises_is_treated_as_a_failure_not_a_crash(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")

        def _boom() -> bool:
            raise RuntimeError("simulated smoke test crash with a secret C:\\Users\\real\\path")

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", _boom),),
        )
        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertEqual(self.layout.current_revision(), "1.0.0")
        self.assertNotIn("C:\\Users\\real\\path", repr(result))

    def test_deploy_result_never_contains_the_source_or_install_paths(self) -> None:
        result = deploy.deploy_release(
            self.layout,
            "1.0.0",
            self.source_a,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", lambda: True),),
        )
        serialized = repr(result)
        self.assertNotIn(str(self.source_a), serialized)
        self.assertNotIn(str(self.install_root), serialized)


# ---------------------------------------------------------------------------
# Default (real, subprocess-based) smoke test -- exercised directly, not via
# an injected fake, because every other test in this file injects a fake
# smoke test and so never actually runs this real code path.
# ---------------------------------------------------------------------------


class DefaultSmokeTestTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_a_release_with_a_real_working_package_passes_the_real_smoke_test(self) -> None:
        release_path = self.base / "release"
        shutil.copytree(REPO_ROOT / "src", release_path / "src")
        self.assertTrue(deploy.default_smoke_test(release_path, timeout_seconds=30.0))

    def test_a_release_missing_its_package_entirely_fails_the_real_smoke_test(self) -> None:
        release_path = self.base / "empty-release"
        release_path.mkdir()
        self.assertFalse(deploy.default_smoke_test(release_path, timeout_seconds=30.0))

    def test_a_release_whose_entrypoint_raises_on_import_fails_rather_than_crashing_the_caller(self) -> None:
        package_dir = self.base / "broken-release" / "src" / "runner_observability"
        package_dir.mkdir(parents=True)
        (package_dir / "__init__.py").write_text("", encoding="utf-8")
        (package_dir / "__main__.py").write_text(
            "raise RuntimeError('simulated broken entrypoint')\n", encoding="utf-8"
        )
        release_path = self.base / "broken-release"
        # Must return a plain False, not raise/propagate the subprocess's
        # own failure -- deploy_release relies on this never crashing the
        # caller.
        self.assertFalse(deploy.default_smoke_test(release_path, timeout_seconds=30.0))

    def test_a_zero_or_negative_timeout_fails_closed_rather_than_hanging(self) -> None:
        release_path = self.base / "release"
        shutil.copytree(REPO_ROOT / "src", release_path / "src")
        # An unreasonably tiny timeout should be treated as a bounded
        # failure (subprocess.TimeoutExpired, caught internally), never an
        # unbounded wait.
        self.assertFalse(deploy.default_smoke_test(release_path, timeout_seconds=0.001))


# ---------------------------------------------------------------------------
# CLI entry point -- bounded behavior, never leaks secrets/paths
# ---------------------------------------------------------------------------


class DeployCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="runner-observability-deploy-test-")
        self.addCleanup(self._tmp.cleanup)
        self.base = Path(self._tmp.name)

    def test_preflight_subcommand_reports_pass_without_any_probes_configured_is_fail_closed(self) -> None:
        exit_code = deploy.main(["preflight"])
        self.assertNotEqual(exit_code, 0)

    def test_preflight_subcommand_prints_no_configured_absolute_paths(self) -> None:
        cert = self.base / "cert.pem"
        cert.write_text("fake-cert", encoding="utf-8")
        printed: list[str] = []
        exit_code = deploy.main(["preflight", "--tls-cert-path", str(cert)], printer=printed.append)
        combined = "\n".join(printed)
        self.assertNotIn(str(cert), combined)
        self.assertNotIn(str(self.base), combined)
        self.assertIsInstance(exit_code, int)

    def test_preflight_result_flags_let_an_operator_pass_through_a_precomputed_outcome(self) -> None:
        printed: list[str] = []
        exit_code = deploy.main(
            ["preflight", "--firewall-result", "pass", "--host-reachable-result", "pass"],
            printer=printed.append,
        )
        combined = "\n".join(printed)
        self.assertIn("firewall: PASS", combined)
        self.assertIn("host_reachable: PASS", combined)
        # Still fails overall: cert/token were never configured in this call.
        self.assertNotEqual(exit_code, 0)

    def test_preflight_result_flags_never_cause_a_real_network_probe_to_run(self) -> None:
        # A "fail" result flag must be honored as a plain pass-through value,
        # not trigger any actual connection attempt.
        printed: list[str] = []
        deploy.main(["preflight", "--host-reachable-result", "fail"], printer=printed.append)
        combined = "\n".join(printed)
        self.assertIn(deploy.REASON_HOST_UNREACHABLE, combined)

    def test_install_subcommand_invokes_an_injected_smoke_test_with_the_release_path(self) -> None:
        source = self.base / "source"
        source.mkdir()
        (source / "marker.txt").write_text("release", encoding="utf-8")
        install_root = self.base / "install"
        cert = self.base / "cert.pem"
        cert.write_text("fake-cert", encoding="utf-8")
        token = self.base / "token.txt"
        token.write_text("fake-token", encoding="utf-8")

        received_paths: list[Path] = []

        def fake_smoke_test(release_path: Path) -> bool:
            received_paths.append(release_path)
            return True

        exit_code = deploy.main(
            [
                "install",
                "--revision",
                "1.0.0",
                "--source",
                str(source),
                "--install-root",
                str(install_root),
                "--tls-cert-path",
                str(cert),
                "--auth-token-path",
                str(token),
            ],
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
            smoke_test=fake_smoke_test,
            printer=lambda _line: None,
        )
        self.assertEqual(exit_code, 0)
        self.assertEqual(len(received_paths), 1)
        self.assertEqual(received_paths[0], install_root / "releases" / "1.0.0")

    def test_install_subcommand_rolls_back_when_the_injected_smoke_test_fails(self) -> None:
        source = self.base / "source"
        source.mkdir()
        (source / "marker.txt").write_text("release", encoding="utf-8")
        install_root = self.base / "install"

        exit_code = deploy.main(
            [
                "install",
                "--revision",
                "1.0.0",
                "--source",
                str(source),
                "--install-root",
                str(install_root),
            ],
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
            smoke_test=lambda _release_path: False,
            printer=lambda _line: None,
        )
        self.assertNotEqual(exit_code, 0)
        self.assertFalse((install_root / "current-release.txt").exists())

    def test_install_subcommand_with_a_nonexistent_source_reports_a_stable_reason_not_a_traceback(self) -> None:
        # Reproduces the reviewer's fix-round-1 finding: a mistyped/missing
        # -Source must never let a raw Python traceback (with this
        # process's absolute paths) reach operator output.
        install_root = self.base / "install"
        missing_source = self.base / "does-not-exist-source"
        cert = self.base / "cert.pem"
        cert.write_text("fake-cert", encoding="utf-8")
        token = self.base / "token.txt"
        token.write_text("fake-token", encoding="utf-8")

        printed: list[str] = []
        exit_code = deploy.main(
            [
                "install",
                "--revision",
                "1.0.0",
                "--source",
                str(missing_source),
                "--install-root",
                str(install_root),
                "--tls-cert-path",
                str(cert),
                "--auth-token-path",
                str(token),
            ],
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
            printer=printed.append,
        )
        combined = "\n".join(printed)
        self.assertNotEqual(exit_code, 0)
        self.assertIn(deploy.REASON_SOURCE_UNAVAILABLE, combined)
        self.assertNotIn("Traceback", combined)
        self.assertNotIn(str(missing_source), combined)
        self.assertNotIn(str(self.base), combined)

    def test_update_subcommand_with_a_pruned_rollback_target_reports_the_reason_not_a_traceback(self) -> None:
        # End-to-end reproduction of the reviewer's fix-round-1 finding #2,
        # driven entirely through the public CLI entry point (main()),
        # exactly like the real PowerShell wrapper invokes it.
        source_1 = self.base / "source-1.0.0"
        source_1.mkdir()
        (source_1 / "marker.txt").write_text("release-a", encoding="utf-8")
        source_2 = self.base / "source-2.0.0"
        source_2.mkdir()
        (source_2 / "marker.txt").write_text("release-b", encoding="utf-8")
        install_root = self.base / "install"
        cert = self.base / "cert.pem"
        cert.write_text("fake-cert", encoding="utf-8")
        token = self.base / "token.txt"
        token.write_text("fake-token", encoding="utf-8")

        install_exit = deploy.main(
            [
                "install",
                "--revision",
                "1.0.0",
                "--source",
                str(source_1),
                "--install-root",
                str(install_root),
                "--tls-cert-path",
                str(cert),
                "--auth-token-path",
                str(token),
            ],
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
            smoke_test=lambda _release_path: True,
            printer=lambda _line: None,
        )
        self.assertEqual(install_exit, 0)

        # Operator prunes the previous (1.0.0) release directory -- the
        # runbook documents this as an allowed manual decision.
        shutil.rmtree(install_root / "releases" / "1.0.0")

        printed: list[str] = []
        update_exit = deploy.main(
            [
                "update",
                "--revision",
                "2.0.0",
                "--source",
                str(source_2),
                "--install-root",
                str(install_root),
                "--tls-cert-path",
                str(cert),
                "--auth-token-path",
                str(token),
            ],
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
            smoke_test=lambda _release_path: False,
            printer=printed.append,
        )
        combined = "\n".join(printed)
        self.assertNotEqual(update_exit, 0)
        self.assertIn(deploy.REASON_ROLLBACK_TARGET_MISSING, combined)
        self.assertNotIn("Traceback", combined)
        # The broken 2.0.0 must never be left active.
        pointer = install_root / "current-release.txt"
        if pointer.exists():
            self.assertNotEqual(pointer.read_text(encoding="utf-8").strip(), "2.0.0")

    def test_install_subcommand_is_bounded_and_never_retries_forever_on_a_permanently_failing_probe(self) -> None:
        source = self.base / "source"
        source.mkdir()
        (source / "marker.txt").write_text("release", encoding="utf-8")
        install_root = self.base / "install"

        calls: list[int] = []

        def always_unreachable() -> bool:
            calls.append(1)
            return False

        exit_code = deploy.main(
            [
                "install",
                "--revision",
                "1.0.0",
                "--source",
                str(source),
                "--install-root",
                str(install_root),
            ],
            host_reachable_probe=always_unreachable,
            max_host_attempts=3,
            printer=lambda _line: None,
        )
        self.assertNotEqual(exit_code, 0)
        self.assertEqual(len(calls), 3)


# ---------------------------------------------------------------------------
# Documentation shape -- runbook and evidence template
# ---------------------------------------------------------------------------


class RunbookShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (REPO_ROOT / "docs" / "runbook.md").read_text(encoding="utf-8")

    def test_runbook_covers_install_update_rollback_and_first_triage(self) -> None:
        lowered = self.text.lower()
        for required in ("install", "update", "rollback", "triage"):
            with self.subTest(required=required):
                self.assertIn(required, lowered)

    def test_runbook_names_every_preflight_diagnostic_category(self) -> None:
        lowered = self.text.lower()
        for category in ("certificate", "auth", "firewall", "unreachable", "unsupported", "version"):
            with self.subTest(category=category):
                self.assertIn(category, lowered)

    def test_runbook_explicitly_defers_real_deployment_to_issue_6(self) -> None:
        lowered = self.text.lower()
        self.assertIn("issue #6", lowered)
        for phrase in ("has not happened", "have not happened", "not been", "not happened", "not have happened"):
            if phrase in lowered:
                break
        else:
            self.fail("runbook must explicitly state real deployment has not happened as part of this task")

    def test_runbook_mentions_tls_firewall_and_windows_service_as_issue_6_responsibility(self) -> None:
        lowered = self.text.lower()
        for term in ("tls", "firewall", "windows service"):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_runbook_never_contains_a_bearer_token_looking_value(self) -> None:
        self.assertNotIn("Bearer ey", self.text)
        self.assertNotRegex(self.text, r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}")

    def test_runbook_references_the_actual_cli_entrypoint(self) -> None:
        self.assertIn("python -m runner_observability", self.text)

    def test_runbook_install_and_update_examples_show_all_four_required_preflight_flags(self) -> None:
        # Reproduces the reviewer's fix-round-1 finding: the documented
        # examples must actually be runnable as written, not silently fail
        # preflight because required flags were omitted.
        install_example_start = self.text.index("./scripts/Install-RunnerObservability.ps1")
        install_example = self.text[install_example_start : install_example_start + 700]
        update_example_start = self.text.index("./scripts/Update-RunnerObservability.ps1")
        update_example = self.text[update_example_start : update_example_start + 700]
        for example in (install_example, update_example):
            for required_flag in ("-TlsCertPath", "-AuthTokenPath", "-FirewallResult", "-HostReachableResult"):
                with self.subTest(example=example[:40], required_flag=required_flag):
                    self.assertIn(required_flag, example)

    def test_runbook_describes_firewall_and_host_checks_as_required_not_merely_expected(self) -> None:
        lowered = self.text.lower()
        self.assertIn("required", lowered)
        # The old wording that framed a hard preflight block as merely
        # tolerable must be gone.
        self.assertNotIn("expected on a bare local-simulation run", lowered)

    def test_runbook_marks_service_start_failed_as_reserved_not_currently_active(self) -> None:
        lowered = self.text.lower()
        self.assertIn("service_start_failed", lowered)
        service_start_index = lowered.index("service_start_failed")
        surrounding = lowered[service_start_index : service_start_index + 400]
        self.assertIn("reserved for issue #6", surrounding)

    def test_runbook_documents_the_rollback_target_missing_reason(self) -> None:
        self.assertIn("rollback_target_missing", self.text)


class CanaryEvidenceTemplateShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (REPO_ROOT / "docs" / "canary-evidence-template.md").read_text(encoding="utf-8")

    def test_template_still_marks_deployment_rows_as_document_shape_only(self) -> None:
        self.assertIn("document shape only", self.text.lower())

    def test_template_still_defers_the_production_ready_decision_to_issue_6(self) -> None:
        self.assertIn("Issue #6", self.text)


if __name__ == "__main__":
    unittest.main()
