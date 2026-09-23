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
import subprocess
import tempfile
import unittest

from runner_observability import deploy


REPO_ROOT = Path(__file__).resolve().parent.parent
TLS_FIXTURES = Path(__file__).parent / "fixtures" / "tls"
VALID_TLS_CERT = TLS_FIXTURES / "server-cert.pem"
VALID_TLS_KEY = TLS_FIXTURES / "server-key.pem"
MISMATCHED_TLS_KEY = TLS_FIXTURES / "other-key.pem"


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

    # -- Strengthened check (issue #7 PERS-07): when a key_path is also
    # supplied, this closes the honesty gap where a present-but-garbage or
    # non-matching cert file used to pass. It attempts a real
    # ssl.SSLContext().load_cert_chain() -- the exact call server.py's
    # create_server() makes -- without ever starting a server or opening a
    # socket. Omitting key_path (the default) must behave exactly as the
    # tests above already prove: presence-only, unchanged.

    def test_a_valid_matching_cert_and_key_pair_passes_the_strengthened_check(self) -> None:
        result = deploy.check_tls_certificate_file(VALID_TLS_CERT, VALID_TLS_KEY)
        self.assertTrue(result.passed)
        self.assertEqual(result.reason, "")

    def test_a_mismatched_key_fails_the_strengthened_check_with_a_stable_reason(self) -> None:
        result = deploy.check_tls_certificate_file(VALID_TLS_CERT, MISMATCHED_TLS_KEY)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_TLS_CERTIFICATE_INVALID)

    def test_malformed_cert_content_fails_the_strengthened_check_with_a_stable_reason(self) -> None:
        malformed = self.base / "malformed-cert.pem"
        malformed.write_text("this is not a certificate\n", encoding="utf-8")
        result = deploy.check_tls_certificate_file(malformed, VALID_TLS_KEY)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_TLS_CERTIFICATE_INVALID)

    def test_a_missing_key_file_fails_the_strengthened_check_with_a_stable_reason(self) -> None:
        # Reviewer fix-round-1 finding (Important #2): a missing/empty KEY
        # file must report tls_certificate_invalid, the same reason the
        # docstring above promises and the same reason server.py's
        # create_server() reports for this identical situation -- never the
        # cert-missing reason, which would point an operator at the wrong
        # file entirely.
        result = deploy.check_tls_certificate_file(VALID_TLS_CERT, self.base / "does-not-exist-key.pem")
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_TLS_CERTIFICATE_INVALID)

    def test_an_empty_key_file_also_fails_with_the_certificate_invalid_reason(self) -> None:
        empty_key = self.base / "empty-key.pem"
        empty_key.write_text("", encoding="utf-8")
        result = deploy.check_tls_certificate_file(VALID_TLS_CERT, empty_key)
        self.assertFalse(result.passed)
        self.assertEqual(result.reason, deploy.REASON_TLS_CERTIFICATE_INVALID)

    def test_the_strengthened_check_never_leaks_the_configured_paths_or_content(self) -> None:
        malformed = self.base / "malformed-cert.pem"
        secret_looking_content = "-----BEGIN PRIVATE KEY-----\nsuper-secret-material-marker\n"
        malformed.write_text(secret_looking_content, encoding="utf-8")
        result = deploy.check_tls_certificate_file(malformed, VALID_TLS_KEY)
        serialized = repr(result)
        self.assertNotIn("super-secret-material-marker", serialized)
        self.assertNotIn(str(malformed), serialized)
        self.assertNotIn(str(self.base), serialized)

    def test_omitting_key_path_keeps_the_original_presence_only_check_unchanged(self) -> None:
        # A cert file that would fail the strengthened check (it is not a
        # real loadable certificate) must still pass the original,
        # presence-only check when no key_path is supplied at all -- the
        # strengthening is strictly additive/opt-in, never a behavior
        # change for existing callers.
        not_a_real_cert = self.base / "not-a-real-cert.pem"
        not_a_real_cert.write_text("just needs to be present and non-empty", encoding="utf-8")
        result = deploy.check_tls_certificate_file(not_a_real_cert)
        self.assertTrue(result.passed)


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

    def test_run_preflight_accepts_an_optional_tls_key_path_and_strengthens_the_check(self) -> None:
        report = deploy.run_preflight(
            python_version=(3, 11),
            tls_cert_path=VALID_TLS_CERT,
            tls_key_path=MISMATCHED_TLS_KEY,
            auth_token_path=self.token,
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
        )
        self.assertFalse(report.passed)
        self.assertIn(deploy.REASON_TLS_CERTIFICATE_INVALID, report.failure_reasons)
        self.assertEqual(len(report.checks), 5)

    def test_run_preflight_without_tls_key_path_is_unaffected(self) -> None:
        report = deploy.run_preflight(
            python_version=(3, 11),
            tls_cert_path=self.cert,
            auth_token_path=self.token,
            firewall_probe=lambda: True,
            host_reachable_probe=lambda: True,
        )
        self.assertTrue(report.passed)

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

    class _FakeService:
        def __init__(self, calls: list[str], start_results: list[bool] | None = None, stop_result: bool = True) -> None:
            self.calls = calls
            self.start_results = list(start_results or [True])
            self.stop_result = stop_result

        def stop(self) -> bool:
            self.calls.append("stop")
            return self.stop_result

        def start(self) -> bool:
            self.calls.append("start")
            return self.start_results.pop(0) if self.start_results else True

        def status(self) -> str:
            return "running"

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

    def test_service_enabled_update_stops_before_activation_and_starts_after_smoke(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        calls: list[str] = []
        service = self._FakeService(calls)

        def smoke_test() -> bool:
            calls.append("smoke")
            return True

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", smoke_test),),
            service_lifecycle=service,
        )

        self.assertTrue(result.success)
        self.assertEqual(calls, ["stop", "smoke", "start"])
        self.assertEqual(self.layout.current_revision(), "2.0.0")

    def test_service_start_failure_restores_previous_release_and_restarts_old_service(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        calls: list[str] = []
        service = self._FakeService(calls, start_results=[False, True])

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            post_activation_checks=(("smoke_test", lambda: True),),
            service_lifecycle=service,
        )

        self.assertFalse(result.success)
        self.assertTrue(result.rolled_back)
        self.assertEqual(result.failure_reason, "service_start_failed")
        self.assertEqual(calls, ["stop", "start", "start"])
        self.assertEqual(self.layout.current_revision(), "1.0.0")

    def test_service_stop_failure_does_not_stage_or_switch_a_release(self) -> None:
        self.layout.stage_release("1.0.0", self.source_a)
        self.layout.activate("1.0.0")
        calls: list[str] = []
        service = self._FakeService(calls, stop_result=False)

        result = deploy.deploy_release(
            self.layout,
            "2.0.0",
            self.source_b,
            preflight_report=self._passing_preflight(),
            service_lifecycle=service,
        )

        self.assertFalse(result.success)
        self.assertFalse(result.rolled_back)
        self.assertEqual(result.failure_reason, "service_stop_failed")
        self.assertEqual(calls, ["stop"])
        self.assertEqual(self.layout.current_revision(), "1.0.0")

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


class WindowsScServiceLifecycleTests(unittest.TestCase):
    def test_stop_is_idempotent_for_an_already_stopped_service(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            calls.append(arguments)
            return subprocess.CompletedProcess(arguments, 0, stdout="STATE : 1  STOPPED", stderr="")

        lifecycle = deploy.WindowsScServiceLifecycle("RunnerObservabilityMonitor", runner)

        self.assertTrue(lifecycle.stop())
        self.assertEqual(calls, [("query", "RunnerObservabilityMonitor")])

    def test_start_runs_only_after_status_is_not_running(self) -> None:
        calls: list[tuple[str, ...]] = []

        def runner(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            calls.append(arguments)
            if arguments[0] == "query":
                return subprocess.CompletedProcess(arguments, 0, stdout="STATE : 1  STOPPED", stderr="")
            return subprocess.CompletedProcess(arguments, 0, stdout="", stderr="")

        lifecycle = deploy.WindowsScServiceLifecycle("RunnerObservabilityMonitor", runner)

        self.assertTrue(lifecycle.start())
        self.assertEqual(
            calls,
            [("query", "RunnerObservabilityMonitor"), ("start", "RunnerObservabilityMonitor")],
        )

    def test_command_failure_is_redacted_as_false(self) -> None:
        def runner(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(arguments, 1, stdout="secret path", stderr="raw failure")

        lifecycle = deploy.WindowsScServiceLifecycle("RunnerObservabilityMonitor", runner)

        self.assertFalse(lifecycle.start())


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

    def test_preflight_subcommand_accepts_tls_key_path_and_strengthens_the_check(self) -> None:
        printed: list[str] = []
        exit_code = deploy.main(
            [
                "preflight",
                "--tls-cert-path",
                str(VALID_TLS_CERT),
                "--tls-key-path",
                str(MISMATCHED_TLS_KEY),
            ],
            printer=printed.append,
        )
        combined = "\n".join(printed)
        self.assertNotEqual(exit_code, 0)
        self.assertIn(deploy.REASON_TLS_CERTIFICATE_INVALID, combined)
        self.assertNotIn(str(VALID_TLS_CERT), combined)
        self.assertNotIn(str(MISMATCHED_TLS_KEY), combined)

    def test_preflight_subcommand_with_a_valid_matching_pair_passes_the_tls_check(self) -> None:
        printed: list[str] = []
        deploy.main(
            [
                "preflight",
                "--tls-cert-path",
                str(VALID_TLS_CERT),
                "--tls-key-path",
                str(VALID_TLS_KEY),
                "--firewall-result",
                "pass",
                "--host-reachable-result",
                "pass",
            ],
            printer=printed.append,
        )
        combined = "\n".join(printed)
        self.assertIn("tls_certificate: PASS", combined)

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

    def test_runbook_documents_service_start_failure_and_hitl_boundary(self) -> None:
        lowered = self.text.lower()
        self.assertIn("service_start_failed", lowered)
        service_start_index = lowered.index("service_start_failed")
        surrounding = lowered[service_start_index : service_start_index + 400]
        self.assertIn("previous release", surrounding)
        self.assertIn("#6", surrounding)

    def test_runbook_documents_the_rollback_target_missing_reason(self) -> None:
        self.assertIn("rollback_target_missing", self.text)

    def test_runbook_documents_the_strengthened_tls_check_and_its_new_flag(self) -> None:
        # Issue #7 PERS-07: the runbook must no longer let a reader believe
        # "cert file present" already means "this will actually be used for
        # encryption" -- it must name the optional -TlsKeyPath flag and
        # explain that supplying it makes the check load a real SSLContext.
        self.assertIn("-TlsKeyPath", self.text)
        lowered = self.text.lower()
        self.assertIn("sslcontext", lowered)
        self.assertIn(deploy.REASON_TLS_CERTIFICATE_INVALID, self.text)

    def test_runbook_documents_the_serve_command_tls_flags(self) -> None:
        # Issue #7 PERS-07: the serve example must show how to actually turn
        # on HTTPS, not just how to run the preflight file-presence check.
        self.assertIn("--tls-cert", self.text)
        self.assertIn("--tls-key", self.text)

    def test_runbook_documents_token_file_service_startup_and_lifecycle(self) -> None:
        lowered = self.text.lower()
        for term in (
            "--token-file",
            "install-runnerobservabilityservice.ps1",
            "sc.exe",
            "icacls",
            "new-netfirewallrule",
            "restart",
        ):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_runbook_keeps_live_acceptance_in_issue_6(self) -> None:
        lowered = self.text.lower()
        self.assertIn("issue #6", lowered)
        self.assertIn("real", lowered)

    def test_runbook_documents_monitor_ip_confirmation_before_runner_configuration(self) -> None:
        lowered = self.text.lower()
        for term in (
            "get-netipconfiguration",
            "get-nettcpconnection",
            "localport 8765",
            "test-netconnection",
            "confirmed monitor ipv4",
        ):
            with self.subTest(term=term):
                self.assertIn(term, lowered)

    def test_runbook_documents_privileged_file_transfer_without_exposing_token(self) -> None:
        lowered = self.text.lower()
        for term in (
            "administrative powershell",
            "copy-item",
            "monitor-token.txt",
            "monitor.crt",
            "monitor.key",
            "access denied",
            "repairpermissions",
            "token value is never",
        ):
            with self.subTest(term=term):
                self.assertIn(term, lowered)
        self.assertIn("c$", lowered)

    def test_update_script_can_enable_existing_service_lifecycle(self) -> None:
        update_script = (REPO_ROOT / "scripts" / "Update-RunnerObservability.ps1").read_text(encoding="utf-8")
        self.assertIn("$ServiceName", update_script)
        self.assertIn('"--service-name", $ServiceName', update_script)
        self.assertIn("does not install", update_script.lower())


class ReadmeOnboardingShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (REPO_ROOT / "README.md").read_text(encoding="utf-8")

    def test_full_clean_flow_transfers_new_secrets_after_reset(self) -> None:
        lowered = self.text.lower()
        for term in (
            "after the full-clean reset",
            "do not run this transfer block",
            "reset removes the old",
            "token/certificate pair; transfer the newly generated current pair",
        ):
            with self.subTest(term=term):
                self.assertIn(term, lowered)


class CanaryEvidenceTemplateShapeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.text = (REPO_ROOT / "docs" / "canary-evidence-template.md").read_text(encoding="utf-8")

    def test_template_still_marks_deployment_rows_as_document_shape_only(self) -> None:
        self.assertIn("document shape only", self.text.lower())

    def test_template_still_defers_the_production_ready_decision_to_issue_6(self) -> None:
        self.assertIn("Issue #6", self.text)


if __name__ == "__main__":
    unittest.main()
