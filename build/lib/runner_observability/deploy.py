"""Local deployment/rollback CONTRACT simulation (issue #4 PERS-04 gap; not issue #6 HITL).

This module exists to close a gap in issue #4 (PERS-04)'s own verification
table, which requires the deployment/rollback *contract* -- pinned revision
handling, preflight, atomic activation, rollback -- to be verifiable in a
local fixture, without ever touching a real Windows Service, a real
certificate store, or a real network host. It is deliberately NOT the
physical Monitor Host / Runner A / Runner B deployment; that stays reserved
for issue #6's HITL acceptance (see ``docs/canary-evidence-template.md``).

Scope boundary (binding, mirrors ``gate.py``):

- Every filesystem operation here (``stage_release``, ``activate``,
  ``deactivate``) operates only on the caller-supplied ``install_root`` --
  never a hardcoded system path, never ``Program Files``, never a real
  Windows Service Control Manager call.
- The preflight checks in this module are deliberately split into two
  kinds. ``check_python_version`` is a real, always-safe local check (it
  only reads ``sys.version_info`` or an injected tuple). The certificate
  and auth checks are *contract-level*: they confirm a credential/cert
  *file is configured and present*, and deliberately never read, log, or
  return its contents -- verifying it is *trusted*/*accepted* by a real
  TLS handshake or a real auth endpoint is real-network work that belongs
  to issue #6, not here. ``check_firewall_port`` and
  ``check_host_reachable`` take an *injectable probe* with **no network
  default at all** -- if the caller does not supply one, the check fails
  closed with a stable "not configured" reason rather than silently
  reaching for a real socket. This is what keeps this module (and every
  test that imports it) 100% runner-independent by construction, not by
  convention.
- Bounded behavior: ``check_host_reachable`` retries its probe at most
  ``max_attempts`` times (default 3) with an injectable ``sleeper`` --
  never an unbounded or infinite retry loop. Post-activation checks
  (service start / smoke test) run exactly once each and short-circuit
  rollback on the first failure; they are never retried in place.
- Redaction: every dataclass here (``CheckResult``, ``PreflightReport``,
  ``DeployResult``) carries only stable reason codes and revision
  identifiers the operator themselves chose to pass in -- never a raw
  exception message, traceback, absolute path, or credential value. Both
  the Python CLI (`main`) and the thin PowerShell wrappers around it must
  never print a configured cert/token file's path or contents.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
import argparse
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
from typing import Protocol


# ---------------------------------------------------------------------------
# Pinned revision handling
# ---------------------------------------------------------------------------

# A safe, bounded token: letters, digits, dot, dash, underscore only -- no
# path separators, no "..", no leading dot (which could collide with the
# atomic-switch temp-file naming below). This is deliberately conservative;
# it does not know which strings are "floating" tags in a real artifact
# registry (that discipline belongs to the runbook/operator process), it
# only guarantees the identifier can never escape ``releases/<revision>``.
_REVISION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class InvalidRevisionError(ValueError):
    """A revision identifier failed validation -- never a real deployment error."""


def validate_revision(revision: object) -> str:
    """Validate a pinned revision identifier and return it unchanged.

    Rejects anything that is not a bounded, path-traversal-free token:
    empty strings, non-strings, and any value containing ``/``, ``\\``, or
    ``..`` (checked independently of the character-class match so a
    same-directory traversal like ``a/../b`` is caught even though every
    individual character is otherwise allowed).
    """
    if not isinstance(revision, str) or not _REVISION_PATTERN.match(revision) or ".." in revision:
        raise InvalidRevisionError(REASON_INVALID_REVISION)
    return revision


# ---------------------------------------------------------------------------
# Preflight checks -- each produces one actionable, stable diagnostic
# ---------------------------------------------------------------------------

REASON_UNSUPPORTED_PYTHON_VERSION = "unsupported_python_version"
REASON_TLS_CERT_FILE_MISSING = "tls_certificate_file_missing"
REASON_TLS_CERTIFICATE_INVALID = "tls_certificate_invalid"
REASON_AUTH_CREDENTIAL_MISSING = "auth_credential_file_missing"
REASON_FIREWALL_CHECK_NOT_CONFIGURED = "firewall_check_not_configured"
REASON_FIREWALL_PORT_BLOCKED = "firewall_port_blocked"
REASON_HOST_CHECK_NOT_CONFIGURED = "host_reachability_check_not_configured"
REASON_HOST_UNREACHABLE = "monitor_host_unreachable"

# Rollback / unexpected-failure reason codes. These are only ever reached
# after a post-activation check has already failed (or the deploy attempt
# hit an error the preflight battery could not anticipate) -- they are
# never used for a "clean" success or a normal preflight failure.
REASON_ROLLBACK_TARGET_MISSING = "rollback_target_missing"
REASON_SOURCE_UNAVAILABLE = "source_unavailable"
REASON_INSTALL_ROOT_UNWRITABLE = "install_root_unwritable"
REASON_INVALID_REVISION = "invalid_revision_identifier"
REASON_UNEXPECTED_DEPLOY_ERROR = "unexpected_deploy_error"


@dataclass(frozen=True, slots=True)
class CheckResult:
    """The redacted, safe-to-persist outcome of one preflight check."""

    name: str
    passed: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class PreflightReport:
    """The complete, redacted preflight result -- reason codes only."""

    checks: tuple[CheckResult, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    @property
    def failure_reasons(self) -> tuple[str, ...]:
        return tuple(check.reason for check in self.checks if not check.passed)


BoolProbe = Callable[[], bool]


class ServiceLifecycle(Protocol):
    """Minimal service adapter used only when a real service is configured."""

    def stop(self) -> bool: ...

    def start(self) -> bool: ...

    def status(self) -> str: ...


ServiceCommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class WindowsScServiceLifecycle:
    """Bounded service lifecycle adapter used by the explicit Windows CLI path."""

    def __init__(
        self,
        service_name: str,
        command_runner: ServiceCommandRunner | None = None,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        self._service_name = service_name
        self._timeout_seconds = timeout_seconds
        self._command_runner = command_runner or self._run_command

    def stop(self) -> bool:
        if self.status() == "stopped":
            return True
        return self._invoke("stop")

    def start(self) -> bool:
        if self.status() == "running":
            return True
        return self._invoke("start")

    def status(self) -> str:
        try:
            result = self._command_runner(("query", self._service_name))
        except Exception:
            return "unknown"
        output = f"{result.stdout}\n{result.stderr}".upper()
        if result.returncode != 0 and "STOPPED" not in output:
            return "unknown"
        if "RUNNING" in output:
            return "running"
        if "STOPPED" in output:
            return "stopped"
        return "unknown"

    def _invoke(self, action: str) -> bool:
        try:
            result = self._command_runner((action, self._service_name))
        except Exception:
            return False
        return result.returncode == 0

    def _run_command(self, arguments: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["sc.exe", *arguments],
            capture_output=True,
            text=True,
            timeout=self._timeout_seconds,
            check=False,
        )


def check_python_version(*, actual: tuple[int, int] | None = None, minimum: tuple[int, int] = (3, 11)) -> CheckResult:
    """Compare the running (or injected) Python version against a minimum.

    This is a real, always-safe local check -- it never touches the network.
    """
    version = actual if actual is not None else (sys.version_info.major, sys.version_info.minor)
    passed = version >= minimum
    return CheckResult("python_version", passed, "" if passed else REASON_UNSUPPORTED_PYTHON_VERSION)


def check_tls_certificate_file(cert_path: Path | str | None, key_path: Path | str | None = None) -> CheckResult:
    """Confirm a TLS certificate file is configured and present -- contents are never read directly.

    With ``key_path`` omitted (the default), this proves only that a cert
    *is configured and present*, exactly as before -- it does not by
    itself prove the file is a valid certificate or that it would ever
    actually be used for encryption.

    When ``key_path`` is also supplied, this check is strengthened: it
    additionally attempts to load the pair into a real
    ``ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`` via ``load_cert_chain`` --
    the exact call ``server.create_server()`` makes when it wraps the
    Monitor Host's listening socket for HTTPS (issue #7 PERS-07). This
    requires no real server, no socket, and no network activity, but does
    prove the configured file is a loadable certificate whose private key
    actually matches it, closing the previous "file present on disk" ==
    "will actually be used for encryption" gap. It still never proves the
    certificate is *trusted* by a real client against a real host -- that
    remains issue #6's job. Load failures (missing/unreadable key file,
    malformed PEM content, a mismatched key) are reported only as the
    stable ``tls_certificate_invalid`` reason -- never the configured path
    or the underlying ``ssl``/``OSError`` exception text.
    """
    if cert_path is None:
        return CheckResult("tls_certificate", False, REASON_TLS_CERT_FILE_MISSING)
    path = Path(cert_path)
    passed = path.is_file() and path.stat().st_size > 0
    if not passed:
        return CheckResult("tls_certificate", False, REASON_TLS_CERT_FILE_MISSING)
    if key_path is None:
        return CheckResult("tls_certificate", True, "")
    # Every load failure from here on -- a missing/unreadable key file, an
    # empty key file, malformed PEM content, or a mismatched key -- is
    # reported as the single tls_certificate_invalid reason, matching this
    # function's own docstring and server.create_server()'s handling of
    # the identical situation. A separate presence pre-check for key_path
    # used to (incorrectly) report the cert-missing reason for a missing
    # *key* file, which contradicted both the docstring above and the
    # runbook, and pointed an operator at the wrong file. Let
    # load_cert_chain itself be the single source of truth instead.
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # Mirror server.create_server()'s explicit floor so this check
        # predicts the same outcome serve would produce.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(path), keyfile=str(key_path))
    except (OSError, ssl.SSLError):
        return CheckResult("tls_certificate", False, REASON_TLS_CERTIFICATE_INVALID)
    return CheckResult("tls_certificate", True, "")


def check_auth_credential_file(token_path: Path | str | None) -> CheckResult:
    """Confirm an auth credential file is configured and present -- contents are never read.

    This proves only that a credential *is configured*, not that a real
    auth endpoint accepts it -- that is issue #6's job.
    """
    if token_path is None:
        return CheckResult("auth_credential", False, REASON_AUTH_CREDENTIAL_MISSING)
    path = Path(token_path)
    passed = path.is_file() and path.stat().st_size > 0
    return CheckResult("auth_credential", passed, "" if passed else REASON_AUTH_CREDENTIAL_MISSING)


def check_firewall_port(probe: BoolProbe | None) -> CheckResult:
    """Confirm a firewall rule permits the ingest port, via an injected probe only.

    There is deliberately no default network probe: an unconfigured check
    fails closed with a stable reason rather than silently reaching for a
    real firewall API.
    """
    if probe is None:
        return CheckResult("firewall", False, REASON_FIREWALL_CHECK_NOT_CONFIGURED)
    try:
        passed = bool(probe())
    except Exception:
        passed = False
    return CheckResult("firewall", passed, "" if passed else REASON_FIREWALL_PORT_BLOCKED)


def check_host_reachable(
    probe: BoolProbe | None,
    *,
    max_attempts: int = 3,
    sleeper: Callable[[float], None] = lambda _seconds: None,
) -> CheckResult:
    """Confirm the Monitor Host is reachable, via an injected probe, bounded retries only.

    There is deliberately no default network probe (see ``check_firewall_port``).
    When a probe is supplied, it is retried at most ``max_attempts`` times --
    never in an unbounded or infinite loop -- with a caller-injectable
    ``sleeper`` between attempts so tests never sleep for real.
    """
    if probe is None:
        return CheckResult("host_reachable", False, REASON_HOST_CHECK_NOT_CONFIGURED)
    for attempt in range(1, max_attempts + 1):
        try:
            if probe():
                return CheckResult("host_reachable", True, "")
        except Exception:
            pass
        if attempt < max_attempts:
            sleeper(1.0)
    return CheckResult("host_reachable", False, REASON_HOST_UNREACHABLE)


def run_preflight(
    *,
    python_version: tuple[int, int] | None = None,
    minimum_python_version: tuple[int, int] = (3, 11),
    tls_cert_path: Path | str | None = None,
    tls_key_path: Path | str | None = None,
    auth_token_path: Path | str | None = None,
    firewall_probe: BoolProbe | None = None,
    host_reachable_probe: BoolProbe | None = None,
    max_host_attempts: int = 3,
    sleeper: Callable[[float], None] = lambda _seconds: None,
) -> PreflightReport:
    """Run the full preflight battery and collect every failure reason, not just the first.

    ``tls_key_path`` is optional; supplying it strengthens the TLS
    certificate check from file-presence-only to a real, local
    ``SSLContext`` load (see ``check_tls_certificate_file``). Omitting it
    keeps the original, weaker check -- this parameter is purely additive.
    """
    checks = (
        check_python_version(actual=python_version, minimum=minimum_python_version),
        check_tls_certificate_file(tls_cert_path, tls_key_path),
        check_auth_credential_file(auth_token_path),
        check_firewall_port(firewall_probe),
        check_host_reachable(host_reachable_probe, max_attempts=max_host_attempts, sleeper=sleeper),
    )
    return PreflightReport(checks=checks)


# ---------------------------------------------------------------------------
# Release layout and atomic switch
# ---------------------------------------------------------------------------

_POINTER_FILE_NAME = "current-release.txt"


@dataclass(frozen=True, slots=True)
class ReleaseLayout:
    """A local, fixture-friendly release directory layout.

    ``install_root/releases/<revision>/`` holds each staged release's files.
    ``install_root/current-release.txt`` is a plain-text pointer file naming
    the active revision; it is only ever replaced via an atomic same-
    directory temp-file-plus-``os.replace`` swap, never edited in place, so
    a crash mid-switch can never leave a half-written pointer.
    """

    install_root: Path

    @property
    def releases_dir(self) -> Path:
        return self.install_root / "releases"

    @property
    def current_pointer(self) -> Path:
        return self.install_root / _POINTER_FILE_NAME

    def release_path(self, revision: str) -> Path:
        return self.releases_dir / validate_revision(revision)

    def current_revision(self) -> str | None:
        if not self.current_pointer.is_file():
            return None
        text = self.current_pointer.read_text(encoding="utf-8").strip()
        return text or None

    def release_exists(self, revision: str) -> bool:
        return self.release_path(revision).is_dir()

    def stage_release(self, revision: str, source_dir: Path | str) -> Path:
        """Copy ``source_dir`` into ``releases/<revision>``, replacing any prior staging of it.

        Never touches any other revision's directory -- a previously
        activated release is always retained so rollback can restore it.

        The copy happens into a throwaway sibling directory first, and only
        the final directory rename replaces ``releases/<revision>`` -- so a
        failure partway through the (potentially slow) copy never leaves an
        existing staged/active release half-deleted or half-overwritten. If
        ``revision`` happens to be the currently active one, this keeps the
        window where its directory is briefly absent as short as a single
        rename instead of spanning the whole copy.
        """
        revision = validate_revision(revision)
        target = self.release_path(revision)
        target.parent.mkdir(parents=True, exist_ok=True)
        staging = self.releases_dir / f".{revision}.staging-{os.getpid()}"
        if staging.exists():
            shutil.rmtree(staging)
        shutil.copytree(Path(source_dir), staging)
        if target.exists():
            shutil.rmtree(target)
        os.replace(staging, target)
        return target

    def activate(self, revision: str) -> None:
        """Atomically point ``current-release.txt`` at ``revision``.

        Writes the new content to a temp file in the same directory as the
        pointer (guaranteeing the same filesystem/volume) and swaps it in
        with a single ``os.replace``, which is atomic on both POSIX and
        NTFS. If ``os.replace`` itself fails, the previous pointer content
        is left completely untouched and the temp file is removed.
        """
        revision = validate_revision(revision)
        if not self.release_exists(revision):
            raise FileNotFoundError("release_not_staged")
        self.install_root.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(dir=self.install_root, prefix=".current-release-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(revision)
            os.replace(tmp_name, self.current_pointer)
        except Exception:
            try:
                os.remove(tmp_name)
            except OSError:
                pass
            raise

    def deactivate(self) -> None:
        """Remove the pointer file, returning to a "no active release" state.

        Used only when rolling back a first install that had no previous
        version to restore. A safe no-op if nothing is currently active.
        """
        try:
            self.current_pointer.unlink()
        except FileNotFoundError:
            pass


# ---------------------------------------------------------------------------
# Deploy orchestration: preflight gate, atomic switch, post-activation checks, rollback
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DeployResult:
    """The redacted outcome of one install/update attempt -- no paths, no raw errors."""

    revision: str
    success: bool
    rolled_back: bool
    restored_revision: str | None
    failure_reason: str = ""
    preflight: PreflightReport | None = field(default=None, compare=False)


def deploy_release(
    layout: ReleaseLayout,
    revision: str,
    source_dir: Path | str,
    *,
    preflight_report: PreflightReport,
    post_activation_checks: Sequence[tuple[str, BoolProbe]] = (),
    service_lifecycle: ServiceLifecycle | None = None,
) -> DeployResult:
    """Stage, atomically activate, and verify one revision; roll back on any failure.

    Order: preflight must already have passed (callers run ``run_preflight``
    themselves so its probes stay swappable/testable independently of this
    function) -> stage the release -> atomically activate it -> run each
    ``post_activation_checks`` entry in order, stopping at the first
    failure. Any failure -- preflight, or a post-activation check -- leaves
    the previous revision active (or, for a first install with no previous
    revision, leaves no active release) and is fully repeatable: calling
    this again with the same failing inputs reaches the same safe state
    every time.
    """
    revision = validate_revision(revision)

    if not preflight_report.passed:
        reasons = preflight_report.failure_reasons
        return DeployResult(
            revision=revision,
            success=False,
            rolled_back=False,
            restored_revision=layout.current_revision(),
            failure_reason=reasons[0] if reasons else "preflight_failed",
            preflight=preflight_report,
        )

    previous_revision = layout.current_revision()
    service_stopped = False

    if service_lifecycle is not None:
        try:
            service_stopped = bool(service_lifecycle.stop())
        except Exception:
            service_stopped = False
        if not service_stopped:
            return DeployResult(
                revision=revision,
                success=False,
                rolled_back=False,
                restored_revision=previous_revision,
                failure_reason="service_stop_failed",
                preflight=preflight_report,
            )

    try:
        layout.stage_release(revision, source_dir)
        layout.activate(revision)
    except FileNotFoundError:
        deployment_failure_reason = REASON_SOURCE_UNAVAILABLE
    except OSError:
        deployment_failure_reason = REASON_INSTALL_ROOT_UNWRITABLE
    except Exception:
        deployment_failure_reason = "deployment_failed"
    else:
        deployment_failure_reason = ""
    if deployment_failure_reason:
        if previous_revision is None:
            layout.deactivate()
        elif layout.release_exists(previous_revision):
            layout.activate(previous_revision)
        if service_lifecycle is not None and service_stopped:
            try:
                service_lifecycle.start()
            except Exception:
                pass
        return DeployResult(
            revision=revision,
            success=False,
            rolled_back=previous_revision is not None,
            restored_revision=previous_revision,
            failure_reason=deployment_failure_reason,
            preflight=preflight_report,
        )

    for check_name, check in post_activation_checks:
        try:
            passed = bool(check())
        except Exception:
            passed = False
        if not passed:
            return _rollback_after_failure(
                layout,
                revision,
                previous_revision,
                f"{check_name}_failed",
                preflight_report,
                service_lifecycle,
                service_stopped,
            )

    if service_lifecycle is not None:
        try:
            service_started = bool(service_lifecycle.start())
        except Exception:
            service_started = False
        if not service_started:
            return _rollback_after_failure(
                layout,
                revision,
                previous_revision,
                "service_start_failed",
                preflight_report,
                service_lifecycle,
                service_stopped,
            )

    return DeployResult(
        revision=revision,
        success=True,
        rolled_back=False,
        restored_revision=None,
        failure_reason="",
        preflight=preflight_report,
    )


def _rollback_after_failure(
    layout: ReleaseLayout,
    revision: str,
    previous_revision: str | None,
    failure_reason: str,
    preflight_report: PreflightReport,
    service_lifecycle: ServiceLifecycle | None,
    service_stopped: bool,
) -> DeployResult:
    """Restore a safe release and best-effort restart the previous service."""
    if previous_revision is None:
        layout.deactivate()
        return DeployResult(
            revision=revision,
            success=False,
            rolled_back=True,
            restored_revision=None,
            failure_reason=failure_reason,
            preflight=preflight_report,
        )
    if not layout.release_exists(previous_revision):
        layout.deactivate()
        return DeployResult(
            revision=revision,
            success=False,
            rolled_back=True,
            restored_revision=None,
            failure_reason=REASON_ROLLBACK_TARGET_MISSING,
            preflight=preflight_report,
        )
    layout.activate(previous_revision)
    if service_lifecycle is not None and service_stopped:
        try:
            service_lifecycle.start()
        except Exception:
            pass
    return DeployResult(
        revision=revision,
        success=False,
        rolled_back=True,
        restored_revision=previous_revision,
        failure_reason=failure_reason,
        preflight=preflight_report,
    )


# ---------------------------------------------------------------------------
# Default (real, but always-local-and-safe) smoke test
# ---------------------------------------------------------------------------


def default_smoke_test(release_path: Path, *, timeout_seconds: float = 30.0) -> bool:
    """Confirm the just-activated release's CLI entrypoint is importable and runnable.

    This is a real, local subprocess invocation of ``python -m
    runner_observability --help`` against the release's own ``src`` layout
    -- it never starts a real Windows Service and never opens a socket. It
    is intentionally bounded by ``timeout_seconds`` (a single attempt, no
    retry loop) and never surfaces the subprocess's raw stdout/stderr to
    any caller -- only a pass/fail boolean.
    """
    package_root = release_path / "src"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(package_root)
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "runner_observability", "--help"],
            cwd=release_path,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except Exception:
        return False
    return completed.returncode == 0


# ---------------------------------------------------------------------------
# CLI entry point (invoked by the thin PowerShell wrappers)
# ---------------------------------------------------------------------------

Printer = Callable[[str], None]


def main(
    argv: Sequence[str] | None = None,
    *,
    firewall_probe: BoolProbe | None = None,
    host_reachable_probe: BoolProbe | None = None,
    max_host_attempts: int = 3,
    smoke_test: Callable[[Path], bool] | None = None,
    service_lifecycle: ServiceLifecycle | None = None,
    printer: Printer = print,
) -> int:
    """Dispatch ``preflight`` / ``install`` / ``update``.

    Every probe (firewall, host-reachability, smoke test) is injectable so
    both this module's own tests and the thin PowerShell wrappers can
    supply fakes; nothing here defaults to a real network call. Output goes
    only through ``printer``, and never includes a configured cert/token
    file's path -- only stable check names and reason codes.
    """
    parser = argparse.ArgumentParser(prog="runner-observability-deploy")
    subcommands = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subcommands.add_parser("preflight", help="run the local preflight check battery")
    preflight_parser.add_argument("--tls-cert-path", default=None)
    preflight_parser.add_argument("--tls-key-path", default=None)
    preflight_parser.add_argument("--auth-token-path", default=None)
    preflight_parser.add_argument("--firewall-result", choices=("pass", "fail"), default=None)
    preflight_parser.add_argument("--host-reachable-result", choices=("pass", "fail"), default=None)

    for name in ("install", "update"):
        sub = subcommands.add_parser(name, help=f"{name} a pinned revision")
        sub.add_argument("--revision", required=True)
        sub.add_argument("--source", required=True)
        sub.add_argument("--install-root", required=True)
        sub.add_argument("--tls-cert-path", default=None)
        sub.add_argument("--tls-key-path", default=None)
        sub.add_argument("--auth-token-path", default=None)
        sub.add_argument("--firewall-result", choices=("pass", "fail"), default=None)
        sub.add_argument("--host-reachable-result", choices=("pass", "fail"), default=None)
        sub.add_argument("--service-name", default=None)

    args = parser.parse_args(argv)

    effective_firewall_probe = firewall_probe if firewall_probe is not None else _probe_from_result(args.firewall_result)
    effective_host_probe = (
        host_reachable_probe if host_reachable_probe is not None else _probe_from_result(args.host_reachable_result)
    )

    if args.command == "preflight":
        try:
            report = run_preflight(
                tls_cert_path=args.tls_cert_path,
                tls_key_path=args.tls_key_path,
                auth_token_path=args.auth_token_path,
                firewall_probe=effective_firewall_probe,
                host_reachable_probe=effective_host_probe,
                max_host_attempts=max_host_attempts,
            )
        except Exception:
            # Same redaction guarantee as the install/update path below:
            # never let a raw traceback (with absolute cert/token paths)
            # reach operator output.
            printer(f"preflight passed=False reason={REASON_UNEXPECTED_DEPLOY_ERROR}")
            return 1
        _print_preflight(report, printer)
        return 0 if report.passed else 1

    # install / update
    layout = ReleaseLayout(Path(args.install_root))
    preflight_report = run_preflight(
        tls_cert_path=args.tls_cert_path,
        tls_key_path=args.tls_key_path,
        auth_token_path=args.auth_token_path,
        firewall_probe=effective_firewall_probe,
        host_reachable_probe=effective_host_probe,
        max_host_attempts=max_host_attempts,
    )
    _print_preflight(preflight_report, printer)

    def _smoke() -> bool:
        # A single, unambiguous calling convention: every smoke_test
        # callable (the real default, or an injected fake) takes exactly
        # the release path. No signature-guessing/exception-based dispatch.
        chosen = smoke_test if smoke_test is not None else default_smoke_test
        return bool(chosen(layout.release_path(args.revision)))

    effective_service_lifecycle = service_lifecycle
    if effective_service_lifecycle is None and getattr(args, "service_name", None):
        effective_service_lifecycle = WindowsScServiceLifecycle(args.service_name)

    # Any unexpected failure below (a mistyped/missing -Source, an
    # unwritable -InstallRoot, a rollback target that was manually pruned,
    # or anything else the preflight battery could not anticipate) must
    # never escape as a raw Python traceback -- that would print this
    # process's absolute paths (source, install root, interpreter) straight
    # to operator output, breaking the same redaction guarantee every check
    # above already honors. Convert every such failure into a stable,
    # redacted reason code instead.
    try:
        result = deploy_release(
            layout,
            args.revision,
            args.source,
            preflight_report=preflight_report,
            post_activation_checks=(("smoke_test", _smoke),),
            service_lifecycle=effective_service_lifecycle,
        )
    except InvalidRevisionError:
        printer(
            f"deploy command={args.command} revision=INVALID "
            f"success=False rolled_back=False reason={REASON_INVALID_REVISION}"
        )
        return 1
    except FileNotFoundError:
        printer(
            f"deploy command={args.command} revision={args.revision} "
            f"success=False rolled_back=False reason={REASON_SOURCE_UNAVAILABLE}"
        )
        return 1
    except OSError:
        printer(
            f"deploy command={args.command} revision={args.revision} "
            f"success=False rolled_back=False reason={REASON_INSTALL_ROOT_UNWRITABLE}"
        )
        return 1
    except Exception:
        printer(
            f"deploy command={args.command} revision={args.revision} "
            f"success=False rolled_back=False reason={REASON_UNEXPECTED_DEPLOY_ERROR}"
        )
        return 1
    printer(
        f"deploy command={args.command} revision={result.revision} "
        f"success={result.success} rolled_back={result.rolled_back} "
        f"reason={result.failure_reason or 'none'}"
    )
    return 0 if result.success else 1


def _probe_from_result(value: str | None) -> BoolProbe | None:
    """Turn an operator-supplied ``pass``/``fail`` CLI flag into a probe.

    This never performs any real check itself -- it only lets an operator
    (or a future real-check script) hand in a result they already
    determined out of band. Omitting the flag leaves the check
    unconfigured (fails closed), exactly like passing no probe at all.
    """
    if value == "pass":
        return lambda: True
    if value == "fail":
        return lambda: False
    return None


def _print_preflight(report: PreflightReport, printer: Printer) -> None:
    printer(f"preflight passed={report.passed}")
    for check in report.checks:
        suffix = f" reason={check.reason}" if check.reason else ""
        printer(f"  - {check.name}: {'PASS' if check.passed else 'FAIL'}{suffix}")


if __name__ == "__main__":
    raise SystemExit(main())
