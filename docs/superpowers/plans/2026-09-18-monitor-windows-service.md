# Monitor Windows Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a Windows SCM-managed Monitor service boundary with protected token-file startup, ACL/Firewall orchestration, lifecycle-aware release updates, and runner-independent verification for issue #8.

**Architecture:** Keep the existing Python monitor core unchanged at its public HTTP/store seams. Add a `--token-file` credential boundary, a Windows-only `pywin32` SCM host that supervises the existing `serve` process, and a PowerShell adapter that owns service/ACL/Firewall commands. Connect the existing pinned-release update flow through an injected service lifecycle seam so local tests remain simulated while an operator can run the real path on Windows.

**Tech Stack:** Python 3.11+ standard library for monitor/config logic, optional `pywin32` on Windows for SCM callbacks, PowerShell 5.1+, `sc.exe`, Windows ACL APIs, and NetSecurity cmdlets; `unittest` and script-shape tests.

**Spec:** `docs/superpowers/specs/2026-09-18-monitor-windows-service-design.md`

**Implementation status (2026-09-18):** Tasks 1–6 are implemented and committed.
The local suite passes 264 tests; the three PowerShell scripts pass AST parsing.
Task 7's GitHub synchronization is complete, while real Windows SCM/ACL/
Firewall, boot/reboot, Runner reconnect, and production-ready evidence remain
explicitly delegated to issue #6 HITL.

## Global Constraints

- Schema version remains v1 and existing monitor/agent behavior remains backward compatible.
- `--token` remains available for existing local compatibility tests; service startup uses `--token-file` and never includes the token value in a command line, config, log, or diagnostic.
- Stable diagnostics never contain token values, private-key contents, raw exception text, configured secret paths, raw payloads, or command lines.
- The service host supervises one Python monitor child, handles SCM stop, uses bounded termination, and exits on unexpected child failure so SCM recovery can act.
- The default service identity is `NT AUTHORITY\LocalService`; custom identities are operator-configured without accepting or logging passwords.
- ACL and Firewall scripts operate only on explicit paths and the fixed Runner Observability rule name; they never delete unrelated rules.
- Real Windows SCM, ACL, Firewall, certificate trust, reboot, Runner reconnect, and production-ready evidence remain #6 HITL evidence.
- Existing no-service deployment simulation remains runner-independent and must keep passing without Windows APIs.

---

### Task 1: Add the protected token-file CLI boundary

**Files:**
- Modify: `src/runner_observability/__main__.py`
- Create: `src/runner_observability/credentials.py`
- Modify: `tests/test_serve_cli.py`
- Create: `tests/test_credentials.py`

**Interfaces:**
- `credentials.read_token_file(path: str | Path) -> str` returns a non-empty token or raises a stable `CredentialFileError(reason)` without retaining the token/path in its string representation.
- `runner_observability.main()` accepts exactly one of `--token` and `--token-file` for `serve`; `--token-file` is read before `Store` creation.

- [ ] **Step 1: Write the failing tests**

```python
def test_token_file_returns_only_the_trimmed_token(self):
    token_path = self.base / "token.txt"
    token_path.write_text("secret-value\n", encoding="utf-8")
    self.assertEqual(read_token_file(token_path), "secret-value")

def test_missing_or_empty_token_file_has_a_stable_reason(self):
    with self.assertRaises(CredentialFileError) as missing:
        read_token_file(self.base / "missing.txt")
    self.assertEqual(missing.exception.reason, "auth_credential_file_missing")
    empty = self.base / "empty.txt"
    empty.write_text("\n", encoding="utf-8")
    with self.assertRaises(CredentialFileError) as blank:
        read_token_file(empty)
    self.assertEqual(blank.exception.reason, "auth_credential_invalid")

def test_serve_token_file_does_not_create_database_on_credential_failure(self):
    result = main(["serve", "--token-file", str(self.base / "missing.txt"), "--database", str(db)])
    self.assertEqual(result, 2)
    self.assertFalse(db.exists())

def test_token_and_token_file_are_mutually_exclusive(self):
    result = main(["serve", "--token", "legacy", "--token-file", str(token_path)])
    self.assertEqual(result, 2)
```

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_credentials tests.test_serve_cli -v`

Expected: FAIL because `credentials.py` and `--token-file` do not exist yet.

- [ ] **Step 3: Implement the smallest credential boundary**

```python
class CredentialFileError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason

def read_token_file(path: Path | str) -> str:
    try:
        value = Path(path).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise CredentialFileError("auth_credential_file_missing") from error
    if not value or "\n" in value or "\r" in value:
        raise CredentialFileError("auth_credential_invalid")
    return value
```

Add a mutually exclusive argparse group, resolve either legacy token or file token, and print only `serve failed reason=<reason>` on file errors.

- [ ] **Step 4: Run the focused tests and confirm they pass**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_credentials tests.test_serve_cli -v`

Expected: PASS, with no token value or configured path in captured diagnostics.

- [ ] **Step 5: Run the existing CLI compatibility tests**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_serve_cli tests.test_http -v`

Expected: PASS for both legacy `--token` and the new `--token-file` path.

- [ ] **Step 6: Commit the credential slice**

```powershell
git add src/runner_observability/__main__.py src/runner_observability/credentials.py tests/test_serve_cli.py tests/test_credentials.py
git commit -m "feat: support protected monitor token files"
```

### Task 2: Define service config and child-command seams

**Files:**
- Modify: `pyproject.toml`
- Create: `src/runner_observability/service.py`
- Create: `tests/test_service.py`

**Interfaces:**
- `ServiceConfig.from_json(path: Path | str) -> ServiceConfig` loads only the approved fields and rejects missing/unknown/invalid values with stable reasons.
- `ServiceConfig.write_atomic(path: Path | str) -> None` writes JSON through a same-directory temporary file and rename.
- `build_monitor_command(config: ServiceConfig) -> tuple[str, ...]` returns the child argv with `--token-file` and optional TLS flags, never a token value.
- `build_service_bin_path(config_path: Path | str, python_executable: Path | str) -> str` returns the SCM command string containing only executable/module/config path values.

- [ ] **Step 1: Write the failing config and redaction tests**

```python
def test_command_uses_token_file_and_never_token_value(self):
    config = ServiceConfig(
        service_name="RunnerObservabilityMonitor",
        python_executable="C:/Python/python.exe",
        database="C:/secure/monitor.sqlite",
        token_file="C:/secure/token.txt",
        host="0.0.0.0",
        port=8765,
        tls_cert="C:/secure/cert.pem",
        tls_key="C:/secure/key.pem",
        release_root="C:/runner-observability",
    )
    command = build_monitor_command(config)
    self.assertIn("--token-file", command)
    self.assertNotIn("secret-value", command)
    self.assertEqual(build_service_bin_path(config.config_path, config.python_executable).count("secret-value"), 0)

def test_partial_tls_pair_and_invalid_port_are_rejected(self):
    with self.assertRaises(ServiceConfigError) as tls_error:
        ServiceConfig.from_mapping({"token_file": "token.txt", "tls_cert": "cert.pem"})
    self.assertEqual(tls_error.exception.reason, "tls_partial_configuration")
    with self.assertRaises(ServiceConfigError) as port_error:
        ServiceConfig.from_mapping({"token_file": "token.txt", "port": 0})
    self.assertEqual(port_error.exception.reason, "invalid_service_configuration")

def test_config_write_is_atomic_and_contains_no_token_value(self):
    config.write_atomic(path)
    text = path.read_text(encoding="utf-8")
    self.assertNotIn("secret-value", text)
    self.assertEqual(ServiceConfig.from_json(path), config)
```

- [ ] **Step 2: Run the focused tests to verify red**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_service -v`

Expected: FAIL because the service module and optional dependency declaration do not exist.

- [ ] **Step 3: Implement config validation, atomic JSON, and command builders**

Use a frozen dataclass with defaults `host="0.0.0.0"`, `port=8765`, and `service_name="RunnerObservabilityMonitor"`. Reject unknown keys, empty required paths, non-integer/out-of-range ports, and a one-sided TLS pair. Keep `token_file` as a path only; do not add a token field to the dataclass.

- [ ] **Step 4: Add the Windows-only optional dependency declaration**

```toml
[project.optional-dependencies]
windows-service = [
    "pywin32>=306; platform_system == 'Windows'",
]
```

- [ ] **Step 5: Run the focused service tests**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_service -v`

Expected: PASS on the current host without importing `pywin32`.

- [ ] **Step 6: Commit the config slice**

```powershell
git add pyproject.toml src/runner_observability/service.py tests/test_service.py
git commit -m "feat: add monitor service configuration boundary"
```

### Task 3: Implement the SCM host and bounded child supervision

**Files:**
- Modify: `src/runner_observability/service.py`
- Modify: `tests/test_service.py`

**Interfaces:**
- `ChildProcess` protocol exposes `poll() -> int | None`, `terminate() -> None`, `kill() -> None`, and `wait(timeout: float) -> int`.
- `MonitorChildSupervisor(command: Sequence[str], popen_factory, stop_timeout: float = 10.0)` exposes `run(stop_event) -> int` and `stop() -> None`.
- `run_service(config_path: Path | str, *, service_api=None, popen_factory=None) -> int` selects the pywin32 adapter only on Windows and reports stable unavailable/start failure reasons elsewhere.

- [ ] **Step 1: Add fake-child tests for the public supervisor seam**

```python
def test_stop_terminates_child_and_waits_within_bound(self):
    child = FakeChild(exit_code=0)
    supervisor = MonitorChildSupervisor(("python", "-m", "runner_observability", "serve"), lambda _: child, stop_timeout=1.0)
    supervisor.stop()
    self.assertEqual(child.terminate_calls, 1)
    self.assertEqual(child.kill_calls, 0)

def test_stop_kills_a_child_that_does_not_exit(self):
    child = FakeChild(exit_code=None, ignores_terminate=True)
    MonitorChildSupervisor(("python", "-m", "runner_observability", "serve"), lambda _: child, stop_timeout=1.0).stop()
    self.assertEqual(child.kill_calls, 1)

def test_unexpected_child_exit_is_returned_as_failure(self):
    child = FakeChild(exit_code=17)
    result = MonitorChildSupervisor(("python", "-m", "runner_observability", "serve"), lambda _: child).run(Event())
    self.assertEqual(result, 17)
```

- [ ] **Step 2: Run the supervisor tests and verify red**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_service.MonitorChildSupervisorTests -v`

Expected: FAIL because the supervisor and fake seam do not exist.

- [ ] **Step 3: Implement the bounded supervisor**

Spawn with `subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)` in production. On stop, call `terminate`, wait at most `stop_timeout`, then call `kill` and wait once more. Return the child exit code; do not retry or print child output.

- [ ] **Step 4: Add the pywin32 adapter behind a guarded import**

Define the adapter only when `os.name == "nt"` and `win32service`/`win32serviceutil` import successfully. `SvcStop` reports `STOP_PENDING`, sets the stop event, and lets the supervisor perform termination. `SvcDoRun` exits with the child result; unexpected non-zero results are reported with the stable `service_child_failed` reason. Non-Windows execution returns `windows_service_unavailable` without a traceback.

- [ ] **Step 5: Run the full service seam tests**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_service -v`

Expected: PASS without requiring Windows SCM on the development host.

- [ ] **Step 6: Commit the SCM host slice**

```powershell
git add src/runner_observability/service.py tests/test_service.py
git commit -m "feat: supervise monitor through Windows service host"
```

### Task 4: Add PowerShell lifecycle, ACL, Firewall, and recovery orchestration

**Files:**
- Create: `scripts/RunnerObservability.Service.psm1`
- Create: `scripts/Install-RunnerObservabilityService.ps1`
- Create: `tests/test_service_scripts.py`

**Interfaces:**
- `Invoke-ServiceCommand` is the injectable command-runner seam used by the module; production defaults to `&` invocation and returns exit code/output only as needed for stable status decisions.
- `Install-RunnerObservabilityService.ps1` accepts `-Action Install|Start|Stop|Status|Restart|Uninstall`, `-ConfigPath`, `-PythonPath`, `-TokenPath`, `-DatabasePath`, optional TLS paths, `-RunnerAddress`, `-ServiceName`, `-ServiceAccount`, and `-Port`.
- The fixed Firewall display name is `Runner Observability Monitor TCP 8765`; all remove operations target only that exact name.

- [ ] **Step 1: Write script contract tests before implementation**

```python
def test_service_script_exposes_all_lifecycle_actions(self):
    text = self.script.read_text(encoding="utf-8")
    for action in ("Install", "Start", "Stop", "Status", "Restart", "Uninstall"):
        self.assertIn(action, text)

def test_service_script_uses_secret_safe_inputs(self):
    lowered = self.script.read_text(encoding="utf-8").lower()
    self.assertIn("--token-file", self.service_module_text)
    self.assertIn("new-netfirewallrule", lowered)
    self.assertIn("icacls", lowered)
    self.assertNotIn("password", lowered)
    self.assertNotIn("--token ", self.service_module_text)

def test_firewall_rule_is_scoped_to_runner_addresses_and_fixed_name(self):
    self.assertIn("-RemoteAddress $RunnerAddress", self.module_text)
    self.assertIn("Runner Observability Monitor TCP 8765", self.module_text)
    self.assertIn("Remove-NetFirewallRule", self.module_text)
```

- [ ] **Step 2: Run the script tests to verify red**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_service_scripts -v`

Expected: FAIL because the module and installer script do not exist.

- [ ] **Step 3: Implement safe command helpers**

Create `Invoke-CheckedCommand`, `Write-AtomicJson`, `Set-ProtectedFileAcl`, `Set-ProtectedDirectoryAcl`, `Ensure-RunnerObservabilityFirewallRule`, `Remove-RunnerObservabilityFirewallRule`, and service query helpers. Convert all external failures to stable reason codes without printing command lines, token paths, or exception text.

- [ ] **Step 4: Implement the Install action**

Validate explicit token/database/config paths and the TLS pair, write the config atomically, apply file/directory ACLs, create the service with `sc.exe create`, set `obj= NT AUTHORITY\LocalService` by default, configure `sc.exe failure` recovery, and create the fixed Firewall allow rule for the provided Runner addresses.

- [ ] **Step 5: Implement lifecycle and uninstall actions**

Use `sc.exe start/stop/query/delete` for lifecycle operations. `Status` must return a stable state summary. `Uninstall` stops and deletes only the named service, removes only the fixed Firewall rule, and leaves release directories and evidence files untouched.

- [ ] **Step 6: Run the script contract tests**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_service_scripts -v`

Expected: PASS without executing SCM, ACL, or NetSecurity commands.

- [ ] **Step 7: Commit the PowerShell slice**

```powershell
git add scripts/RunnerObservability.Service.psm1 scripts/Install-RunnerObservabilityService.ps1 tests/test_service_scripts.py
git commit -m "feat: add monitor service ACL and firewall orchestration"
```

### Task 5: Wire service lifecycle into pinned-release updates

**Files:**
- Modify: `src/runner_observability/deploy.py`
- Modify: `scripts/Update-RunnerObservability.ps1`
- Modify: `tests/test_deployment_docs.py`

**Interfaces:**
- Add `ServiceLifecycle` protocol with `stop() -> bool`, `start() -> bool`, and `status() -> str`.
- Extend the deployment operation with optional `service_lifecycle: ServiceLifecycle | None`; `None` preserves current simulation behavior.
- Service-enabled update ordering is `stop -> stage -> activate -> smoke -> start`; any failure restores the previous pointer and calls `start()` for the previous release when it exists.

- [ ] **Step 1: Add ordering and rollback tests**

```python
def test_service_enabled_update_stops_before_activation_and_starts_after_smoke(self):
    calls = []
    service = FakeService(calls)
    result = deploy_release(layout, "new", source_dir, preflight_report=passing_report, post_activation_checks=[("smoke_test", lambda: calls.append("smoke") or True)], service_lifecycle=service)
    self.assertTrue(result.success)
    self.assertEqual(calls, ["stop", "smoke", "start"])

def test_service_start_failure_restores_previous_release_and_restarts_old_service(self):
    service = FakeService(["stop"], start_results=[False, True])
    result = deploy_release(layout, "new", source_dir, preflight_report=passing_report, post_activation_checks=[("smoke_test", lambda: True)], service_lifecycle=service)
    self.assertEqual(result.failure_reason, "service_start_failed")
    self.assertEqual(layout.current_revision(), "previous")
    self.assertEqual(service.calls, ["stop", "start", "start"])

def test_without_service_lifecycle_existing_deployment_order_is_unchanged(self):
    result = deploy_release(layout, "new", source_dir, preflight_report=passing_report, post_activation_checks=[("smoke_test", lambda: True)], service_lifecycle=None)
    self.assertTrue(result.success)
```

- [ ] **Step 2: Run deployment tests to verify red**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_deployment_docs.DeployReleaseTests -v`

Expected: new service-order tests fail while all existing deployment tests remain green.

- [ ] **Step 3: Implement the optional lifecycle seam**

Thread the optional service adapter through the existing transaction/rollback path. Keep all filesystem and result redaction guarantees. Do not make `deploy.py` import PowerShell or Windows-only modules.

- [ ] **Step 4: Add PowerShell wiring without changing simulation defaults**

Extend `Update-RunnerObservability.ps1` with an explicit optional service name. When it is supplied, pass `--service-name` to the Python deploy command; the bounded `sc.exe` adapter performs the stop/start sequence and deploy rollback. Without it, retain the current runner-independent local simulation path.

- [ ] **Step 5: Run focused deployment verification**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_deployment_docs -v`

Expected: PASS for existing 100% runner-independent deployment simulation and new injected service ordering.

- [ ] **Step 6: Commit the deployment slice**

```powershell
git add src/runner_observability/deploy.py scripts/Update-RunnerObservability.ps1 tests/test_deployment_docs.py
git commit -m "feat: connect service lifecycle to release rollback"
```

### Task 6: Update runbook and issue-specific evidence contract

**Files:**
- Modify: `docs/runbook.md`
- Modify: `README.md`
- Modify: `tests/test_deployment_docs.py`

**Interfaces:**
- Documentation must show token-file service startup, lifecycle commands, ACL/Firewall inputs, recovery behavior, and removal commands without any real token or private-key material.
- Documentation must state that implementation scripts are delivered by #8 while real-host evidence and production-ready decision remain #6 HITL.

- [ ] **Step 1: Add documentation-shape tests**

```python
def test_runbook_documents_token_file_service_startup_and_lifecycle(self):
    lowered = self.runbook.lower()
    for term in ("--token-file", "install-runnerobservabilityservice.ps1", "sc.exe", "icacls", "new-netfirewallrule", "restart"):
        self.assertIn(term, lowered)

def test_runbook_keeps_live_acceptance_in_issue_6(self):
    lowered = self.runbook.lower()
    self.assertIn("issue #6", lowered)
    self.assertIn("real", lowered)
```

- [ ] **Step 2: Run the new documentation tests to verify red**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_deployment_docs.RunbookShapeTests -v`

Expected: the new service-specific assertions fail before documentation changes.

- [ ] **Step 3: Update the operator flow**

Document the safe install sequence with non-secret path/address metavariables, never credentials: write the token file out-of-band, install service config, apply ACL, create the Firewall rule for Runner A/B addresses, run `status`, perform the smoke check, and use `Update-RunnerObservability.ps1` for pinned upgrades/rollback.

- [ ] **Step 4: Document failure triage and evidence boundary**

Add stable reasons for credential-file failure, service child failure, service start failure, rollback target missing, and Firewall rule mismatch. State exactly which checks are local shape/simulation and which must be timestamped in #6.

- [ ] **Step 5: Run documentation and redaction tests**

Run: `$env:PYTHONPATH='src'; python -m unittest tests.test_deployment_docs -v`

Expected: PASS, including existing checks for absence of bearer-looking values, raw paths, and premature production-ready claims.

- [ ] **Step 6: Commit the documentation slice**

```powershell
git add docs/runbook.md README.md tests/test_deployment_docs.py
git commit -m "docs: document monitor service operations and evidence boundary"
```

### Task 7: Full verification and tracker synchronization

**Files:**
- Modify: `docs/superpowers/plans/2026-09-18-monitor-windows-service.md`
- Modify: issue #8 body through the authenticated GitHub CLI after evidence exists.

- [ ] **Step 1: Run the complete local suite**

Run: `$env:PYTHONPATH='src'; python -m unittest discover -s tests -v`

Expected: all tests pass; capture the exact test count and no-failure summary.

- [ ] **Step 2: Run repository redaction scans**

Run: `rg -n -i "ghp_|github_pat_|bearer [A-Za-z0-9._-]{12,}|password\s*=|token\s*=" README.md docs scripts src tests`

Expected: only safe option names, test fixture markers, or non-secret path/address metavariables appear; no credential value or private-key content is introduced.

- [ ] **Step 3: Review the diff and plan coverage**

Run: `git diff --check HEAD~6..HEAD` and inspect `git diff --stat HEAD~6..HEAD`. Confirm every issue #8 acceptance row has either local evidence or an explicit #6 HITL evidence boundary.

- [ ] **Step 4: Synchronize issue #8 without closing it**

Update the issue’s `Plan`, `Verification`, and pending-items section with observed local test evidence and pinned commit links. Keep issue state Open and Project status In Progress until #6 consumes live deployment evidence; do not claim real boot, service, ACL, Firewall, or reboot results from local tests.

- [ ] **Step 5: Reread GitHub state**

Run: `gh issue view 8 --repo StolasIn-cl/runner-observability --json state,assignees,body,projectItems,url` and `gh project item-list 2 --owner StolasIn-cl --format json`. Confirm assignee `StolasIn-cl`, issue Open, and Project `In Progress` before reporting the implementation handoff.
