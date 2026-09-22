# Runner and Monitor Onboarding Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver safe, role-separated Windows onboarding and service-lifecycle scripts for the Monitor Host and Runner Host, with tested inventory gates, secret boundaries, ACL repair, hosts handling, and direct-host verification commands.

**Architecture:** Keep the existing Python monitor/heartbeat runtime unchanged and add a small pure-Python onboarding contract module for validation seams. Put Windows mutations behind a shared PowerShell bootstrap module, then expose separate Monitor and Runner entry points. Keep the existing role-specific service modules as adapters, but make their lifecycle operations check service existence and wait for actual SCM state.

**Tech Stack:** Python 3.11+ standard library, `unittest`, PowerShell 5.1+/7, Windows SCM (`sc.exe`/CIM), `icacls.exe`, Windows machine environment, and `New-NetFirewallRule`.

**Spec:** `docs/superpowers/specs/2026-09-22-runner-monitor-onboarding-design.md`

## Global Constraints

- Inventory is read-only and runs before every mutating action.
- An existing `current-release.txt` is an existing managed install; never run first-install staging over it.
- A non-empty managed root without a valid release pointer fails closed with `inspect-before-use`.
- Tokens never appear in command-line arguments, config JSON, logs, issue text, or evidence.
- `monitor.key` stays on the Monitor Host and is never copied to a Runner.
- Hosts edits accept only a confirmed IPv4 address and preserve unrelated lines.
- Uninstall preserves token, certificate, key, release, identity, state, config, and database unless a future explicit cleanup action is added.
- Existing user changes under `build/`, `src/runner_observability.egg-info/`, and `scripts/Invoke-RunnerTelemetryDiagnostics.ps1` are out of scope and must remain untouched.
- The known baseline contains one unrelated deployment smoke-test failure; issue-16 tests must remain independently attributable.

---

### Task 1: Add the pure onboarding validation contract

**Files:**
- Create: `src/runner_observability/onboarding.py`
- Test: `tests/test_onboarding.py`

**Interfaces:**
- `inspect_install_root(root: Path | str) -> InstallRootInspection`
- `validate_monitor_ip(value: object) -> str`
- `validate_certificate_mode(mode: str, *, cert_present: bool, key_present: bool, allow_dev_self_signed: bool) -> None`
- `upsert_hosts_mapping(contents: str, *, hostname: str, monitor_ip: str, replace_conflicting: bool = False) -> HostsUpdate`
- `safe_reason(value: object) -> str`

- [ ] **Step 1: Write failing tests for the public seams**

  Add tests for:

  ```python
  self.assertEqual(inspect_install_root(missing).state, "new")
  self.assertEqual(inspect_install_root(with_pointer).state, "existing")
  self.assertEqual(inspect_install_root(non_empty_without_pointer).state, "inspect-before-use")
  with self.assertRaises(OnboardingValidationError):
      validate_monitor_ip("<monitor-host>")
  self.assertEqual(validate_monitor_ip("192.168.24.10"), "192.168.24.10")
  self.assertEqual(upsert_hosts_mapping("127.0.0.1 localhost\n", hostname="monitor-test.local", monitor_ip="192.168.24.10").changed, True)
  self.assertEqual(upsert_hosts_mapping("192.168.24.10 monitor-test.local\n", hostname="monitor-test.local", monitor_ip="192.168.24.10").changed, False)
  with self.assertRaises(OnboardingValidationError):
      upsert_hosts_mapping("192.168.24.11 monitor-test.local\n", hostname="monitor-test.local", monitor_ip="192.168.24.10")
  ```

- [ ] **Step 2: Run only the new test module and verify it fails**

  Run:

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_onboarding -v
  ```

  Expected: import or missing-interface failures because the contract module is not implemented yet.

- [ ] **Step 3: Implement the minimal contract**

  Use dataclasses containing only bounded state/reason values. Inspect the filesystem only for existence, file type, pointer text, and directory emptiness. Parse the pointer revision without returning absolute paths in exception messages. Validate IPv4 octets and reject placeholders, multicast, loopback, unspecified, and broadcast addresses. Update hosts text by replacing one exact hostname line only when the current address matches; raise a stable conflict error for a different address.

- [ ] **Step 4: Run the new tests and verify they pass**

  Run the same command and require zero failures/errors.

- [ ] **Step 5: Commit the isolated contract change**

  ```powershell
  git add src/runner_observability/onboarding.py tests/test_onboarding.py
  git commit -m "feat: add onboarding validation contract"
  ```

### Task 2: Add the shared Windows bootstrap module

**Files:**
- Create: `scripts/RunnerObservability.Bootstrap.psm1`
- Test: `tests/test_onboarding_scripts.py`

**Interfaces:**
- `Get-RunnerObservabilityInventory`
- `Assert-RunnerObservabilityInventoryGate`
- `New-RunnerObservabilityTokenFile`
- `Set-RunnerObservabilityFileAcl`
- `Set-RunnerObservabilityDirectoryAcl`
- `Set-RunnerObservabilityRuntimeAcl`
- `Set-RunnerObservabilityHostsMapping`
- `Set-RunnerObservabilityMachineEnvironment`
- `Wait-RunnerObservabilityServiceState`
- `Assert-RunnerObservabilityServiceAbsent`
- `Invoke-RunnerObservabilityServiceAction`

- [ ] **Step 1: Write failing static and behavior-contract tests**

  Assert that the module contains read-only inventory fields, `current-release.txt` classification, `monitor.key` rejection, `Read-Host -AsSecureString`, `RandomNumberGenerator`, `icacls`, `SetEnvironmentVariable(..., 'Machine')`, exact hosts hostname handling, and bounded service-state polling. Assert that forbidden output terms include `--token `, `Bearer <value>`, `monitor.key` copying, and `FullControl` grants to the service account.

- [ ] **Step 2: Run the targeted tests and verify the new contract fails**

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_onboarding_scripts -v
  ```

- [ ] **Step 3: Implement the shared module**

  Keep all native command failures mapped to stable reason codes. Inventory must report host, Python, machine configuration presence, candidate roots, release state, secret-file existence, matching services, and Runner process presence without printing secret contents. Use a cryptographically random 32-byte token encoded as URL-safe text, write it atomically, and ACL it for SYSTEM, Administrators, and the selected service account only. Use read/execute ACLs for runtimes and modify ACLs only for state/database directories. Make hosts updates idempotent and require an explicit `-AllowHostsChange` gate.

- [ ] **Step 4: Run targeted tests and verify they pass**

  Run the new test module and confirm the module text and redaction assertions pass.

- [ ] **Step 5: Commit the shared module**

  ```powershell
  git add scripts/RunnerObservability.Bootstrap.psm1 tests/test_onboarding_scripts.py
  git commit -m "feat: add Windows onboarding bootstrap helpers"
  ```

### Task 3: Harden both existing service adapters

**Files:**
- Modify: `scripts/RunnerObservability.Service.psm1`
- Modify: `scripts/RunnerHeartbeat.Service.psm1`
- Modify: `scripts/Install-RunnerObservabilityService.ps1`
- Modify: `scripts/Install-RunnerHeartbeatService.ps1`
- Test: `tests/test_service_scripts.py`
- Test: `tests/test_heartbeat_service.py`

**Interfaces:**
- Existing `Install`, `Start`, `Stop`, `Status`, `Restart`, and `Uninstall` actions remain compatible.
- `Install` fails with `service_already_exists` instead of calling `sc.exe create` over an existing service.
- Lifecycle commands wait for `Running`, `Stopped`, or `Absent` and fail with `service_state_timeout` when the bound is exceeded.

- [ ] **Step 1: Extend tests with idempotence and state-readback assertions**

  Add static assertions for service existence checks, bounded wait loops, explicit absent verification after delete, and the unchanged token-file-only service command. Add Python tests for the existing `WindowsScServiceLifecycle` seam where a command reports success but state remains transitional.

- [ ] **Step 2: Run service tests and verify the new assertions fail**

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_service_scripts tests.test_heartbeat_service tests.test_deployment_docs.WindowsScServiceLifecycleTests -v
  ```

- [ ] **Step 3: Implement bounded service lifecycle behavior**

  Query the exact service name before install, return current state for `Status`, treat already-stopped/already-running operations as safe no-ops, and poll the actual CIM service state after each mutating SCM command. Stop before delete and verify the service is absent. Preserve the existing LocalService default and recovery configuration.

- [ ] **Step 4: Run the targeted service tests and verify they pass**

- [ ] **Step 5: Commit the lifecycle hardening**

  ```powershell
  git add scripts/RunnerObservability.Service.psm1 scripts/RunnerHeartbeat.Service.psm1 scripts/Install-RunnerObservabilityService.ps1 scripts/Install-RunnerHeartbeatService.ps1 tests/test_service_scripts.py tests/test_heartbeat_service.py
  git commit -m "fix: verify Windows service lifecycle state"
  ```

### Task 4: Build the Monitor role entry point

**Files:**
- Create: `scripts/Install-RunnerObservabilityMonitor.ps1`
- Modify: `tests/test_onboarding_scripts.py`
- Modify: `README.md`
- Modify: `docs/runbook.md`

**Interfaces:**
- Parameters: `-Action`, `-PythonPath`, `-ConfigPath`, `-DatabasePath`, `-SecretRoot`, `-TokenPath`, `-TlsCertPath`, `-TlsKeyPath`, `-CertificateMode`, `-RunnerAddress`, `-ServiceName`, `-ServiceAccount`, `-AllowDevSelfSigned`, and `-WhatIf`.
- Actions: `Preflight`, `Install`, `RepairPermissions`, `Start`, `Stop`, `Restart`, `Status`, `Uninstall`.

- [ ] **Step 1: Add failing script-contract tests**

  Assert that the role script imports the shared module, starts with inventory, exposes all actions, supports `PublicCa`, `PrivateCa`, `SelfSigned`, and `Existing` modes, generates the token without a token parameter, uses `--token-file`, never copies `monitor.key`, and prints only paths/fingerprint/expiry/reason codes.

- [ ] **Step 2: Run the new Monitor contract tests and verify failure**

- [ ] **Step 3: Implement Monitor preflight and install**

  `Preflight` performs only inventory, path, Python import, cert/key pairing, service existence, runner-address, and ACL readiness checks. `Install` refuses an existing service, creates missing token/config/data directories atomically, applies minimal ACLs, registers the verified service, scopes the fixed Firewall rule to the supplied Runner addresses, and waits for the requested state. In explicit `SelfSigned` development/test mode, generate a 2048-bit RSA key and certificate using `CertificateRequest` when available, or the Windows PKI/native RSA fallback on older PowerShell, export the certificate as PEM, encode the RSA private parameters as PKCS#8 PEM without OpenSSL, and print only fingerprint/expiry metadata. Existing cert modes never read or print certificate contents; public/private CA modes require both operator-supplied files. If no supported Windows generation path is available, return `certificate_generation_unavailable` and do not start the service.

- [ ] **Step 4: Run Monitor contract tests and verify they pass**

- [ ] **Step 5: Commit the Monitor role entry point**

  ```powershell
  git add scripts/Install-RunnerObservabilityMonitor.ps1 tests/test_onboarding_scripts.py README.md docs/runbook.md
  git commit -m "feat: add Monitor onboarding entry point"
  ```

### Task 5: Build the Runner role entry point

**Files:**
- Create: `scripts/Install-RunnerObservabilityRunner.ps1`
- Modify: `tests/test_onboarding_scripts.py`
- Modify: `README.md`
- Modify: `docs/runbook.md`

**Interfaces:**
- Parameters: `-Action`, `-PythonPath`, `-InstallRoot`, `-Endpoint`, `-TokenPath`, `-RunnerId`, `-StatePath`, `-MonitorHost`, `-MonitorIp`, `-CertificateTrustModel`, `-MonitorCertificatePath`, `-ExpectedCertificateSha256`, `-ImportCertificate`, `-AllowHostsChange`, `-RunnerAccount`, `-ServiceAccount`, `-ServiceName`, and `-AllowInsecureHttp`.
- Actions: `Preflight`, `Configure`, `RepairPermissions`, `Start`, `Stop`, `Restart`, `Status`, `Uninstall`.

- [ ] **Step 1: Add failing Runner contract tests**

  Assert that the script requires an endpoint and verified IP for mutation, rejects `<monitor-host>` and invalid octets, classifies an existing current release without staging over it, creates/validates local `runner-id.txt`, supports secure-string token input and existing token paths, imports certificates only for private/self-signed modes after fingerprint verification, refuses `monitor.key`, updates machine environment only after preflight, and configures the Heartbeat service with a config path rather than token value.

- [ ] **Step 2: Run the Runner contract tests and verify failure**

- [ ] **Step 3: Implement Runner preflight and configure flow**

  Run inventory first. For a new root, create the root and stable identity; for an existing managed root, read and preserve the active release and identity. Write only the non-secret heartbeat config atomically, grant LocalService read/execute access to the confirmed Python/package paths and modify access to state/identity directories, optionally apply one confirmed hosts mapping, then persist machine environment values and read them back. Use `Read-Host -AsSecureString` only when the operator selected interactive token input; do not support a `-Token` parameter.

- [ ] **Step 4: Run Runner contract tests and verify they pass**

- [ ] **Step 5: Commit the Runner role entry point**

  ```powershell
  git add scripts/Install-RunnerObservabilityRunner.ps1 tests/test_onboarding_scripts.py README.md docs/runbook.md
  git commit -m "feat: add Runner onboarding entry point"
  ```

### Task 6: Add direct Windows verification and repair the operator documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/runbook.md`
- Modify: `tests/test_onboarding_scripts.py`
- Create: `docs/issue-16-verification.md`

- [ ] **Step 1: Add documentation-shape tests**

  Require the docs to show the exact Monitor-first then Runner order, inventory-before-change rule, commands for `Preflight`, `Install`/`Configure`, `Status`, `Stop`, `Start`, `Restart`, `Uninstall`, service-state verification, hosts/certificate trust choices, ACL repair, token safety, and the handoff to live acceptance issues.

- [ ] **Step 2: Run documentation tests and verify the new contract fails**

- [ ] **Step 3: Document executable commands**

  Include commands that can be pasted into an elevated PowerShell prompt without placing secrets on the command line, for example:

  ```powershell
  .\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Preflight -PythonPath $python -ConfigPath $config -DatabasePath $database -SecretRoot $secretRoot -TlsCertPath $cert -TlsKeyPath $key -RunnerAddress $runnerIp
  .\scripts\Install-RunnerObservabilityMonitor.ps1 -Action Status -ServiceName $serviceName
  .\scripts\Install-RunnerObservabilityRunner.ps1 -Action Preflight -PythonPath $python -InstallRoot $installRoot -Endpoint $endpoint -TokenPath $tokenPath -MonitorHost $monitorHost -MonitorIp $monitorIp
  .\scripts\Install-RunnerObservabilityRunner.ps1 -Action Configure -AllowHostsChange -CertificateTrustModel PrivateCa -MonitorCertificatePath $runnerCert
  .\scripts\Install-RunnerObservabilityRunner.ps1 -Action Status
  ```

  State explicitly that a successful local test suite is not live evidence; the user must first run Monitor verification, then Runner verification, then one real CI job and dashboard association check.

- [ ] **Step 4: Run documentation tests and verify they pass**

- [ ] **Step 5: Commit the documentation/evidence template**

  ```powershell
  git add README.md docs/runbook.md docs/issue-16-verification.md tests/test_onboarding_scripts.py
  git commit -m "docs: add issue 16 host verification workflow"
  ```

### Task 7: Run verification and record issue evidence

**Files:**
- Modify: `docs/issue-16-verification.md`
- Modify: issue 16 body after local evidence is available

- [ ] **Step 1: Run the issue-16 targeted tests**

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_onboarding tests.test_onboarding_scripts tests.test_service_scripts tests.test_heartbeat_service -v
  ```

- [ ] **Step 2: Run the full suite and capture the fresh result**

  ```powershell
  python -m unittest discover -s tests -v
  ```

  Record the exact count and distinguish any remaining pre-existing failure from issue-16 failures; do not report the suite as passing while the baseline failure remains.

- [ ] **Step 3: Run PowerShell parser and read-only preflight checks**

  ```powershell
  Get-ChildItem scripts\Install-RunnerObservabilityMonitor.ps1, scripts\Install-RunnerObservabilityRunner.ps1 | ForEach-Object { [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null) | Out-Null }
  ```

  Run both role scripts with `-Action Preflight` on this Monitor Host only after confirming their parameters; do not install/restart the existing Monitor service automatically.

- [ ] **Step 4: Update issue 16 Verification with actual local evidence**

  Keep Project `In Progress` until the user completes live Monitor/Runner acceptance. Include the fresh local command, test count, parser result, and the known baseline failure without claiming production readiness.

- [ ] **Step 5: Re-read issue and Project state**

  Verify the assignee, open state, `In Progress` Project state, and formatted body before reporting implementation handoff. Do not close issue 16 until the user supplies real Monitor and Runner evidence.
