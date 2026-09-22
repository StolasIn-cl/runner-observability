# Runner and Monitor Onboarding Automation Design

## Status

Approved in conversation on 2026-09-22 for issue #16. The operator will
validate the Monitor Host first and then validate a real Runner.

## Goal

Provide two executable, role-specific PowerShell entry points that turn the
current README/runbook fragments into a repeatable Windows onboarding and
service-lifecycle workflow. The scripts must stop at a read-only inventory gate,
emit only stable redacted reason codes, and require explicit operator choices
for secret transfer, certificate trust, hosts-file edits, machine environment
changes, and destructive cleanup.

## Non-goals

- No dashboard, schema, ingest, or event-projection changes.
- No automatic cross-host secret transfer.
- No production CA issuance or trust decision made by the scripts.
- No arbitrary hosts-file replacement.
- No default deletion of releases, `runner-id.txt`, heartbeat state, token,
  private key, or database.

## Role boundaries

### Monitor Host

`scripts/Install-RunnerObservabilityMonitor.ps1` is the Monitor entry point.
It supports `Preflight`, `Install`, `RepairPermissions`, `Start`, `Stop`,
`Restart`, `Status`, and `Uninstall`. It owns token generation, protected
Monitor config/database directories, TLS certificate/key references, the
Monitor Windows Service, and the inbound Firewall rule. It never sends a
private key or token to a Runner. A clean secret/config/data layout is a
supported starting point: the script creates missing directories and can
generate a development/test self-signed PEM certificate and PKCS#8 PEM key
with Windows/.NET cryptography APIs, without requiring OpenSSL. Public-CA and
private-CA modes require operator-supplied certificate/key files and do not
silently replace them.

### Runner Host

`scripts/Install-RunnerObservabilityRunner.ps1` is the Runner entry point. It
supports the same lifecycle actions for `RunnerObservabilityHeartbeat` plus
`Preflight`, `Configure`, and `RepairPermissions`. It verifies the confirmed
machine paths before changing anything, creates a local stable `runner-id.txt`
only when absent, accepts a token already transferred to the Runner or reads a
token interactively with `Read-Host -AsSecureString`, and never accepts a token
value as a command-line parameter. A public certificate is copied/imported only
for an explicitly selected private-CA or self-signed trust model and only
after a caller-supplied fingerprint check. The script rejects
`monitor.key`, placeholder IPs, conflicting hosts entries, and an install root
whose state cannot be classified as new or an existing managed install.

## Shared implementation

`scripts/RunnerObservability.Bootstrap.psm1` owns the cross-role seams:

- read-only host/install/service inventory;
- managed install-root classification (`new`, `existing`, or
  `inspect-before-use`);
- stable reason-code failures and redacted output;
- cryptographically random token-file creation and secret ACLs;
- exact IPv4 validation and idempotent `monitor-test.local` hosts mapping;
- machine environment updates with readback;
- minimum read/execute versus modify ACL helpers;
- service existence checks and bounded wait-for-state operations.

The existing Monitor and Heartbeat service modules remain role-specific
adapters. Their lifecycle actions use the shared wait/existence behavior so
`sc.exe` returning success is not treated as proof that the service reached the
requested state.

## Safety and idempotency contract

1. Every mutating action starts by running the same inventory and rechecking
   the target paths/service names supplied by the operator.
2. A pre-existing service causes `Install` to stop with a stable
   `service_already_exists` reason; `RepairPermissions` or lifecycle actions
   are the explicit alternatives.
3. A managed install root with `current-release.txt` is classified as an
   existing installation and is never treated as a first-install staging area.
   A non-empty root without a valid pointer is rejected.
4. Hosts updates preserve unrelated lines, keep one mapping for the selected
   hostname, and refuse a conflicting existing mapping unless the operator
   explicitly chooses a reviewed replacement action.
5. Uninstall removes only the named service and its owned Firewall rule by
   default. Persistent secrets, releases, identity, state, config, and data
   remain available for rollback and diagnosis.
6. All output excludes token values, private-key material, certificate content,
   raw exception text, command-line secrets, and absolute secret paths.
7. `SelfSigned` generation is explicit development/test behavior and writes
   only the generated files plus redacted fingerprint/expiry metadata. If the
   host lacks the required Windows/.NET certificate API, the script fails with
   a stable reason instead of falling back to an external command or silently
   serving plain HTTP.

## Verification seams

The public seams under test are:

- the Python pure validation helpers for install-state classification, IPv4 /
  placeholder rejection, hosts-file update behavior, certificate trust-mode
  rules, and redacted reason-code formatting;
- the PowerShell script/module contract for role separation, lifecycle actions,
  token-safe command construction, ACL intent, and inventory-before-mutation;
- direct `Preflight` execution on Windows PowerShell 5.1+/PowerShell 7 and a
  real Monitor Host install/lifecycle smoke test;
- a subsequent real Runner `Preflight`/configuration/Heartbeat service smoke
  test. Real CI and dashboard acceptance remains with #10–#13 and #6.

The current baseline has one unrelated deployment smoke failure. The new tests
must identify the issue-16 behavior independently and must not weaken or hide
that baseline failure.
