# Runner observability

This repository contains a local, fail-open telemetry monitor for self-hosted
CI runners. It uses Python 3.11+ and the standard library only.

## Schema-v1 boundary

`runner_observability.contracts.validate_event(payload)` is the only allowed
input boundary for later HTTP and SQLite layers. It returns an immutable
`ValidatedEvent` only for complete `schema_version: 1` envelopes. The monitor,
not the sender, owns `received_at`.

Approved event types are `runner.heartbeat`, `runner.offline`, `job.started`,
`job.heartbeat`, `job.finished`, `job.progress`, and `job.fallback`. Generic
job events require the complete stable job key: repository, workflow run ID,
run attempt, and job ID. A supplied Actions run URL is validated and passed
through; this monitor does not query GitHub or construct run URLs.

The validator is closed-world: unknown fields and event types are rejected,
as are oversized inputs and credential-bearing, raw-log, environment, command,
absolute-path, PR-text, individual test/group, or raw fallback reason fields.
Rejections expose only stable reason codes, never input values.

Run the current contract suite with:

```powershell
$env:PYTHONPATH='src'
python -m unittest discover -s tests -v
```

## Running the monitor (`serve`)

```powershell
$env:PYTHONPATH='src'
python -m runner_observability serve --token <token> --database <path>
```

By default this serves plain HTTP, exactly as before issue #7. To serve
real HTTPS instead, pass a matching certificate and private key pair:

```powershell
python -m runner_observability serve --token <token> --database <path> `
    --tls-cert <path\to\tls-cert.pem> --tls-key <path\to\tls-key.pem>
```

For Windows Service startup, keep the bearer credential in an ACL-protected
file and use the service host's `--token-file` path boundary. The service
command line contains the config/token file paths, never the token value:

```powershell
python -m runner_observability serve --token-file <path\to\token.txt> --database <path>
```

Install and manage the SCM service with
`scripts/Install-RunnerObservabilityService.ps1`; it also applies the
service-file ACLs and the fixed Runner-address Firewall rule. Use
`-ServiceName` on `scripts/Update-RunnerObservability.ps1` to include service
stop/start in a pinned release update and rollback. The scripts' local
contract tests do not claim that a real host, reboot, effective Firewall, or
production-ready decision has been observed; those facts belong to issue #6.

`--tls-cert`/`--tls-key` are optional, stdlib-`ssl`-only (no third-party
TLS dependency), and must be provided as a pair -- supplying only one is a
controlled, redacted error and the monitor never starts serving. A
certificate/key that cannot be loaded (missing file, malformed content, a
mismatched key) is also a controlled, redacted error; the configured path,
file contents, and the underlying `ssl`/`OSError` exception text are never
included in any diagnostic. See "Native TLS/HTTPS support" below and
`docs/runbook.md` for the full contract.

### Native TLS/HTTPS support (issue #7)

Before this ticket, `create_server()` always built a plain
`ThreadingHTTPServer` -- the "TLS certificate" preflight check below only
ever confirmed a cert *file* existed on disk, never that the Monitor Host
would actually use it to encrypt traffic. `create_server()` (and the
`serve --tls-cert`/`--tls-key` flags above) now wrap the server's
listening socket with a real `ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)`
when both are supplied, using only the Python 3.11 standard library `ssl`
module -- no third-party TLS/certificate dependency. Omitting both
arguments keeps today's plain-HTTP behavior completely unchanged, which is
what the full test suite and the Local Verification Gate below continue to
exercise. This closes the gap between PERS-04's original plan ("Monitor
Host 採 HTTPS/TLS") and what the code actually did.

## Local Verification Gate (issue #5)

`scripts/Invoke-VerificationGate.ps1` is a thin PowerShell wrapper around
`runner_observability.gate`, which (1) runs the complete unittest suite
above, (2) runs a set of isolated fault drills -- monitor restart-and-
recover, runner/job offline-then-recovery, and injected SQLite/cleanup/
notification failures -- each against its own fresh, throwaway temp-file
SQLite database, never any shared or named database file, and (3) writes a
redacted Markdown evidence report (`gate-report.md` by default; regenerated
per run and git-ignored, since its timestamp changes every time).

```powershell
./scripts/Invoke-VerificationGate.ps1
```

**This gate is 100% runner-independent.** It never opens a socket to a real
host, never assumes a Monitor Host or Runner A/B exists, and its report is
always stamped `status: not-ready`. Local drills passing is necessary but not
sufficient for production; it is not real-hardware, TLS/auth/firewall, or
real-workflow-acceptance evidence.

### Local Gate results (most recent observed local run)

```
## Automated gate (full local suite)
- result: PASS
- tests_run: 105
- failures: 0
- errors: 0

## Isolated fault drills
- monitor_restart_recovery: PASS
- offline_recovery: PASS
- sqlite_integrity_failure_isolated: PASS (integrity_check_failed)
- cleanup_failure_isolated: PASS (cleanup_failed)
- notification_failure_isolated: PASS

## Fail-open contract
- fail_open_contract: PASS

Overall local gate result: PASS (status remains `not-ready`)
```

This is a snapshot of one real local run's own output, copied here as
observed evidence; the authoritative, freshly timestamped report is always
regenerated by running the script above, not by trusting this copy.

### Known limitations

- No Monitor Host, Runner A, or Runner B deployment evidence exists yet.
- No real, trusted-CA TLS certificate issuance, authentication against a
  real endpoint, or real firewall configuration has been exercised. The
  monitor itself can now serve genuine HTTPS locally (issue #7, see
  "Native TLS/HTTPS support" above) -- what remains issue #6's job is
  issuing/trusting a real certificate and exercising it against real
  hardware, not the encryption mechanism itself.
- No real GitHub Actions workflow acceptance has been observed.
- This gate cannot and does not produce a production-ready decision.

### Handoff to issue #6 (HITL)

Issue #6 is the only place real-hardware deployment, TLS/auth/firewall
configuration, real-workflow acceptance, and the production-ready decision
may be recorded, using `docs/canary-evidence-template.md` as the evidence
skeleton. This repository's automated tests may validate that template's
document shape only; they never assert that its deployment/acceptance facts
occurred.

**Next operator action:** open issue #6 and run its HITL deployment and
acceptance checklist against a real Monitor Host, Runner A, and Runner B,
recording results directly in `docs/canary-evidence-template.md`.

## Local Deployment Simulation (issue #4 gap closure)

`scripts/Install-RunnerObservability.ps1`,
`scripts/Update-RunnerObservability.ps1`, and
`scripts/Invoke-RunnerPreflight.ps1` implement and exercise the
install/upgrade/rollback **contract** required by issue #4 (PERS-04)'s own
verification table: a pinned revision, a preflight check battery
(Python version, TLS certificate file presence -- optionally strengthened
into a real, local `SSLContext` load when `-TlsKeyPath` is also supplied,
see issue #7 -- auth credential file presence, firewall, Monitor Host
reachability), an atomic activation
switch, a post-activation smoke test, and automatic rollback to the
previous version on any failure. The substantive logic lives in
`src/runner_observability/deploy.py` (unit-tested in
`tests/test_deployment_docs.py`), with the PowerShell scripts as thin
orchestration -- the same split already used for the Local Verification
Gate's `gate.py` / `Invoke-VerificationGate.ps1`.

```powershell
./scripts/Invoke-RunnerPreflight.ps1 -TlsCertPath <path> -TlsKeyPath <path> -AuthTokenPath <path>
./scripts/Install-RunnerObservability.ps1 -Revision <rev> -Source <dir> -InstallRoot <dir>
./scripts/Update-RunnerObservability.ps1 -Revision <rev> -Source <dir> -InstallRoot <dir>
```

**This is 100% runner-independent local simulation**, proven against local
fixture directories and injected/mocked checks -- it never installs a real
Windows Service, never issues or trusts a real TLS certificate, never
configures a real firewall rule, and never opens a real network socket on
its own. The `-FirewallResult`/`-HostReachableResult` parameters only let
an operator pass through a result already determined out of band; omitting
them leaves those two checks unconfigured (fail-closed, not a silent real
network call). Full install/upgrade/rollback/first-triage instructions for
a different operator, without this ticket, are in `docs/runbook.md`. Real
Monitor Host / Runner A / Runner B deployment, real TLS/auth/firewall
configuration, and the production-ready decision remain issue #6 (HITL)'s
responsibility, exactly as for the Local Verification Gate above.
