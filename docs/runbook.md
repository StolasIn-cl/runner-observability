# Runner observability -- operator runbook

This is the single document an operator needs to install, update, roll
back, and perform first triage of the local, fail-open telemetry monitor
for self-hosted CI runners -- without reading the original design ticket or
implementation plan.

## Scope: what this runbook covers, and what it explicitly does not

This runbook and the scripts it describes
(`scripts/Install-RunnerObservability.ps1`,
`scripts/Update-RunnerObservability.ps1`,
`scripts/Invoke-RunnerPreflight.ps1`) implement and exercise the
**deployment/rollback contract** only: pinned-revision installs, a
preflight check battery, an atomic activation switch, a post-activation
smoke test, and automatic rollback on failure. Every one of those has been
proven against local fixture directories and injected/mocked checks (see
`tests/test_deployment_docs.py`); none of it has ever opened a socket to a
real host, touched a real certificate store, or called a real Windows
Service or firewall API.

Real production deployment work is explicitly **issue #6's responsibility,
and has not happened as part of this task**:

- Installing and starting a real Windows Service (Monitor Host or a
  runner agent) has **not** been done here.
- Issuing or trusting a real TLS certificate has **not** been done here.
- Configuring a real Windows Firewall rule has **not** been done here.
- Deploying to a real Monitor Host, Runner A, or Runner B has **not** been
  done here.
- Running a real GitHub Actions workflow end to end against a live
  deployment has **not** been done here.

If you are looking for that evidence, it belongs in
`docs/canary-evidence-template.md`, filled in only by a human operator
running the real issue #6 HITL checklist against real hardware -- not by
any script or test in this repository.

## Prerequisites

- Python 3.11 or newer on the target host (`python --version`). Nothing in
  this repository requires third-party packages.
- PowerShell 5.1 or newer (Windows built-in `powershell.exe` is fine).
- A built copy of this repository (or a specific pinned revision's
  contents) available as a local source directory to install from. This
  runbook does not describe how you obtained that copy (git clone,
  artifact download, etc.) -- only what to do with it once you have it
  locally.
- A place to install to (`-InstallRoot`): an empty or already-managed
  directory this runbook's scripts own. Do not point it at a directory
  with unrelated content; `Update-RunnerObservability.ps1` only manages
  what it created.

## Concepts: pinned revisions, releases, and the atomic switch

- Every install/update names an explicit **pinned revision** (a version
  tag or commit-ish string, e.g. `1.4.0` or a short commit hash) -- never
  `latest` or any other floating reference you did not choose yourself.
- Each revision's files are copied into
  `<InstallRoot>\releases\<revision>\` (**staged**). Staging never deletes
  any other revision's directory, which is what makes rollback possible.
  Old release directories accumulate; disk cleanup of unused old releases
  is a manual operator decision, not something these scripts do
  automatically.
- Exactly one revision is **active** at a time, recorded in a single
  plain-text pointer file, `<InstallRoot>\current-release.txt`. Switching
  which revision is active is **atomic**: the new pointer content is
  written to a temporary file in the same directory and then swapped in
  with a single rename, so a crash mid-switch can never leave the pointer
  half-written -- it always reads either the old revision or the new one,
  never a mix.

## Install (first-time setup)

Run from an elevated PowerShell prompt if the target install directory
requires elevated permissions to create; the scripts themselves do not
require elevation on their own.

```powershell
./scripts/Install-RunnerObservability.ps1 `
    -Revision "1.0.0" `
    -Source "C:\path\to\built\1.0.0" `
    -InstallRoot "C:\runner-observability" `
    -TlsCertPath "C:\path\to\tls-cert.pem" `
    -TlsKeyPath "C:\path\to\tls-key.pem" `
    -AuthTokenPath "C:\path\to\auth-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

All four of `-TlsCertPath`, `-AuthTokenPath`, `-FirewallResult`, and
`-HostReachableResult` are **required for this command to get past
preflight** -- the preflight battery below has five checks, and omitting
any of these four leaves the corresponding check unconfigured, which fails
closed (see "Preflight checks" below). `-TlsCertPath`/`-AuthTokenPath` must
point at real files that already exist locally; `-FirewallResult` and
`-HostReachableResult` must be the outcome of a real check an operator (or
an issue #6 process) already performed out of band for the actual target
environment -- these two flags never trigger a real check themselves, they
only pass through a result you already have. `-TlsKeyPath` is optional but
strongly recommended (see "Preflight checks" below): without it, the TLS
check only proves a cert *file* is present, not that it is a real,
loadable certificate that will actually be used for encryption.

What this does:

1. Runs the full preflight check battery (see "Preflight checks" below).
   If any check fails, installation stops before anything is written to
   `-InstallRoot`, and the script prints only the stable diagnostic
   reason(s) -- never a raw exception, a file path, or a credential value.
2. Stages the revision's files under
   `<InstallRoot>\releases\1.0.0\`.
3. Atomically activates it (`current-release.txt` now reads `1.0.0`).
4. Runs a local smoke test: invokes the newly staged release's own CLI
   entrypoint (`python -m runner_observability --help`) to confirm it
   imports and runs cleanly. This does **not** start a real Windows
   Service and does **not** open any socket.
5. If the smoke test fails, the install is rolled back: since this was a
   first install, there is no previous revision to restore, so
   `current-release.txt` is removed and the install ends in a clean,
   "nothing active" state rather than a half-installed one. Re-run after
   fixing the underlying issue.

Starting the monitor itself (once you trust the installed revision) uses
the same CLI surface documented in `README.md`:

```powershell
python -m runner_observability serve --token <token> --database <path> `
    --tls-cert <path\to\tls-cert.pem> --tls-key <path\to\tls-key.pem>
```

`--tls-cert`/`--tls-key` are optional but must be given as a pair --
supplying only one is a controlled, redacted error and the monitor never
starts. Omitting both (as in `docs/canary-evidence-template.md`-free local
testing and the Local Verification Gate) keeps the monitor on plain HTTP,
exactly as before this ticket. When both are given, the monitor wraps its
listening socket with a real `ssl.SSLContext` and serves genuine HTTPS --
this is the actual encryption boundary; the preflight "TLS certificate"
check (see "Preflight checks" below, even in its strengthened form) only
ever predicts whether this step *will* succeed, it never substitutes for
it.

or, to send one event (the fail-open agent path):

```powershell
python -m runner_observability emit --endpoint <url> --token <token> --event-json <json>
```

This runbook does not repeat the full schema/CLI reference; see
`README.md`'s "Schema-v1 boundary" section for that.

## Runner canary script (issue #6, using issue #7 HTTPS)

After issue #7, the monitor can serve genuine HTTPS when it is started with
`--tls-cert` and `--tls-key`. The canary script therefore requires an
`https://` endpoint by default and relies on the Runner's normal Windows
certificate trust store. It reads the bearer token from a file, never places
the token in the PowerShell command line, and keeps its producer epoch and
next sequence in `%LOCALAPPDATA%\RunnerObservability\canary-state.json`.

Pull the repository on the Runner, then run these commands from its root:

```powershell
git pull --ff-only
python --version
$runnerId = "<runner-uuid>"
$monitor = "https://<monitor-host>:8765"
$tokenFile = "C:\secure\runner-observability-token.txt"

.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode Smoke `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile
```

Expected result: one `[PASS]` line. If the Monitor Host is intentionally
plain HTTP for a local-only test, add `-AllowInsecureHttp`; do not use that
switch for the issue #6 HTTPS evidence.

Run the remaining checks in this order:

1. `Smoke`: confirms Runner-to-Monitor HTTPS, authentication, event ingest,
   and an online dashboard projection.
2. `Auth`: sends one heartbeat with an invalid token and confirms HTTP 401,
   then sends a valid heartbeat and confirms the runner is online again.
3. `OfflineRecovery`: sends a baseline heartbeat, sends nothing for the
   default 601 seconds, confirms `offline` with
   `offline_reason=heartbeat_timeout`, then sends a newer heartbeat and
   confirms recovery to `online`. Stop every other heartbeat producer for
   this Runner during the wait; otherwise another producer can keep it alive.
4. `NetworkFailure`: stop the Monitor Host first, then run the command below.
   The expected result is `[PASS]` because the endpoint failure is observed
   without printing a token. Start the Monitor Host again before continuing.

```powershell
.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode Auth `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile

.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode OfflineRecovery `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile

.\scripts\Invoke-RunnerCanary.ps1 `
    -Mode NetworkFailure `
    -Endpoint $monitor `
    -RunnerId $runnerId `
    -TokenPath $tokenFile
```

For a fast, non-destructive connectivity failure check without stopping the
Monitor Host, point `-FailureEndpoint` at an unused local HTTPS port, for
example `https://127.0.0.1:1`. This checks the canary's failure observation
path; the existing Python agent tests and the manual `emit` procedure still
cover the agent's fail-open delivery behavior. If you intentionally use an
HTTP failure endpoint, add `-AllowInsecureHttp` explicitly.

Use the default `runner-canary` producer id. Do not run this script with the
same `-ProducerId` as a live agent at the same time, because producer
sequence ordering is intentionally monotonic per producer epoch. The state
file must not contain a token and should stay local to the Runner; do not
copy one Runner's state file to another Runner.

## Update (upgrading an existing install)

```powershell
./scripts/Update-RunnerObservability.ps1 `
    -Revision "1.1.0" `
    -Source "C:\path\to\built\1.1.0" `
    -InstallRoot "C:\runner-observability" `
    -TlsCertPath "C:\path\to\tls-cert.pem" `
    -TlsKeyPath "C:\path\to\tls-key.pem" `
    -AuthTokenPath "C:\path\to\auth-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

As with install above, all four of `-TlsCertPath`, `-AuthTokenPath`,
`-FirewallResult`, and `-HostReachableResult` are required for this command
to get past preflight.

Same sequence as install, with one difference: because a previous revision
is already active, any failure -- preflight, or the post-activation smoke
test -- **retains the previous version as active**. The upgrade attempt
leaves `current-release.txt` reading the old revision, unchanged, and
prints the stable failure reason. This is repeatable: re-running a still-
failing update reaches the same safe "previous version still active"
state every time, never a partially-switched or corrupted one.

This automatic rollback depends on the previous revision's staged files
still being present under `<InstallRoot>\releases\<previous-revision>\`.
If that directory has been manually removed (see "Old release directories"
under Rollback below), a failed update cannot restore it; the script
deactivates instead of leaving the broken new revision active, and prints
the distinct `rollback_target_missing` reason so you know manual recovery
(re-staging the previous revision, or fixing and retrying the new one) is
needed.

## Rollback

Rollback is not a separate script -- it is the automatic, guaranteed
outcome of any failed `Update-RunnerObservability.ps1` run (see above). If
you need to manually revert to a specific earlier revision that is still
staged on disk (e.g. after successfully upgrading to a revision you now
want to back out of for an unrelated reason), re-run
`Update-RunnerObservability.ps1` with `-Revision` set back to the earlier
revision and the matching `-Source` for it. The atomic-switch and smoke-
test/rollback contract applies identically in that direction.

Old release directories under `<InstallRoot>\releases\` are never deleted
automatically, specifically so a previously active revision stays
available for exactly this kind of manual rollback. **Do not manually
delete the directory for the currently-active (or most recently active)
revision** -- if you prune it and a later update then fails, automatic
rollback has nothing to restore and will deactivate instead of recovering
the previous version (see `rollback_target_missing` in "First triage"
below). Pruning older, no-longer-relevant release directories once you no
longer need to roll back to them is fine.

## Preflight checks

`Invoke-RunnerPreflight.ps1` (also run automatically as the first step of
install/update) runs a fixed battery of checks and reports only a stable,
actionable diagnostic per check -- never a raw exception, traceback, or
secret value:

| Check | What it confirms | Failure diagnostic |
| --- | --- | --- |
| Python version | The local Python interpreter meets the minimum supported version (3.11) | `unsupported_python_version` |
| TLS certificate | Without `-TlsKeyPath`: only that a certificate file is configured and present on disk (its contents are never read) -- this does **not** prove the file is a valid certificate or that it will ever actually be used for encryption. With `-TlsKeyPath` also supplied, this check is strengthened: it attempts to load the pair into a real `ssl.SSLContext` (`load_cert_chain`), the exact call the monitor's `serve --tls-cert/--tls-key` makes to actually turn on HTTPS -- proving the file is a loadable certificate whose key really matches it, without ever starting a server or opening a socket | `tls_certificate_file_missing` (no cert configured, or the file is missing/empty), or, only when `-TlsKeyPath` was supplied, `tls_certificate_invalid` (the pair failed to load: missing/unreadable key, malformed content, or a mismatched key) |
| Auth credential | A credential/token file is configured and present on disk (its contents are never read) | `auth_credential_file_missing` |
| Firewall | The ingest port is reachable through the local firewall configuration, via an operator-supplied check | `firewall_check_not_configured` (no check wired up) or `firewall_port_blocked` (checked and blocked) |
| Host reachability | The target Monitor Host responds, retried up to 3 times with a short pause between attempts -- never retried indefinitely | `host_reachability_check_not_configured` (no check wired up) or `monitor_host_unreachable` (retried and still unreachable) |

All five checks must pass before `Install-RunnerObservability.ps1` or
`Update-RunnerObservability.ps1` will write anything -- there is no
"skip the firewall/host check" mode. Two of these checks (firewall, host
reachability) require the operator to supply a real check for the actual
target environment via `-FirewallResult`/`-HostReachableResult`; this
repository intentionally ships no default that reaches out over a real
network on its own, so **omitting either flag is a hard block, not a
warning** -- you must determine that result out of band (a real firewall
rule check, a real ping/connect to the Monitor Host, etc.) and pass it in
explicitly. Wiring up those real checks for a specific Monitor Host, TLS
issuance and trust, real Windows Firewall rules, and real Windows Service
installation/credentials are all issue #6 (HITL) responsibilities -- see
the "Scope" section above.

```powershell
./scripts/Invoke-RunnerPreflight.ps1 `
    -TlsCertPath "C:\path\to\tls-cert.pem" `
    -TlsKeyPath "C:\path\to\tls-key.pem" `
    -AuthTokenPath "C:\path\to\auth-token.txt" `
    -FirewallResult Pass `
    -HostReachableResult Pass
```

## First triage

Use this table when something looks wrong. Every diagnostic named here is
a stable reason code you will see printed by the scripts above -- never a
raw exception message, stack trace, absolute path, or token value.

| Symptom / diagnostic | Likely cause | What to do |
| --- | --- | --- |
| `unsupported_python_version` | The host's Python interpreter is older than 3.11 | Install/upgrade Python 3.11+ on the target host and re-run |
| `tls_certificate_file_missing` | No cert file configured, or the configured path does not exist / is empty | Confirm `-TlsCertPath` points at a real, non-empty file. Issuing/trusting the certificate itself is issue #6's job, not this script's |
| `tls_certificate_invalid` | `-TlsKeyPath` was also supplied, and the cert/key pair could not be loaded into a real `SSLContext` -- the key file is missing/empty, the cert content is malformed, or the key does not match the certificate | Confirm `-TlsCertPath`/`-TlsKeyPath` point at a real, matching PEM certificate and private key pair (the same files you intend to pass to `serve --tls-cert`/`--tls-key`). This check never reports the file contents or which specific rule failed |
| `auth_credential_file_missing` | No credential file configured, or the configured path does not exist / is empty | Confirm `-AuthTokenPath` points at a real, non-empty file. This check never reads or reports the token's value |
| `firewall_check_not_configured` | `-FirewallResult` was omitted -- this check is **required**, not optional, for install/update to proceed | Determine the real firewall outcome for the target environment out of band and pass `-FirewallResult Pass` or `-FirewallResult Fail` explicitly. There is no way to skip this check |
| `firewall_port_blocked` | A real firewall check was wired up and reported the port is blocked | Open the ingest port for the Monitor Host per your organization's firewall change process (issue #6) |
| `host_reachability_check_not_configured` | `-HostReachableResult` was omitted -- this check is **required**, not optional, for install/update to proceed | Determine the real Monitor Host reachability outcome out of band and pass `-HostReachableResult Pass` or `-HostReachableResult Fail` explicitly. There is no way to skip this check |
| `monitor_host_unreachable` | A real reachability check was wired up and the host did not respond within 3 attempts | Confirm the Monitor Host process is running and the network path to it is up; this check never retries beyond 3 attempts, so a transient blip should simply be re-run manually |
| `service_start_failed` | **Reserved for issue #6.** No script in this repository's local simulation currently wires up a real service-start check -- the only post-activation check the real scripts run today is `smoke_test_failed` below. This reason code exists in `deploy.py`'s generic post-activation-check machinery for a future, real Windows Service start check that issue #6 may add; you will not see it from today's scripts | If you ever do see this from a modified/future script, treat it the same as `smoke_test_failed`: the previous revision has already been automatically restored (or deactivated if its directory was pruned -- see `rollback_target_missing`) |
| `smoke_test_failed` | The newly activated revision's own CLI entrypoint did not run cleanly (`python -m runner_observability --help` failed or timed out) | The previous revision (or "nothing active", on a first install) has already been automatically restored; re-run the newly staged revision's smoke test manually to investigate before retrying the update |
| `rollback_target_missing` | A post-activation check failed, but the previous revision's `releases\<revision>\` directory was manually removed, so automatic rollback could not restore it | The broken new revision has been deactivated (not left active) -- `current-release.txt` now reflects "nothing active" or the last state before this attempt. Re-stage the previous revision's files (re-run `Update-RunnerObservability.ps1` with its `-Revision`/`-Source`) to restore it, or fix and retry the new revision |
| `source_unavailable` | `-Source` does not exist, is not readable, or is otherwise unusable when staging began | Confirm `-Source` points at a real, readable local directory containing the revision's built files, then re-run |
| `install_root_unwritable` | `-InstallRoot` (or a path under it) could not be written to -- for example, insufficient permissions | Confirm you have write access to `-InstallRoot` (an elevated prompt may be required), then re-run |
| `unexpected_deploy_error` | A failure occurred that does not match any diagnostic above | Nothing is left half-written to disk, and no raw exception or path was printed. Re-run with verbose local troubleshooting (e.g. inspect `-InstallRoot` by hand) before escalating |
| Dashboard shows a runner/job as offline unexpectedly | Normal liveness behavior -- see `README.md`; not a deployment-script issue | Check the 10-minute heartbeat timeout behavior described in `README.md`, not this runbook |

If a diagnostic is not in this table, do not guess at its cause from the
name alone -- treat it as an unhandled failure and escalate; do not infer
that a deploy or rollback succeeded from a diagnostic you do not
recognize.

## Local Verification Gate vs. this runbook

Before using this runbook's install/update scripts against any real
target, `scripts/Invoke-VerificationGate.ps1` (issue #5) should already be
passing locally. That gate proves the monitor's own event/store/dashboard
logic and isolated fault recovery; it is a prerequisite, not a
replacement, for the deployment contract this runbook describes. Neither
this runbook's local install/update simulation nor issue #5's gate is
sufficient evidence for a production-ready decision -- see
`docs/canary-evidence-template.md` and issue #6.
