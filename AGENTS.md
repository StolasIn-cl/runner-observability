# Runner observability operating rules

This repository is used on more than one Windows computer. Treat every
installation command as machine-specific. The first action on a target host
is always a read-only inventory; installation, certificate import, environment
variable changes, and service restarts come only after the inventory identifies
the current state.

## Required reading and order

1. Read [`CONTEXT.md`](CONTEXT.md) for the last known deployment snapshot and
   the recommended paths. It is a reference, not proof of the current state.
2. Run the **Step 0 inventory** in [`README.md`](README.md) on the actual
   target machine. Save or paste its output before changing anything.
3. Compare the result with `CONTEXT.md`. If the machine, user, runner root,
   install root, release pointer, endpoint, or service model differs, update
   the plan for that machine before issuing a mutating command.
4. Choose exactly one path: new install, existing-install update, or
   troubleshooting. Never run first-install commands against a non-empty
   managed install root.
5. Make one change, verify it, and only then continue to the next change.

## Safety rules

- Treat `C:\actions-runner`, `C:\runner-observability-agent`, and
  `C:\runner-observability-secrets` as current conventions, not universal
  facts. Confirm each with `Test-Path` and the machine environment variables.
- An existing `current-release.txt` means the Runner already has a managed
  agent installation. Use the update procedure and preserve the active
  release; do not repeat first-install staging.
- Keep `monitor-token.txt` outside the repository, workspace, logs, command
  history, and CI artifacts. Do not print its contents or include the token in
  a command line.
- Keep `monitor.key` on the Monitor Host only. Never copy the private key to a
  Runner. A Runner may receive `monitor.crt` only when the certificate trust
  procedure requires it; the Python agent uses the operating system's default
  trust store, not an arbitrary certificate file next to the token.
- Treat `C:\Windows\System32\drivers\etc\hosts` as a machine-specific,
  mutating configuration file. Inspect it before editing, use the confirmed
  Monitor IP, keep one `monitor-test.local` mapping, and verify DNS/port 8765
  afterwards. A placeholder IP is documentation only.
- Do not copy `runner-id.txt` or heartbeat state from another Runner. The CI
  helper creates a stable identity under the local install root on first use.
- A machine environment-variable change affects newly started processes. If
  the GitHub Actions listener was already running, restart that listener once
  after configuration. A full Windows reboot is unnecessary.
- Restart only a service whose exact name was found by inventory. The known
  Runner machines currently run `Runner.Listener.exe` directly and have no
  matching observability service; do not invent a service name.
- The monitor process/service must be restarted after deploying monitor Python
  or static dashboard files. A Runner restart is not required for a dashboard
  deployment alone.

## Branch-specific guidance

### New Runner

Follow README sections **Step 0**, **Step 1**, and **Step 2** in order. Stop
if the install root or release pointer already exists. Decide whether the
certificate is publicly trusted or private/self-signed before copying any
certificate file. Finish with one real CI job and the verification checklist.

### Existing Runner update

Run inventory first. Keep the current release available for rollback, stage a
new immutable revision, activate it only after the local import smoke test,
then run one real CI job. Do not overwrite the active release in place.

### Troubleshooting

Start with the actual process environment, not the machine environment alone:

```powershell
Get-CimInstance Win32_Process -Filter "Name = 'Runner.Listener.exe'" |
    Select-Object ProcessId, ParentProcessId, ExecutablePath,
        @{Name='CommandLine'; Expression={
            ([string]$_.CommandLine) `
                -replace '(?i)(--token\s+)\S+', '$1<redacted>' `
                -replace '(?i)(Bearer\s+)\S+', '$1<redacted>'
        }}

Get-ChildItem Env:RUNNER_OBSERVABILITY_* -ErrorAction SilentlyContinue |
    Select-Object Name, Value
```

If the process environment is empty or stale, restart the verified Runner
listener using its actual launch method. Then check the release pointer,
token-file existence, endpoint spelling, TLS trust, and the monitor's ingest
logs/dashboard. Do not delete database rows or `runner-id.txt` as a first
diagnostic action.

## Completion criteria

An onboarding or update is complete only when all of these are true:

- the inventory identifies the intended machine and existing-state decision;
- exactly one active release is named by `current-release.txt`;
- the token file exists at the verified path and its contents were never
  printed;
- the Runner process was started after machine environment variables were set;
- one real CI job produced telemetry;
- the dashboard shows the physical Runner as active and associates rebuild
  progress with the correct job;
- no unrelated files, services, certificates, or database rows were changed.
