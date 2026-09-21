# Deployment context

This file records the last known deployment shape so an operator or agent can
choose a safe next step. It is not live discovery. Refresh it with the README
**Step 0 inventory** before changing any host. Never put token contents,
private-key contents, or bearer credentials in this file.

Last verified snapshot: 2026-09-21 (Asia/Taipei)

## Recommended path convention

Use these paths only after confirming that the target machine is new or that
the existing installation already uses them:

| Role | Recommended path | Contents |
| --- | --- | --- |
| GitHub Actions runner | `C:\actions-runner` | Runner.Listener, `_work`, runner diagnostics |
| CI observability install root | `C:\runner-observability-agent` | `current-release.txt`, `releases\<revision>\src` and local `runner-id.txt` |
| Runner secret directory | `C:\runner-observability-secrets` | `monitor-token.txt`; `monitor.crt` only when trust installation requires it |
| Windows hosts file | `%SystemRoot%\System32\drivers\etc\hosts` | Optional `monitor-test.local` to Monitor-IP mapping; verify per machine |
| Monitor source checkout | operator-chosen | Source used to start or deploy the Monitor; do not assume a Runner path |
| Monitor database | `C:\runner-observability-data\monitor.sqlite` | Monitor event store; verify before using |

The install root and secret directory are separate on purpose. A release
directory must never contain the token or private key.

## Known Runner snapshot

These values came from inventory output and are clues for comparison, not
commands to copy blindly.

| Label | Computer / account | Python | Install root | Runner root | Services |
| --- | --- | --- | --- | --- | --- |
| runner-A | `DESKTOP-3J2K2PD` / `DESKTOP-3J2K2PD\PromeoPCRunner2` | `C:\Python314\python.exe` / Python 3.14.6 | `C:\runner-observability-agent` | `C:\actions-runner` | No matching service found; `Runner.Listener.exe` running directly |
| runner-B | `PROMEORUNNER-DT` / `PROMEORUNNER-DT\RDME-PROMEOPC-GA` | `C:\Users\RDME-PROMEOPC-GA\AppData\Local\Programs\Python\Python311\python.exe` / Python 3.11.9 | `C:\runner-observability-agent` | `C:\actions-runner` | No matching service found; `Runner.Listener.exe` running directly |

Both known Runners had the following machine-level configuration at the time
of inventory:

```text
RUNNER_OBSERVABILITY_INSTALL_ROOT=C:\runner-observability-agent
RUNNER_OBSERVABILITY_TOKEN_PATH=C:\runner-observability-secrets\monitor-token.txt
```

Runner-A had the concrete endpoint:

```text
RUNNER_OBSERVABILITY_ENDPOINT=https://monitor-test.local:8765/v1/events
```

The earlier Runner-B inventory contained the placeholder
`https://<monitor-host>:8765/v1/events`; re-check it before using Runner-B as a
template. Do not copy an endpoint from this file without confirming DNS and
the actual Monitor Host.

The token file was present on both known Runners. The existence of
`monitor.crt`, `monitor.key`, and `monitor-token.txt` was confirmed in
`C:\runner-observability-secrets`; this file intentionally records no secret
contents. The Monitor private key belongs on the Monitor Host and should not
be distributed to Runners.

## Known Monitor snapshot

The current interactive start script is `src\start.ps1`. It uses:

```text
source checkout: C:\Users\stolas_in\Desktop\runner-observability
data directory: C:\runner-observability-data
secret directory: C:\runner-observability-secrets
HTTPS port: 8765
certificate: C:\runner-observability-secrets\monitor.crt
private key: C:\runner-observability-secrets\monitor.key
token: C:\runner-observability-secrets\monitor-token.txt
```

Confirm the actual Monitor process or Windows service before restarting it.
The Runner inventory did not find an observability service; that result does
not prove that the Monitor Host has no service.

## New-machine record

Before onboarding a new Runner, fill these facts from the inventory output:

```text
label=
computer=
account=
python.command=
python.version=
runner.root=
runner.listener.launch_mode=
install.root.existing=
install.current_revision=
secrets.root.existing=
endpoint.machine_value=
token.path.existing=
monitor.crt.trust_model=public-ca|private-ca|unknown
hosts.monitor-test.local.ip=confirmed-or-not-configured
matching.services=
```

If any value is unknown, the onboarding is in the inventory phase. Do not
execute a first-install or certificate-import command yet.
