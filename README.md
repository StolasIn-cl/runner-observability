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
