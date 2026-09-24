# Runner Job Telemetry Durable Outbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans (recommended) to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit, bounded, file-backed Runner telemetry outbox that survives process restart, replays transient delivery failures, dead-letters permanent rejections, and preserves the existing fail-open CLI behavior.

**Architecture:** Keep direct `emit` delivery unchanged when no outbox directory is supplied. Add a focused `DurableOutbox` module with atomic file-per-event persistence under `pending/` and `dead-letter/`, then connect it to optional `emit --outbox-dir` and a `flush --token-file` command. Reuse existing event validation, HTTP delivery classification, credential-file handling, and redacted diagnostic conventions.

**Tech Stack:** Python 3.11+ standard library, `unittest`, JSON files, `pathlib`, atomic `os.replace`, `fsync`, existing `deliver_event` transport seams, PowerShell runbook documentation.

**Spec:** `docs/superpowers/specs/2026-09-24-runner-job-telemetry-outbox-design.md`

## Global Constraints

- Pending files contain only `queued_at` and a validated schema-v1 event; dead-letter files may add only an allowlisted `dead_letter_reason`.
- The outbox root is explicit; no default spool path is enabled automatically.
- Default capacity is 1,000 pending/dead-letter events and 32 MiB total queue-owned JSON files.
- A single drain processes at most 100 events or 5 seconds of wall-clock time.
- Successful delivery removes a pending file; transient network/429/5xx failures retain it; permanent HTTP rejection moves it to dead-letter.
- Queue, filesystem, delivery, and replay failures remain fail-open and return CLI exit code 0.
- Tokens, endpoint values, raw exception text, HTTP bodies, and unvalidated payloads never enter queue files, dead-letter files, diagnostics, or command output.
- No target-machine deployment, ACL mutation, service restart, certificate/trust change, or live canary is performed by this plan.
- The existing unrelated `tests/test_deployment_docs.py:836` failure remains independently reported if it persists.

## Review Focus

- Same `event_id` with different event content must report `outbox_event_conflict` and preserve the original file; Task 1 tests this before implementation.
- Corrupt or tampered pending JSON must be skipped with `outbox_corrupt_event` and no content leakage; Task 1 tests this boundary.
- A transient failure must retain the event while a permanent rejection must dead-letter it; Task 2 tests both paths and restart replay.
- Capacity must be checked before writing and include dead-letter files without deleting older events; Task 1 tests count and byte limits.
- CLI queue failure and delivery failure must remain exit code 0, while no-outbox mode remains byte-for-byte compatible at the argument/transport seam; Task 3 tests both modes.

---

### Task 1: Implement atomic outbox storage and capacity

**Files:**
- Create: `src/runner_observability/outbox.py`
- Create: `tests/test_outbox.py`

**Interfaces:**
- `OutboxLimits(max_events: int = 1000, max_bytes: int = 32 * 1024 * 1024, max_drain_events: int = 100, max_drain_seconds: float = 5.0)` — immutable validated limits.
- `EnqueueResult(event_id: str, status: str, reason: str | None = None)` — status is `queued`, `duplicate`, `conflict`, or `rejected`.
- `DurableOutbox(root: Path | str, *, limits: OutboxLimits = OutboxLimits(), diagnostic: Callable[[str], None] | None = None)`.
- `DurableOutbox.enqueue(event: object, *, queued_at: str | None = None) -> EnqueueResult`.
- `DurableOutbox.pending_events() -> tuple[list[tuple[Path, dict[str, object]]], int]` — returns valid pending envelopes sorted by `(queued_at, event_id)` plus the number of corrupt files skipped; all corrupt-file diagnostics use the stable diagnostic seam.

**Produces:** A validated, secret-free pending queue that can be reopened by a new `DurableOutbox` instance. Task 2 consumes the exact file layout and `pending_events()` result.

- [ ] **Step 1: Write failing storage tests**

  Add tests for atomic enqueue/reopen, duplicate no-op, event conflict, corrupt-file skip, and capacity count/bytes. Use the existing heartbeat fixture shape and a temporary directory; assert file contents do not contain a bearer token or endpoint.

- [ ] **Step 2: Run the storage tests and verify the expected RED state**

  Run:

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_outbox -v
  ```

  Expected: import or missing-interface failures because `runner_observability.outbox` does not exist yet.

- [ ] **Step 3: Implement the minimal storage boundary**

  Validate input with `validate_event`, serialize the validated payload using the existing JSON-copy convention, write a `{\"queued_at\": ..., \"event\": ...}` envelope to a same-directory temporary file, flush/fsync it, and replace `<root>/pending/<event_id>.json`. Compare only the validated event when handling an existing event_id. Count `.json` files and bytes across `pending/` and `dead-letter/` before accepting a new file. Leave malformed files in place, report only `outbox_corrupt_event`, return its count separately from valid pending entries, and continue listing other pending files.

- [ ] **Step 4: Run storage tests and verify GREEN**

  Run the same `tests.test_outbox` command; require all storage tests to pass with no secret-bearing diagnostics.

- [ ] **Step 5: Commit the storage task**

  ```powershell
  git add src/runner_observability/outbox.py tests/test_outbox.py
  git commit -m "feat: add durable telemetry outbox storage"
  ```

### Task 2: Add bounded drain, replay, and dead-letter behavior

**Files:**
- Modify: `src/runner_observability/outbox.py`
- Modify: `tests/test_outbox.py`

**Interfaces:**
- `DrainResult(delivered: int, retained: int, dead_lettered: int, corrupt: int)` — counts one bounded drain pass.
- `DurableOutbox.drain(deliver: Callable[[object, str, str], DeliveryResult], endpoint: str, token: str, *, clock: Callable[[], float] = time.monotonic, sleeper: Callable[[float], None] = time.sleep) -> DrainResult`.

**Consumes:** Task 1's `pending_events()`, file layout, `OutboxLimits`, and stable diagnostic boundary.

**Produces:** Replay semantics used by Task 3: delivered files are removed, transient failures remain, permanent `rejected_http_response` failures are moved atomically to dead-letter with a stable reason, and the configured count/time budget stops further work.

- [ ] **Step 1: Write failing drain tests**

  Add tests for success removal, transient retention followed by replay from a new instance, permanent rejection dead-letter, corrupt-file skip while healthy files proceed, and the maximum event/time budget.

- [ ] **Step 2: Run drain tests and verify the expected RED state**

  Run:

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_outbox -v
  ```

  Expected: the new drain tests fail because `DrainResult` and `DurableOutbox.drain` are not implemented.

- [ ] **Step 3: Implement the minimal drain loop**

  Iterate the sorted pending list until `max_drain_events` or `max_drain_seconds` is reached. Call the injected delivery function with each original event. Remove only when `delivered` is true; retain known transient reasons; atomically rewrite/move validated permanent failures to `dead-letter/<event_id>.json` with `dead_letter_reason`; catch filesystem errors as stable diagnostics without raising to the caller.

- [ ] **Step 4: Run storage and drain tests and verify GREEN**

  Require the complete `tests.test_outbox` module to pass, including all Task 1 regression cases.

- [ ] **Step 5: Commit the drain task**

  ```powershell
  git add src/runner_observability/outbox.py tests/test_outbox.py
  git commit -m "feat: replay transient telemetry failures"
  ```

### Task 3: Integrate optional outbox and flush CLI paths

**Files:**
- Modify: `src/runner_observability/agent.py`
- Modify: `src/runner_observability/__main__.py`
- Modify: `tests/test_agent.py`
- Create: `tests/test_cli_outbox.py`

**Interfaces:**
- Existing `agent.main` direct `emit --endpoint --token --event-json` behavior remains unchanged when `--outbox-dir` is absent.
- `emit` gains optional `--outbox-dir` and enqueues before bounded drain.
- New `flush --endpoint --token-file --outbox-dir` drains existing pending files without accepting event payload input.
- Package `python -m runner_observability` dispatches both new options while preserving `serve` behavior and existing test injection seams.

**Consumes:** Task 2's `DurableOutbox.drain`, `DrainResult`, existing `deliver_event` transport/clock/sleeper injection, and `read_token_file`.

**Produces:** Fail-open CLI behavior: queue/delivery failure returns 0; invalid event and credential failures use existing stable reason behavior; no token is written to queue or diagnostics.

- [ ] **Step 1: Write failing CLI integration tests**

  Add tests proving `emit --outbox-dir` leaves a pending file on injected 503, removes it on injected 202, `flush --token-file` replays after a new process-style invocation, queue capacity still returns 0, and no-outbox direct mode still calls the existing transport exactly as before.

- [ ] **Step 2: Run the CLI tests and verify the expected RED state**

  Run:

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_agent tests.test_cli_outbox -v
  ```

  Expected: new CLI cases fail because the parser has no `--outbox-dir`/`flush` path.

- [ ] **Step 3: Implement CLI integration**

  Add an outbox argument only to the `emit` path, pass the existing injected delivery seams into `DurableOutbox.drain`, and add the `flush` path with `read_token_file`. Keep `deliver_event` as the only transport implementation and route all queue failures through the existing safe diagnostic wrapper. Do not print endpoint, token, event payload, exception text, or filesystem contents.

- [ ] **Step 4: Run focused CLI and existing agent tests and verify GREEN**

  Run the focused command from Step 2 plus the existing heartbeat/service/CI integration tests; require all to pass.

- [ ] **Step 5: Commit the CLI task**

  ```powershell
  git add src/runner_observability/agent.py src/runner_observability/__main__.py tests/test_agent.py tests/test_cli_outbox.py
  git commit -m "feat: add fail-open telemetry outbox CLI"
  ```

### Task 4: Document operation and complete verification

**Files:**
- Modify: `docs/runbook.md`
- Create: `tests/test_outbox_docs.py`

**Interfaces:** Existing operator runbook sections for Runner telemetry and canary; no new machine mutation.

**Consumes:** Task 3's `--outbox-dir` and `flush --token-file` command behavior.

**Produces:** Redacted operator guidance for choosing a protected Runner-owned data root, observing pending/dead-letter counts, invoking replay, and distinguishing local evidence from target HITL evidence.

- [ ] **Step 1: Write failing documentation-contract tests**

  Assert the runbook names `--outbox-dir`, `flush`, `--token-file`, pending/dead-letter behavior, capacity, and explicitly says not to place the outbox under the secrets root or print token/payload values.

- [ ] **Step 2: Run the documentation test and verify the expected RED state**

  Run:

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest tests.test_outbox_docs -v
  ```

  Expected: the new runbook assertions fail because the outbox operation section is not documented.

- [ ] **Step 3: Update the runbook**

  Add read-only PowerShell inspection examples that show counts and stable status fields only, plus safe `flush` invocation using `--token-file`. State that actual ACL, Runner account, service release, and live replay remain target-side HITL evidence.

- [ ] **Step 4: Run the complete verification set**

  Run:

  ```powershell
  $env:PYTHONPATH = Join-Path (Get-Location) 'src'
  python -m unittest discover -s tests -q
  python -m compileall -q src tests
  git diff --check
  ```

  Expected: all new and existing tests pass except the already-known unrelated `test_a_release_missing_its_package_entirely_fails_the_real_smoke_test` at `tests/test_deployment_docs.py:836`, if it remains reproducible.

- [ ] **Step 5: Commit documentation and verification updates**

  ```powershell
  git add docs/runbook.md tests/test_outbox_docs.py
  git commit -m "docs: operate runner telemetry outbox"
  ```

- [ ] **Step 6: Synchronize Issue #3151**

  Update the issue body with the implementation commit SHAs, focused/full test results, outbox scope, and remaining target-side HITL evidence. Reread the issue assignee and Project status; keep the issue Open and Project `In Progress` until target evidence and the agreed completion gate exist.
