# Runner Observability Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local, fail-open runner telemetry monitor that implements PERS-01 through PERS-05 without treating external Promeo CI data as a control plane.

**Architecture:** A Python standard-library monitor accepts a restricted v1 event envelope, atomically appends it to SQLite, and maintains runner/job/incident projections. A separate fail-open agent CLI emits the same envelope. The dashboard consumes monitor-owned JSON only; it never calls GitHub and uses only the event-supplied Actions URL.

**Tech Stack:** Python 3.11+ standard library (`sqlite3`, `http.server`, `urllib`), SQLite, static HTML/CSS/JavaScript, `unittest`.

**Spec:** `C:\Users\stolas_in\Desktop\promeo-pc-promeo\.scratch\runner-observability\implementation-tickets\PERS-01-minimum-end-to-end-observability.md` through `PERS-05-verification-gate-and-canary.md`; CI contract reference: `C:\Users\stolas_in\Desktop\promeo-pc-promeo\promeo_trunk\docs\architecture\pr-validation-rebuild-architecture.md`.

## Global Constraints

- Schema version is exactly v1; incompatible changes require a new version.
- No bearer, GitHub token, raw log, complete environment, command line, absolute path, PR title/body, individual test identity, or fallback raw reason may be persisted, displayed, or emitted as a diagnostic.
- `received_at` is monitor-owned and is the sole freshness/retention time source.
- Sender retries only temporary network failures, 429, and 5xx: at most two retries and five seconds total; it always exits 0 for telemetry delivery failures.
- The monitor never calls GitHub APIs or infers a run URL.
- Production TLS, Windows service credentials/firewall rules, external workflow hooks, and two-runner acceptance require operator evidence; do not fabricate them in automated tests.

---

### Task 1: Repository contract and v1 validation

**Files:**
- Create: `pyproject.toml`, `src/runner_observability/contracts.py`, `tests/test_contracts.py`, `README.md`

**Interfaces:**
- Produces `validate_event(payload) -> ValidatedEvent` and event-type constants for all later work.
- Rejects malformed, oversized, unapproved, or secret-bearing inputs before persistence.

- [ ] Write tests for valid generic lifecycle events and explicit rejection of token/schema/job-key violations.
- [ ] Run the focused tests and confirm they fail because no contract exists.
- [ ] Implement the smallest typed v1 envelope validator and sanitised rejection reason.
- [ ] Re-run focused tests, then the complete suite.
- [ ] Commit the contract slice.

### Task 2: Transactional event store and baseline projection (PERS-01)

**Files:**
- Create: `src/runner_observability/store.py`, `src/runner_observability/projection.py`, `tests/test_ingest.py`, `tests/fixtures/generic_lifecycle.json`

**Interfaces:**
- Consumes `ValidatedEvent`.
- Produces `Store.ingest(event, received_at) -> IngestResult`, current runner/job views, and append-only history.

- [ ] Write failing integration tests for lifecycle projection, duplicate event IDs, validation atomicity, and terminal outcomes.
- [ ] Confirm failures are assertions for missing behaviour, not test setup errors.
- [ ] Implement migration, one SQLite transaction per accepted event, unique event ID, and generic runner/job projection.
- [ ] Re-run integration and full suites.
- [ ] Commit the PERS-01 persistence slice.

### Task 3: Ordering, liveness, incidents, replay, retention (PERS-02)

**Files:**
- Modify: `src/runner_observability/store.py`, `src/runner_observability/projection.py`
- Create: `src/runner_observability/health.py`, `tests/test_resilience.py`, `tests/test_history.py`

**Interfaces:**
- Adds `refresh_liveness(now)`, `replay()`, `history(filters)`, persisted incident records, and `degraded` health.

- [ ] Write fake-clock tests for stale/later sequence, attempt guard, terminal non-regression, ten-minute timeout, and recovery.
- [ ] Write tests for edge-triggered persisted incidents, replay, retention by `received_at`, and non-destructive degraded handling.
- [ ] Verify each test fails for the intended missing state transition.
- [ ] Implement monotonic projection guards, liveness refresh, incident dedupe, SQLite integrity/replay, and scoped retention.
- [ ] Re-run all resilience/history tests and suite.
- [ ] Commit the PERS-02 resilience slice.

### Task 4: HTTP monitor and fail-open versioned Runner Agent (PERS-01/PERS-04)

**Files:**
- Create: `src/runner_observability/server.py`, `src/runner_observability/agent.py`, `src/runner_observability/__main__.py`, `tests/test_http.py`, `tests/test_agent.py`

**Interfaces:**
- `python -m runner_observability serve` exposes authenticated ingest and read-only dashboard/API endpoints.
- `python -m runner_observability emit` sends one validated event and always exits zero for delivery failure.

- [ ] Write failing HTTP tests for bearer/schema/payload-size handling and no-payload logging.
- [ ] Write failing sender tests for bounded retry classification, diagnostic redaction, and always-zero CLI exit.
- [ ] Implement standard-library HTTP handler and sender with injected clock/transport for deterministic tests.
- [ ] Re-run focused tests and full suite.
- [ ] Commit the transport/agent slice.

### Task 5: Command-center dashboard and controlled stage/fallback presentation (PERS-01/PERS-03)

**Files:**
- Create: `src/runner_observability/dashboard.py`, `src/runner_observability/static/index.html`, `src/runner_observability/static/app.js`, `src/runner_observability/static/app.css`, `tests/test_dashboard.py`, `tests/test_stage_projection.py`

**Interfaces:**
- `dashboard_snapshot()` returns aliases, runner activity/liveness, current/last job, safe timeline, history filters, incidents, and event-supplied `run_url`.
- Supports controlled `job.progress` and `job.fallback` aggregates while preserving generic v1 event display.

- [ ] Write failing snapshot/render tests for idle → running → idle, offline + running, progress-unreported, URL passthrough, history filters, and redaction.
- [ ] Add PR/rebuild fixtures covering only approved phase names and aggregate fallback/unsafe values.
- [ ] Implement snapshot formatting and a dependency-free command-center UI based on the approved variant-B asset.
- [ ] Confirm no GitHub request is made and raw test/group/path content is absent.
- [ ] Re-run full suite and commit the dashboard slice.

### Task 6: Pinned deployment and operations contract (PERS-04)

**Files:**
- Create: `scripts/Install-RunnerObservability.ps1`, `scripts/Update-RunnerObservability.ps1`, `scripts/Invoke-RunnerPreflight.ps1`, `docs/runbook.md`, `tests/test_deployment_docs.py`

**Interfaces:**
- Deployment scripts accept a pinned revision/config path and either atomically activate a verified release or retain the previous release.
- Preflight emits redacted, actionable diagnostics and never prints a secret.

- [ ] Write tests that inspect scripts/runbook for pinned revision, preflight, atomic switch, smoke test, rollback, bounded CLI, TLS/firewall/secret-rotation instructions.
- [ ] Verify red failures.
- [ ] Implement redacted scripts and operator runbook, explicitly leaving Windows Service installation as an operator-authorised step.
- [ ] Re-run deployment tests and full suite.
- [ ] Commit the PERS-04 operations slice.

### Task 7: Verification Gate and evidence handoff (PERS-05)

**Files:**
- Create: `scripts/Invoke-VerificationGate.ps1`, `docs/canary-evidence-template.md`, `tests/test_gate.py`
- Modify: `README.md`

**Interfaces:**
- The verification command runs runner-independent tests and returns a report that remains `not-ready` until both external runner evidence records are supplied.

- [ ] Write failing tests that reject a ready verdict without automated, isolated-drill, Runner A, and Runner B evidence.
- [ ] Implement the local gate/report and evidence template without inventing deployment results.
- [ ] Run the full automated gate, retain its report, and state the external acceptance prerequisites.
- [ ] Commit the PERS-05 local gate slice.

### Task 8: GitHub issue synchronization and completion evidence

**Files:**
- Modify: `README.md`, `docs/runbook.md`, `docs/canary-evidence-template.md`

- [ ] Run the complete test suite and capture the exact output.
- [ ] Commit and push immutable evidence to the tracked repository remote.
- [ ] Update each issue body with actual results, pinned commit links, and successor/blocked scope.
- [ ] Close only an issue whose stated verification is complete; preserve #5 as In Progress if either physical runner acceptance remains absent.
- [ ] Reread GitHub issue and Project state after each status transition.
