# Runner observability -- canary/HITL evidence template

This is a **reusable document skeleton**, not a filled report. It defines the
shape of the evidence issue #6 (HITL) must record before any production-ready
decision. Nothing in this file is filled in by an automated test, and no
automated test may claim any of these fields is true -- only a human operator
running the real HITL checklist may record real values here.

## Scope boundary

| Evidence area | Owned by | Automated-test claims allowed |
| --- | --- | --- |
| Local runner-independent suite, isolated fault drills, redacted evidence report | Issue #5 (this repo's local Verification Gate; see `scripts/Invoke-VerificationGate.ps1` and the generated `gate-report.md`) | Yes -- pass/fail counts and drill capability results only |
| Monitor Host / Runner A / Runner B deployment | Issue #6 (HITL) | No -- document shape only; never assert deployment occurred |
| TLS, authentication, firewall configuration | Issue #6 (HITL) | No |
| Real GitHub Actions workflow acceptance | Issue #6 (HITL) | No |
| Production-ready decision | Issue #6 (HITL) | No |

Issue #5's local gate passing is a prerequisite for starting issue #6's
checklist below. It is not, by itself, sufficient evidence for any row in
this template.

## 1. Local Verification Gate reference (issue #5)

- Local gate report path/commit reference: `_____________________________`
- Local gate overall result (PASS / FAIL, from the report's own stamp): `_____`
- Local gate status field (must read `not-ready`): `_____________________`
- Date/time the referenced local gate run was produced (UTC): `______________`

This section only points at issue #5's own redacted report; it does not
duplicate or re-derive its contents here.

## 2. Monitor Host deployment evidence

- Host identifier (operator-assigned, non-secret label): `_______________`
- Pinned revision/commit deployed: `_______________________________________`
- Service installed and running as expected: [ ] Yes  [ ] No
- Operator name and date: `________________________________________________`

## 3. Runner A deployment evidence

- Host identifier (operator-assigned, non-secret label): `_______________`
- Agent version/pinned revision installed: `___________________________`
- Successful heartbeat observed on the Monitor Host dashboard: [ ] Yes  [ ] No
- Operator name and date: `________________________________________________`

## 4. Runner B deployment evidence

- Host identifier (operator-assigned, non-secret label): `_______________`
- Agent version/pinned revision installed: `___________________________`
- Successful heartbeat observed on the Monitor Host dashboard: [ ] Yes  [ ] No
- Operator name and date: `________________________________________________`

## 5. TLS / authentication / firewall evidence

- TLS certificate source and expiry (no key material recorded here): `_____`
- Bearer token rotation confirmed (token value itself never recorded): [ ] Yes  [ ] No
- Firewall rule scoping the ingest endpoint confirmed: [ ] Yes  [ ] No
- Operator name and date: `________________________________________________`

## 6. Real workflow acceptance evidence

- Actions run URL (from a real GitHub Actions run, not fabricated): `_____`
- Observed end-to-end: job started -> heartbeats -> finished/fallback, as
  shown live on the Monitor Host dashboard: [ ] Yes  [ ] No
- Notes on any observed fallback/offline/retention behavior during the run: `_____`
- Operator name and date: `________________________________________________`

## 7. Production-ready decision

- Decision: [ ] Ready  [ ] Not ready  [ ] Blocked
- Rationale (reference the specific rows above that were or were not met): `_____`
- Decision-maker name and date: `________________________________________`

**Reminder:** an incomplete section above must leave the decision in section 7
as "Not ready" or "Blocked" -- never inferred as "Ready" from partial evidence
or from issue #5's local gate alone.
