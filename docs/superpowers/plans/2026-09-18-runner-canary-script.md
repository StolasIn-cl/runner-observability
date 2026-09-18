# Runner canary script

## Goal

Provide one PowerShell script that can be pulled onto a Windows Runner and
used to exercise the live Monitor Host contract after issue #7's HTTPS/TLS
implementation. The script must keep bearer tokens out of process arguments
and output, preserve producer sequence state across runs, and give a short
operator flow for the remaining issue #6 canary checks.

## Scope

- Add `scripts/Invoke-RunnerCanary.ps1` with four modes: `Smoke`,
  `OfflineRecovery`, `Auth`, and `NetworkFailure`.
- Require HTTPS by default, with an explicit `-AllowInsecureHttp` escape hatch
  for a deliberately local/plain-HTTP test.
- Read the token from a file and maintain epoch/sequence state in a local
  state file that never contains the token.
- Add contract tests for the script's safety and mode surface.
- Add an operator section to `docs/runbook.md` with copyable commands and
  expected results.

## Non-goals

- Do not alter issue #7's TLS server implementation.
- Do not change the existing `emit --token` CLI contract.
- Do not claim that a real Monitor Host, certificate store, firewall, service,
  or GitHub Actions workflow has been tested by repository tests.

## Verification

1. Run the new contract tests and PowerShell parser check.
2. Run the complete Python test suite.
3. Run `git diff --check` and inspect the final diff for token leakage and
   accidental changes to existing user files.
