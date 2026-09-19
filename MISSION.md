# Mission: Understand the Runner Observability network path

## Why

The user is operating a small internal application that observes runner progress. They want to understand why a complete deployment has several setup and test steps, and how to identify which layer failed without needing a strong networking background.

## Success looks like

- Explain the path from Runner to Monitor Host in plain Traditional Chinese.
- Understand what hostname mapping, TCP, firewall, TLS certificate, HTTP, bearer token, and liveness each protect or verify.
- Choose the next command from the symptom instead of guessing.
- Complete the Runner Observability canary checks with confidence.

## Constraints

- Use Traditional Chinese and concrete Windows PowerShell examples.
- Teach from the actual runner-observability project and the recent troubleshooting experience.
- The deployment is on a company LAN and carries runner progress data.
- Never place tokens, private keys, or certificate contents in learning materials.
- Keep the first lesson short enough to revisit while operating the system.

## Out of scope

- Advanced routing, public-cloud networking, enterprise PKI design, and secrets-management products.
- Replacing the project's deployment or canary runbook.
- Declaring the system production-ready based only on local tests.
