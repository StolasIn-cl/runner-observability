# Learning Record 0001: Runner 到 Monitor 的路徑

## What was understood

The learner completed the canary sequence on two runners and recognized that the practical setup was mostly copying the verification files and correcting the hostname mapping. This demonstrates the key distinction between the conceptual layers and the number of operator actions: the layers are separate for diagnosis, but the happy-path procedure can be short.

The next question is how to view the monitor-owned dashboard and why a browser may still warn about an HTTPS URL even after TCP and PowerShell health checks succeed.

## Evidence

- Both runners reported passing canary checks, including OfflineRecovery.
- The monitor is served by the root URL and its browser dashboard reads the monitor-owned dashboard API.
- The test certificate is intended for the monitor hostname, so the browser should use the hostname rather than the current LAN IP.
