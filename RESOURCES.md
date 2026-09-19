# Resources

## Knowledge

- [Microsoft Learn: Test-NetConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2025-ps) — explains the PowerShell connection diagnostic, including TCP port tests and quiet Boolean output.
- [Microsoft Learn: Hosts File Editor](https://learn.microsoft.com/en-us/windows/powertoys/hosts-file-editor) — explains the Windows hosts file as a local hostname-to-IP mapping.
- [Microsoft Learn: DNS overview](https://learn.microsoft.com/en-us/windows/win32/dns/dns-overview) — explains why names such as monitor-test.local are translated into numeric IP addresses.
- [Microsoft Learn: DNS queries and lookups](https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups) — describes how the Windows DNS client resolves names using local information, cache, and DNS servers.
- [Microsoft Learn: Import-Certificate](https://learn.microsoft.com/en-us/powershell/module/pki/import-certificate?view=windowsserver2025-ps) — documents importing a certificate into a Windows certificate store.
- [Python documentation: ssl](https://docs.python.org/3/library/ssl.html) — explains TLS contexts, certificate chains, peer authentication, and hostname checking.
- [Python documentation: http.server](https://docs.python.org/3/library/http.server.html) — documents the HTTP server building block used by the project's local monitor service.
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446) — primary protocol specification for the secure channel concept.

## Wisdom

No community or secondary sources are needed for this first lesson. The explanation is grounded in the official references above and the project's own scripts and runbook.

## Gaps

- The lesson intentionally does not cover how the company network assigns IP addresses or manages its internal DNS.
- The lesson does not decide whether the current self-signed certificate arrangement is appropriate for a future production rollout.
