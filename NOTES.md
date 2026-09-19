# Teaching notes

- Prefer Traditional Chinese, short explanations, and concrete PowerShell commands.
- The learner is new to networking; use the mental model: 地址簿 → 大門 → 保全 → 加密通道 → API 櫃台 → 應用程式資料.
- Tie every concept to the actual Runner Observability incident:
  - monitor-test.local initially pointed to the old 192.168.1.50.
  - The monitor was reachable at 192.168.24.141.
  - TCP succeeded after the local mapping was corrected.
  - HTTPS by IP failed because the certificate identity/trust was not aligned with that request.
  - HTTPS by the hostname succeeded after the certificate was trusted.
- Never copy the token or private key into lessons, examples, reports, or screenshots.
