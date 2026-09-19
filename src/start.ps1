Set-Location 'C:\Users\stolas_in\Desktop\runner-observability'

$env:PYTHONPATH = Join-Path $PWD 'src'
$monitorData = 'C:\runner-observability-data'
New-Item -ItemType Directory -Force $monitorData | Out-Null

$monitorToken = (Get-Content -Raw 'C:\runner-observability-secrets\monitor-token.txt').Trim()

python -m runner_observability serve `
  --host 0.0.0.0 `
  --port 8765 `
  --token $monitorToken `
  --database "$monitorData\monitor.sqlite" `
  --tls-cert 'C:\runner-observability-secrets\monitor.crt' `
  --tls-key 'C:\runner-observability-secrets\monitor.key'