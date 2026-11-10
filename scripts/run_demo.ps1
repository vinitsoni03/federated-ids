# Start the local demo dashboard and open it in the browser (Windows PowerShell).
#   powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
Start-Process "http://127.0.0.1:8000"
& $py -m uvicorn demo.app:app --host 127.0.0.1 --port 8000
