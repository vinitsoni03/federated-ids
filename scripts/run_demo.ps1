# Start the local demo dashboard and open it in the browser (Windows PowerShell).
#   powershell -ExecutionPolicy Bypass -File scripts\run_demo.ps1
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
# use the project's venv if it exists, otherwise whatever python is on PATH
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
# open the browser first; uvicorn then keeps running in this window until Ctrl+C
Start-Process "http://127.0.0.1:8000"
& $py -m uvicorn demo.app:app --host 127.0.0.1 --port 8000
