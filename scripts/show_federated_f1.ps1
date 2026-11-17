# Live federated run for a demo: 10 clients, FedAvg, IID, 30 rounds, 8 classes; prints the test F1 at the end.
#   powershell -ExecutionPolicy Bypass -File scripts\show_federated_f1.ps1
# Same configuration as the Azure + laptop Flower run (expected test macro-F1 0.6692). ~4 min on the GPU.
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
# GPU venv if present, otherwise the project's venv (CPU is slower but gives the same result)
$py = "D:\federated-ids-work\venv-cuda\Scripts\python.exe"
$device = "cuda"
if (-not (Test-Path $py)) { $py = Join-Path $root ".venv\Scripts\python.exe"; $device = "cpu" }
$run = "demo_" + (Get-Date -Format "yyyyMMdd_HHmm")
Write-Host "Federated learning: 10 clients, FedAvg, 30 rounds, 8 classes (expected test macro-F1 0.6692)" -ForegroundColor Cyan
& $py -u -m federated_ids.federated.simulation --seed 0 --device $device --run-name $run
if ($LASTEXITCODE -ne 0) { Write-Host "run failed (exit $LASTEXITCODE)" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host ""
Write-Host "RESULT on the test set:" -ForegroundColor Green
& $py scripts\print_run_f1.py "artifacts\runs\$run\metrics.json"
