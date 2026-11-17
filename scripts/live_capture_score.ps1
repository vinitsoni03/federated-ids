# Record this laptop's own traffic for N seconds (e.g. while a YouTube video plays) and score it with the detectors.
#   powershell -ExecutionPolicy Bypass -File scripts\live_capture_score.ps1 [-Seconds 60] [-Name youtube] [-Interface Wi-Fi]
# Needs Wireshark/Npcap. The capture stays outside the repository (it contains addresses and visited hosts).
# All of it is normal traffic, so every alarm is a false alarm (report section 4.2).
param([int]$Seconds = 60, [string]$Name = "youtube", [string]$Interface = "Wi-Fi")
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$py = Join-Path $root ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = "python" }
$dumpcap = "C:\Program Files\Wireshark\dumpcap.exe"
$dir = "D:\federated-ids-work\captures"
New-Item -ItemType Directory -Force $dir | Out-Null
$pcap = Join-Path $dir ($Name + "_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".pcapng")
Write-Host "Recording $Interface for $Seconds s - play the video now..." -ForegroundColor Cyan
& $dumpcap -i $Interface -a "duration:$Seconds" -q -w $pcap
if ($LASTEXITCODE -ne 0) { Write-Host "capture failed (exit $LASTEXITCODE)" -ForegroundColor Red; exit $LASTEXITCODE }
Write-Host "Scoring with the frozen and the hardened detector..." -ForegroundColor Cyan
& $py -m federated_ids.live.score $pcap
