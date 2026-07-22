$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$dataDir = Join-Path $root "data"
$pidFile = Join-Path $dataDir "server.pid"
$stateFile = Join-Path $dataDir "server-state.json"

if (-not (Test-Path -LiteralPath $pidFile)) {
    Write-Host "SBOM Scan is not running (no PID file)."
    exit 0
}

$savedPid = [int](Get-Content -LiteralPath $pidFile -Raw)
$processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $savedPid" -ErrorAction SilentlyContinue
if (-not $processInfo) {
    Remove-Item -LiteralPath $pidFile -Force
    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
    Write-Host "Removed stale PID file; the server was not running."
    exit 0
}

if ($processInfo.Name -notmatch "^python(\.exe)?$" -or $processInfo.CommandLine -notmatch "uvicorn\s+app\.main:app") {
    throw "PID $savedPid does not belong to this project's Uvicorn server. Refusing to stop it."
}

Stop-Process -Id $savedPid
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    Start-Sleep -Milliseconds 250
    if (-not (Get-Process -Id $savedPid -ErrorAction SilentlyContinue)) { break }
}
if (Get-Process -Id $savedPid -ErrorAction SilentlyContinue) {
    Stop-Process -Id $savedPid -Force
}

Remove-Item -LiteralPath $pidFile -Force
Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
Write-Host "SBOM Scan stopped (PID $savedPid)."

