param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8088,
    [string]$HostAddress = "127.0.0.1",
    [string]$GitAllowedHosts = $env:SBOM_GIT_ALLOWED_HOSTS
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$dataDir = Join-Path $root "data"
$pidFile = Join-Path $dataDir "server.pid"
$stateFile = Join-Path $dataDir "server-state.json"
$stdoutLog = Join-Path $dataDir "server.out.log"
$stderrLog = Join-Path $dataDir "server.err.log"

if ($GitAllowedHosts) {
    $env:SBOM_GIT_ALLOWED_HOSTS = $GitAllowedHosts
} else {
    Remove-Item Env:SBOM_GIT_ALLOWED_HOSTS -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Path $dataDir -Force | Out-Null

if (Test-Path -LiteralPath $pidFile) {
    $savedPid = [int](Get-Content -LiteralPath $pidFile -Raw)
    $existing = Get-CimInstance Win32_Process -Filter "ProcessId = $savedPid" -ErrorAction SilentlyContinue
    if ($existing -and $existing.CommandLine -match "uvicorn\s+app\.main:app") {
        $state = Get-Content -LiteralPath $stateFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        Write-Host "SBOM Scan is already running (PID $savedPid)."
        Write-Host "URL: http://$($state.host):$($state.port)"
        exit 0
    }
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
}

$listener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
if ($listener) {
    throw "Port $Port is already in use by PID $($listener.OwningProcess). Stop that service or run .\start.ps1 -Port <port>."
}

$venvPython = Join-Path $root ".venv\Scripts\python.exe"
$python = if (Test-Path -LiteralPath $venvPython) { $venvPython } else { (Get-Command python -ErrorAction Stop).Source }
$arguments = @("-m", "uvicorn", "app.main:app", "--host", $HostAddress, "--port", "$Port")
$process = Start-Process -FilePath $python -ArgumentList $arguments -WorkingDirectory $root `
    -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -WindowStyle Hidden -PassThru

Set-Content -LiteralPath $pidFile -Value $process.Id -Encoding ascii
@{
    pid = $process.Id
    host = $HostAddress
    port = $Port
    startedAt = (Get-Date).ToString("o")
} | ConvertTo-Json | Set-Content -LiteralPath $stateFile -Encoding utf8

$ready = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    Start-Sleep -Milliseconds 500
    if ($process.HasExited) { break }
    try {
        $health = Invoke-RestMethod -Uri "http://${HostAddress}:${Port}/api/health" -TimeoutSec 2
        if ($health.status -eq "ok") { $ready = $true; break }
    } catch { }
}

if (-not $ready) {
    if (-not $process.HasExited) { Stop-Process -Id $process.Id -Force }
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $stateFile -Force -ErrorAction SilentlyContinue
    throw "SBOM Scan failed to start. Check $stderrLog"
}

Write-Host "SBOM Scan started (PID $($process.Id))."
Write-Host "URL: http://${HostAddress}:${Port}"
Write-Host "Stop: .\stop.ps1"
