# run_cammonitor.ps1 — keep-alive wrapper for the Flask app
# Launched by Task Scheduler (ONSTART / SYSTEM). Restarts app on crash.
# Waits for go2rtc (port 1984) before starting. Single-instance guard on port 5001.

$ErrorActionPreference = "Stop"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot   = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PythonExe  = Join-Path $RepoRoot ".venv\Scripts\python.exe"
$AppScript  = Join-Path $RepoRoot "run_local.py"
$AppPort    = 5001
$Go2rtcPort = 1984

function Test-Port([int]$p) {
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $p)
        $tcp.Close(); return $true
    } catch { return $false }
}

function Wait-Port([int]$p, [string]$name, [int]$timeoutSec = 120) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    Write-Host "$(Get-Date -Format 'HH:mm:ss') Waiting for $name on port $p..."
    while ((Get-Date) -lt $deadline) {
        if (Test-Port $p) { Write-Host "$(Get-Date -Format 'HH:mm:ss') $name is up."; return }
        Start-Sleep -Seconds 3
    }
    Write-Host "$(Get-Date -Format 'HH:mm:ss') WARNING: $name not up after ${timeoutSec}s — starting anyway."
}

# Single-instance guard
if (Test-Port $AppPort) {
    Write-Host "CamMonitor already listening on port $AppPort — exiting."
    exit 0
}

# Wait for go2rtc before starting (ordering dependency)
Wait-Port -p $Go2rtcPort -name "go2rtc"

Set-Location $RepoRoot

# Keep-alive loop
while ($true) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss') Starting CamMonitor..."
    try {
        $proc = Start-Process -FilePath $PythonExe `
            -ArgumentList "`"$AppScript`"" `
            -PassThru -NoNewWindow -WorkingDirectory $RepoRoot
        $proc.WaitForExit()
        $code = $proc.ExitCode
        Write-Host "$(Get-Date -Format 'HH:mm:ss') CamMonitor exited (code $code). Restarting in 5s..."
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') CamMonitor failed to start: $_. Retrying in 5s..."
    }
    Start-Sleep -Seconds 5
}
