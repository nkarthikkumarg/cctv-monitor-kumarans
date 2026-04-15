# run_caddy.ps1 — keep-alive wrapper for Caddy reverse proxy
# Launched by Task Scheduler (ONSTART / SYSTEM). Restarts Caddy on crash.
# Waits for go2rtc (1984) and CamMonitor (5001) before starting.
# Single-instance guard on port 8080.

$ErrorActionPreference = "Stop"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$CaddyExe   = Join-Path $ScriptDir "bin\caddy.exe"
$Caddyfile  = Join-Path $ScriptDir "Caddyfile"
$ProxyPort  = 8080
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
if (Test-Port $ProxyPort) {
    Write-Host "Caddy already listening on port $ProxyPort — exiting."
    exit 0
}

# Wait for upstream services (ordering dependency)
Wait-Port -p $Go2rtcPort -name "go2rtc"
Wait-Port -p $AppPort    -name "CamMonitor"

# Keep-alive loop
while ($true) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss') Starting Caddy..."
    try {
        $proc = Start-Process -FilePath $CaddyExe `
            -ArgumentList "run", "--config", "`"$Caddyfile`"" `
            -PassThru -NoNewWindow
        $proc.WaitForExit()
        $code = $proc.ExitCode
        Write-Host "$(Get-Date -Format 'HH:mm:ss') Caddy exited (code $code). Restarting in 5s..."
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') Caddy failed to start: $_. Retrying in 5s..."
    }
    Start-Sleep -Seconds 5
}
