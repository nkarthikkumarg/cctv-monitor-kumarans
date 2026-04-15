# run_cloudflared.ps1 — keep-alive wrapper for cloudflared tunnel
# Launched by Task Scheduler (ONSTART / SYSTEM). Restarts cloudflared on crash.
# Waits for Caddy (port 8080) before starting.
# Single-instance guard via process name check.

$ErrorActionPreference = "Stop"
$ScriptDir       = Split-Path -Parent $MyInvocation.MyCommand.Path
$CloudflaredExe  = Join-Path $ScriptDir "bin\cloudflared.exe"
$ConfigPath      = Join-Path $ScriptDir "cloudflared.yml"
$CaddyPort       = 8080

if (!(Test-Path $ConfigPath)) {
    throw "cloudflared.yml not found at $ConfigPath. Copy and edit cloudflared.yml.template first."
}

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

# Single-instance guard via process name
$existing = Get-Process -Name "cloudflared" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "cloudflared already running (PID $($existing.Id)) — exiting."
    exit 0
}

# Wait for Caddy before starting tunnel
Wait-Port -p $CaddyPort -name "Caddy"

# Keep-alive loop
while ($true) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss') Starting cloudflared tunnel..."
    try {
        $proc = Start-Process -FilePath $CloudflaredExe `
            -ArgumentList "tunnel", "--config", "`"$ConfigPath`"", "run" `
            -PassThru -NoNewWindow
        $proc.WaitForExit()
        $code = $proc.ExitCode
        Write-Host "$(Get-Date -Format 'HH:mm:ss') cloudflared exited (code $code). Restarting in 10s..."
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') cloudflared failed to start: $_. Retrying in 10s..."
    }
    Start-Sleep -Seconds 10
}
