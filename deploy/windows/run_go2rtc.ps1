# run_go2rtc.ps1 — keep-alive wrapper for go2rtc
# Launched by Task Scheduler (ONSTART / SYSTEM). Restarts go2rtc on crash.
# Single-instance guard: exits immediately if go2rtc is already listening on port 1984.

$ErrorActionPreference = "Stop"
$ScriptDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Go2rtcExe  = Join-Path $ScriptDir "bin\go2rtc.exe"
$ConfigPath = Join-Path $ScriptDir "go2rtc.yaml"
$Port       = 1984

function Test-Port([int]$p) {
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new("127.0.0.1", $p)
        $tcp.Close(); return $true
    } catch { return $false }
}

# Single-instance guard
if (Test-Port $Port) {
    Write-Host "go2rtc already listening on port $Port — exiting."
    exit 0
}

# Keep-alive loop — restarts go2rtc if it crashes
while ($true) {
    Write-Host "$(Get-Date -Format 'HH:mm:ss') Starting go2rtc..."
    try {
        $proc = Start-Process -FilePath $Go2rtcExe `
            -ArgumentList "-config", "`"$ConfigPath`"" `
            -PassThru -NoNewWindow
        $proc.WaitForExit()
        $code = $proc.ExitCode
        Write-Host "$(Get-Date -Format 'HH:mm:ss') go2rtc exited (code $code). Restarting in 5s..."
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') go2rtc failed to start: $_. Retrying in 5s..."
    }
    Start-Sleep -Seconds 5
}
