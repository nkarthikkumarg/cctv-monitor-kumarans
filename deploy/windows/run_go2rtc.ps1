$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Go2rtcExe = Join-Path $ScriptDir "bin\go2rtc.exe"
$ConfigPath = Join-Path $ScriptDir "go2rtc.yaml"

& $Go2rtcExe -config $ConfigPath
