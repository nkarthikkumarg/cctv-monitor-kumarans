$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CaddyExe = Join-Path $ScriptDir "bin\caddy.exe"
$Caddyfile = Join-Path $ScriptDir "Caddyfile"

& $CaddyExe run --config $Caddyfile
