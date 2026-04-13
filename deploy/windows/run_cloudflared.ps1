$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CloudflaredExe = Join-Path $ScriptDir "bin\cloudflared.exe"
$ConfigPath = Join-Path $ScriptDir "cloudflared.yml"

if (!(Test-Path $ConfigPath)) {
  throw "cloudflared.yml not found. Copy and edit cloudflared.yml.template first."
}

& $CloudflaredExe tunnel --config $ConfigPath run
