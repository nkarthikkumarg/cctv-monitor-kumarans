$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = (Resolve-Path (Join-Path $ScriptDir "..\..")).Path
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"

Set-Location $RepoRoot
& $PythonExe run_local.py
