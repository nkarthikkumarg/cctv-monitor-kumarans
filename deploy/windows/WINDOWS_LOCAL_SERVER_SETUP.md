# Windows Local Server Setup

This guide packages the local site stack for Windows:

1. CamMonitor app
2. go2rtc
3. Caddy
4. Cloudflared tunnel

For the full, in-depth Cloudflare tunnel walkthrough, use:

- [deploy/windows/README.md](README.md)

## 1. Requirements

- Windows 10/11 (64-bit)
- Internet access for one-time download
- Python 3.10+ installed (with `py` launcher)
- PowerShell

## 2. Run Installer

Open PowerShell as Administrator:

```powershell
cd C:\path\to\cctv-monitor-kumarans
powershell -ExecutionPolicy Bypass -File .\deploy\windows\install.ps1
```

This will:

- create `.venv`
- install Python dependencies
- download `go2rtc.exe`, `caddy.exe`, and `cloudflared.exe`
- set `config.ini` local defaults (`127.0.0.1:5001`)
- create startup tasks for all four processes

## 3. Configure Cloudflare Tunnel

1. Login once:

```powershell
.\deploy\windows\bin\cloudflared.exe tunnel login
```

2. Create tunnel:

```powershell
.\deploy\windows\bin\cloudflared.exe tunnel create mls-site
```

3. Map DNS:

```powershell
.\deploy\windows\bin\cloudflared.exe tunnel route dns mls-site mls-site.yourdomain.in
```

4. Edit [cloudflared.yml.template](cloudflared.yml.template) and save as:

- `deploy/windows/cloudflared.yml`

Set:

- `tunnel` ID
- `credentials-file`
- `hostname`

## 4. First Manual Test

Run each command in a separate PowerShell window:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_go2rtc.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_caddy.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_cammonitor.ps1
```

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_cloudflared.ps1
```

Open:

- `http://127.0.0.1:8080`

Public URL:

- `https://mls-site.yourdomain.in`

## 5. Verify Startup Tasks

The installer creates these ONLOGON tasks:

- `CamMonitor-App`
- `CamMonitor-go2rtc`
- `CamMonitor-Caddy`
- `CamMonitor-Cloudflared`

To check:

```powershell
schtasks /Query /TN CamMonitor-App
schtasks /Query /TN CamMonitor-go2rtc
schtasks /Query /TN CamMonitor-Caddy
schtasks /Query /TN CamMonitor-Cloudflared
```

## Notes

- Keep `go2rtc` and app on localhost only; only Caddy/tunnel is exposed.
- Cloudflared task uses `mls-site` tunnel name by default.
- If you use a different tunnel name, update `run_cloudflared.ps1`.
