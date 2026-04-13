# Windows Setup (Simple Guide)

This guide is written in plain language so a non-technical person can do the setup.

What we are installing:

1. Local dashboard app
2. Video bridge (go2rtc)
3. Local web gateway (Caddy)
4. Cloudflare tunnel (public URL)

## Before You Start

You need:

- Windows 10/11
- Internet connection
- Cloudflare account
- Your domain already added in Cloudflare (example: `kumarans.in`)
- Python 3.10 or above installed

## Step 1: Run One Installer Command

Open **PowerShell as Administrator**.

Go to project folder:

```powershell
cd C:\path\to\cctv-monitor-kumarans
```

Run installer:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\install.ps1
```

What this does automatically:

- installs Python packages
- downloads `go2rtc`, `caddy`, and `cloudflared`
- sets local app to run on `127.0.0.1:5001`
- generates a random app secret if the config still has the placeholder value
- generates a bootstrap admin password if the default `admin123` is still set, and **prints it to the terminal**
- creates auto-start tasks so services restart after login/reboot

After the installer finishes, note the bootstrap password printed in the terminal — you need it for first login. It is also written to `deploy\windows\bootstrap-admin.txt`.

If you want to skip auto-start tasks (not recommended):

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\install.ps1 -SkipStartupTasks
```

## Step 2: Login Cloudflare from This PC

Run:

```powershell
.\deploy\windows\bin\cloudflared.exe tunnel login
```

Browser will open Cloudflare page.
Approve your domain.

## Step 3: Create Tunnel

Run:

```powershell
.\deploy\windows\bin\cloudflared.exe tunnel create mls-site
```

Important:

- Save the tunnel ID shown in output.
- Save the credentials JSON path shown in output.

## Step 4: Create Public Hostname in Cloudflare

Run:

```powershell
.\deploy\windows\bin\cloudflared.exe tunnel route dns mls-site mls-site-test.kumarans.in
```

You can replace hostname with your own subdomain.

## Step 5: Fill Cloudflare Config File

Open this file:

- `deploy/windows/cloudflared.yml`

If it does not exist, copy from template:

- `deploy/windows/cloudflared.yml.template`

Put your real values:

```yaml
tunnel: YOUR_TUNNEL_ID
credentials-file: C:\Users\YOUR_USER\.cloudflared\YOUR_TUNNEL_ID.json

ingress:
  - hostname: mls-site-test.kumarans.in
    service: http://127.0.0.1:8080
  - service: http_status:404
```

The hostname here must be exactly the same as Step 4.

## Step 6: First Test (Manual)

Open 4 PowerShell windows and run one command in each:

Window 1:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_go2rtc.ps1
```

Window 2:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_caddy.ps1
```

Window 3:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_cammonitor.ps1
```

Window 4:

```powershell
powershell -ExecutionPolicy Bypass -File .\deploy\windows\run_cloudflared.ps1
```

## Step 7: Check URLs

Local URL should open:

- `http://127.0.0.1:8080`

Public URL should open:

- `https://mls-site-test.kumarans.in`

If local works but public does not, Cloudflare tunnel/DNS is the issue.

## Step 8: Connect Local Site to Central

In local dashboard:

1. Open `Edit Site Details`
2. Fill these:
   - `Dashboard URL` = your public URL
   - `Refresh URL` = `your-public-url/api/central-refresh`
   - `Central API URL` = central server API
3. Click `Register This Site`

## Quick Fixes (Very Common)

Public URL says **Could not resolve host**:

- DNS route command not done or wrong hostname.

Public URL says **1033**:

- cloudflared process not running.

Public URL says **502**:

- Caddy or app or go2rtc is down.
- Check:
  - `http://127.0.0.1:5001`
  - `http://127.0.0.1:8080`

Preview/video not opening:

- go2rtc is not running.

## Auto-Start Check

Installer creates startup tasks. Verify:

```powershell
schtasks /Query /TN CamMonitor-App
schtasks /Query /TN CamMonitor-go2rtc
schtasks /Query /TN CamMonitor-Caddy
schtasks /Query /TN CamMonitor-Cloudflared
```

If needed, run immediately:

```powershell
schtasks /Run /TN CamMonitor-go2rtc
schtasks /Run /TN CamMonitor-Caddy
schtasks /Run /TN CamMonitor-App
schtasks /Run /TN CamMonitor-Cloudflared
```
