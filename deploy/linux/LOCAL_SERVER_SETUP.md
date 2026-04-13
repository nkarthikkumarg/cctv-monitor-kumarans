# Linux Local Server Setup

## Fastest Install

For production-style local setup on Ubuntu/Debian, the easiest path is now:

```bash
sudo bash deploy/linux/install.sh
```

That installer will:

1. install OS packages
2. copy the app to `/opt/cctv-monitor-kumarans`
3. create the Python virtual environment
4. install Python requirements
5. install `go2rtc`
6. install `Caddy`
7. install and enable systemd services
8. generate a random app secret if the config still has the placeholder value
9. generate a bootstrap admin password if the config still has the default password
10. store the SQLite database in `/opt/cctv-monitor-kumarans/data/cam_monitor.db`

After it completes, open the server in a browser and finish the site configuration from the UI.

### First-run Setup Wizard

When you first visit the server (after logging in with the default credentials), the app walks you through a GUI wizard at `/setup`.
It lets you:
1. Save Site Details and Central API settings.
2. Import the camera Excel/CSV file.
3. Follow the inline Cloudflare/remote-access guidance.
4. Mark the setup as complete so future logins go straight to the dashboard.

The installer already installs `go2rtc`, `Caddy`, `ffmpeg`, `libopus0`, and the correct codec packages for your OS version (`libvpx7`/`libx264-164` on Ubuntu 22.04+, `libvpx6`/`libx264-155` on Ubuntu 20.04) so you get WebRTC playback out of the box—no extra dependencies to install.

The systemd services (`cammonitor`, `go2rtc`, `caddy`) are enabled with `Restart=always`, so a reboot keeps the stack running automatically.
`cammonitor` also starts in strict mode, which blocks production service startup if weak defaults are still present.

This is the recommended production model for each local site.

The local site machine runs:

1. `CamMonitor`
2. `go2rtc`
3. `Caddy`

`go2rtc` stays local to the server and converts camera RTSP streams into browser-friendly output.
Caddy fronts both CamMonitor and go2rtc on one site URL, so users only need a web browser.

## Recommended Platform

- Ubuntu 22.04+ or Debian 12+
- Wired Ethernet
- SSD storage
- 8 GB RAM or more

## Directory Layout

Recommended install path:

- `/opt/cctv-monitor-kumarans`

## Manual Install

Use this only if you do not want to use the one-command installer.

## 1. Install Python Environment

From the project directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## 2. Install go2rtc

Download the correct binary for your Linux architecture from:

- https://github.com/AlexxIT/go2rtc/releases

Example for Linux AMD64:

```bash
sudo curl -L -o /usr/local/bin/go2rtc https://github.com/AlexxIT/go2rtc/releases/download/v1.9.13/go2rtc_linux_amd64
sudo chmod +x /usr/local/bin/go2rtc
```

Example for Linux ARM64:

```bash
sudo curl -L -o /usr/local/bin/go2rtc https://github.com/AlexxIT/go2rtc/releases/download/v1.9.13/go2rtc_linux_arm64
sudo chmod +x /usr/local/bin/go2rtc
```

## 3. Confirm CamMonitor Config

In [config.ini](../../config.ini), keep:

```ini
[go2rtc]
enabled = true
base_url = http://127.0.0.1:1984
```

This keeps go2rtc private to the local machine.

## 4. Install systemd Service Files

Copy the bundled service files:

- [cammonitor.service](cammonitor.service)
- [go2rtc.service](go2rtc.service)

Commands:

```bash
sudo cp deploy/linux/cammonitor.service /etc/systemd/system/
sudo cp deploy/linux/go2rtc.service /etc/systemd/system/
sudo systemctl daemon-reload
```

## 5. Install Caddy

Install Caddy from the official package for your Linux distribution:

- https://caddyserver.com/docs/install

The bundled config is:

- [Caddyfile](Caddyfile)

It serves:

- `/` -> CamMonitor on `127.0.0.1:5001`
- `/go2rtc/*` -> go2rtc on `127.0.0.1:1984`

## 6. Install go2rtc Config

The bundled config is:

- [go2rtc.yaml](go2rtc.yaml)

It binds go2rtc only to localhost.

## 7. Create Local Service User

```bash
sudo useradd --system --home /opt/cctv-monitor-kumarans --shell /usr/sbin/nologin cammonitor
sudo chown -R cammonitor:cammonitor /opt/cctv-monitor-kumarans
```

## 8. Start Services

```bash
sudo systemctl enable --now go2rtc
sudo systemctl enable --now cammonitor
```

Start Caddy with the bundled `Caddyfile`, or install it as a service on the server.

## 9. Verify

Check local services:

```bash
sudo systemctl status go2rtc
sudo systemctl status cammonitor
sudo systemctl status caddy
```

Bootstrap login file:

- `/opt/cctv-monitor-kumarans/bootstrap-admin.txt`

Local URLs:

- `http://127.0.0.1:1984`
- `http://127.0.0.1:5001`
- `http://127.0.0.1:8080`
- `http://127.0.0.1:8080/api/health`

Dashboard URLs used by the browser:

- `https://your-site-subdomain/...`

The browser should only need the dashboard URL.

## Stream Flow

The final product flow is:

1. camera RTSP stream -> `go2rtc`
2. Caddy proxies `/go2rtc/*` to `go2rtc`
3. Caddy proxies `/` to CamMonitor
4. browser popup uses the proxied go2rtc player over the same site URL
5. double-click -> browser fullscreen

No VLC or RTSP player is required on the user machine.
