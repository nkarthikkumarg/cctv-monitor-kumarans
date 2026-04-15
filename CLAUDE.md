# CLAUDE.md — cctv-monitor-kumarans

## Project overview

Two-tier CCTV monitoring system:

- **Local app** (`app.py`) — Flask dashboard running on each site's local server. Monitors cameras via ping, streams preview via go2rtc, syncs status to central.
- **Central dashboard** (`central_app.py`) — Flask app on Railway (PostgreSQL). Aggregates all sites, provides SSO into local dashboards, manages users.

---

## Architecture

```
Browser → Cloudflare Tunnel → Caddy (:8080) → Flask (:5001)
                                             → go2rtc (:1984)   ← RTSP cameras
```

- **Caddy** reverse proxies port 8080 → Flask 5001 and `/go2rtc/*` → go2rtc 1984
- **cloudflared** exposes port 8080 via Cloudflare Tunnel (HTTPS)
- **go2rtc** bridges RTSP camera streams to WebRTC/MSE for browser preview
- **APScheduler** runs `monitor.py` poll loop inside Flask process

---

## Key files

| File | Role |
|------|------|
| `app.py` | Local Flask app — all routes, JS, HTML (single-file) |
| `db.py` | SQLite access — cameras, status, events, daily_snapshots |
| `monitor.py` | Camera ping loop, state machine, health ticks |
| `preview.py` | Brand-aware RTSP/MJPEG URL builder (Hikvision, Dahua, Prama) |
| `central_sync.py` | Pushes site summary to central dashboard |
| `alerts.py` | Twilio SMS alert dispatch |
| `central_app.py` | Central Flask app (Railway) — multi-site aggregation |
| `deploy/linux/` | systemd service files + install.sh for Linux |
| `deploy/windows/` | Task Scheduler PS1 scripts + install.ps1 for Windows |
| `Caddyfile` | Caddy config for Mac dev. Linux uses `/etc/caddy/Caddyfile` |
| `config.ini` | Local config — credentials, ports, go2rtc, central API key |

---

## Database (SQLite — `cam_monitor.db`)

Tables: `cameras`, `status`, `events`, `daily_snapshots`, `users`, `alert_log`

- `cameras.active = 0` = soft delete (never hard-delete rows)
- `status` has one row per camera IP — online/offline state, last_seen, offline_since
- `daily_snapshots` — one row per (date, ip) — tracks `total_checks` and `downtime_min`
- **DB files are gitignored** — never committed

### Health % calculation

- `tick_daily_check(ip)` — called every poll for all cameras → increments `total_checks`
- `tick_downtime(ip, minutes)` — called every poll when camera is **offline** → increments `downtime_min` incrementally
- `record_came_online(ip)` — does NOT write `downtime_min` (already ticked incrementally)
- `_calc_uptime_pct(total_checks, downtime_min)` → `((checks - downtime) / checks) * 100`
- `health_7d` = 7-day rolling sum from `daily_snapshots`

### IP reuse / soft-delete pattern

When editing a camera IP or reusing a soft-deleted camera's IP:
1. Check conflict: `WHERE ip=? AND active=1` only (not soft-deleted)
2. Purge orphaned rows from ALL tables before rename: `cameras`, `status`, `events`, `daily_snapshots`

---

## SSO flow (central → local)

1. Central signs HMAC-SHA256 token using `site_registrations.api_key` (authoritative — not `site_summaries.site_api_key`)
2. Token expiry: 300s
3. Local verifies with `CENTRAL_API_KEY` from `config.ini`
4. On success: `login_user(remember=True)` + `session.permanent = True`

---

## go2rtc integration

- go2rtc binary at `tools/go2rtc/go2rtc` (Mac arm64)
- Config at `deploy/linux/go2rtc.yaml` — listens on `127.0.0.1:1984`
- RTSP URL built by `preview.py::get_stream_urls()`:
  - If `nvr_ip` set and different from camera `ip` → use NVR IP + `nvr_channel` for RTSP
  - Otherwise → use camera `ip` + `channel=1` (direct camera, always channel 1)
- Player mode: `webrtc,mse` — WebRTC preferred, MSE fallback
- **Pre-warm**: `POST /api/camera/<ip>/warm` fires background thread to open RTSP before iframe loads → reduces time-to-first-frame from ~2-3s to ~0.5-1s
- `warmCamera(ip)` called on camera row `onmouseenter` and at start of `openModal()`

---

## CSRF

- All state-changing JS fetches must use `apiFetch()` (adds `X-CSRF-Token` header)
- Raw `fetch()` only for read-only GETs or public endpoints

---

## Auto-start (Mac dev machine)

Four launchd plists in `~/Library/LaunchAgents/`:

| Plist | Binary/script |
|-------|--------------|
| `com.mls-site-test.cammonitor` | `.venv/bin/python run_local.py` in project root |
| `com.mls-site-test.go2rtc` | `tools/go2rtc/go2rtc -config deploy/linux/go2rtc.yaml` |
| `com.mls-site-test.caddy` | `caddy run --config Caddyfile` in project root |
| `com.mls-site-test.cloudflared` | system cloudflared, `~/.cloudflared/config.yml` |

All have `KeepAlive=true`. On sleep/wake processes are suspended (not killed) — no restart needed.

**Important:** All plists must point to `cctv-monitor-kumarans` (not the old `cam-monitor-v2`). If a service crashes with `Address already in use`, check for stale PIDs from crashed processes still holding the port.

## Auto-start (Linux)

systemd services: `go2rtc.service`, `cammonitor.service`, `caddy.service`, `cloudflared.service`

- All have `Restart=always`, `RestartSec=5`
- Start order via `After=` dependencies: go2rtc → cammonitor → caddy → cloudflared
- Installed by `deploy/linux/install.sh` to `/opt/cctv-monitor-kumarans/`

## Auto-start (Windows)

Task Scheduler tasks (ONSTART, SYSTEM, /DELAY 30s): `CamMonitor-App`, `CamMonitor-go2rtc`, `CamMonitor-Caddy`, `CamMonitor-Cloudflared`

Run scripts in `deploy/windows/run_*.ps1`:
- **Keep-alive loop** — restarts service on crash (5s backoff)
- **Single-instance guard** — checks port before starting, exits if already running
- **Port-wait ordering** — each script waits for upstream ports before starting

---

## Python venv (Mac)

```bash
cd "/Volumes/Hivelinks/Test Apps/cctv-monitor-kumarans"
python3 -m venv .venv
grep -v "^psycopg" requirements.txt | .venv/bin/pip install -r /dev/stdin
```

`psycopg` is excluded — only needed by the central app (Railway/PostgreSQL), not the local app (SQLite).

---

## Gitignore

DB files, pycache, logs, .env, .DS_Store are all ignored. Never commit `*.db`.

---

## Common pitfalls

- **502 after sleep** — check all four launchd plists point to the correct project path
- **`Address already in use`** — stale Python PID holding port 5001; kill it, launchd will restart
- **`UNIQUE constraint failed: status.ip`** — orphaned row in `status` for a soft-deleted camera IP; purge all orphans before IP rename
- **`Another camera already uses this IP address`** — conflict check must filter `AND active=1`
- **Health shows 100% for offline camera** — `downtime_min` only updates via `tick_downtime()` each poll; if that's not being called, camera is confirmed offline but `st["online"]` is `False`
- **SSO redirect loop** — central must sign token with `site_registrations.api_key`, not `site_summaries.site_api_key`
- **CSRF error on save** — route handler called with raw `fetch()` instead of `apiFetch()`
- **Preview RTSP wrong channel** — camera accessed directly must use `channel=1`; `nvr_channel` only applies when RTSP connects to `nvr_ip`
