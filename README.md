# CCTV Monitor — Kumarans

Camera monitoring for Sri Kumaran Childrens Home Educational Council sites, with a central cloud dashboard for multi-site visibility.

For onboarding a brand new site, see:

- [NEW_SITE_SETUP.md](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/NEW_SITE_SETUP.md)
- [deploy/linux/LOCAL_SERVER_SETUP.md](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/deploy/linux/LOCAL_SERVER_SETUP.md)
- [deploy/windows/WINDOWS_LOCAL_SERVER_SETUP.md](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/deploy/windows/WINDOWS_LOCAL_SERVER_SETUP.md)
- [deploy/windows/README.md](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/deploy/windows/README.md)

## What This Repo Contains

This project now has two parts:

1. Local site monitor
   - Runs near the cameras
   - Polls cameras on the local network
   - Shows the full site dashboard
   - Lets you add/edit cameras, view logs, exports, and maintenance state

2. Central dashboard
   - Shows brief site summaries across multiple sites
   - Lets you generate and revoke per-site API keys
   - Opens each site's full local dashboard
   - Can be deployed to Railway with a simple custom domain

## Main Files

```text
app.py             Local site dashboard and APIs
monitor.py         Local polling scheduler
db.py              Local SQLite operations
central_sync.py    Local site -> central sync helper
central_app.py     Central cloud dashboard and registration APIs
config.ini         Local site configuration
cameras.csv        Local camera source list
requirements.txt   Python dependencies
Procfile           Railway startup command for central dashboard
```

## Local Site Quick Start

### Option A (Recommended for production Linux install)

Use the one-command installer on Ubuntu/Debian:

```bash
sudo bash deploy/linux/install.sh
```

Then open the proxy URL and finish configuration from the Setup Wizard (`/setup`):

- `http://<server-ip>:8080`

The installer also:

- generates a random Flask secret if the config still has the placeholder value
- converts the local SQLite path to an absolute production path
- replaces the default `admin/admin123` password with a generated password on first production install
- writes the bootstrap login to `/opt/cctv-monitor-kumarans/bootstrap-admin.txt`

Service auto-start is enabled for:

- `cammonitor`
- `go2rtc`
- `caddy`

For smoke checks after install:

- `http://127.0.0.1:8080/api/health`

Detailed Linux guide:

- [deploy/linux/LOCAL_SERVER_SETUP.md](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/deploy/linux/LOCAL_SERVER_SETUP.md)

### Option B (Local/dev run from source)

1. Install Python 3.10+.
2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Run local app:

```bash
python app.py
```

Local/dev dashboard:

- `http://127.0.0.1:5000` (or your configured `[web]` port)

### Configure local site identity and central sync

Update [config.ini](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/config.ini):

- dashboard username/password
- email and WhatsApp settings if needed
- local site identity under `[central]`

Important `[central]` fields:

```ini
[central]
enabled = true
site_id = blr-campus-1
site_name = Bangalore Campus
campus = South Campus
site_address = Admin Block
contact_name = Security Control Room
contact_phone = +91XXXXXXXXXX
contact_email = controlroom@example.com
dashboard_url = http://127.0.0.1:5001
api_url = https://monitor.yourdomain.com/api/site-summary
api_key = generated-from-central
refresh_url =
```

Production-style example:

```ini
[central]
enabled = true
site_id = mls-campus-skch
site_name = MLS Campus
campus = Mallasandra
site_address = Admin Block
contact_name = Security Control Room
contact_phone = +91XXXXXXXXXX
contact_email = controlroom@example.com
dashboard_url = https://mls-site-test.kumarans.in
api_url = https://cctv.kumarans.in/api/site-summary
api_key = generated-from-central
refresh_url = https://mls-site-test.kumarans.in/api/central-refresh
```

### Add cameras

Edit [cameras.csv](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/cameras.csv).

Columns:

```text
ip,name,location,zone,nvr_name,nvr_channel,brand,username,password,notes
```

Supported brands:

- `hikvision`
- `dahua`
- `prama`

In production installs, camera import is available directly from the Setup Wizard and dashboard UI.

## Local Site Features

- Filterable table-based camera dashboard
- Add and edit individual cameras
- Camera detail popups with preview, RTSP, notes, and logs
- Audit log and camera log pages
- Manual refresh and scheduled polling
- Maintenance mode
- Bulk upload and exports
- Site Details GUI for updating local site identity and central connection settings
- `Register This Site` action to request a real site key from central

## Central Dashboard Quick Start

### Run locally

```bash
python central_app.py
```

Central dashboard:

- `http://127.0.0.1:5100`

Central connect page:

- `http://127.0.0.1:5100/connect-site`

## Central Dashboard Features

- Site overview cards with total, online, offline, maintenance
- Campus grouping
- Click-through to each local site dashboard
- Separate `Add New Site` page
- One-click API key generation for local sites
- Registered site key list
- Delete key with double confirmation
- Revoking a key removes the site registration and blocks further sync with that key

## How Local Sites Connect To Central

There are two supported paths:

### Recommended

From the local site dashboard:

1. Open `Edit Site Details`
2. Fill `site_id`, `site_name`, `campus`, and `api_url`
3. Click `Register This Site`
4. The local site requests a generated key from central
5. The key is saved into `config.ini`
6. The local site starts syncing as a formally registered site

### Manual

From the central connect page:

1. Generate a site key
2. Copy the generated values
3. Paste them into the local site's `Edit Site Details` form
4. Save

## Railway Deployment For Central Dashboard

This repo is prepared for Railway deployment of the central dashboard.

### Included deployment files

- [railway.toml](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/railway.toml) — Railway build and deploy config
- [Procfile](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/Procfile) — fallback startup command
- [requirements.txt](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/requirements.txt) with `gunicorn`
- [central_app.py](/Volumes/Hivelinks/Test%20Apps/cam-monitor-v2/central_app.py) with Railway `PORT` support

### Railway environment variables

```env
CENTRAL_API_KEY=replace-with-a-long-random-secret
CENTRAL_PUBLIC_URL=https://cctv.kumarans.in
DATABASE_URL=provided-by-railway-postgres
CENTRAL_DASHBOARD_USERNAME=admin
CENTRAL_DASHBOARD_PASSWORD=replace-with-a-strong-password
HTTPS_ONLY=true
```

Notes:

- `PORT` is provided by Railway automatically
- `CENTRAL_PUBLIC_URL` should be your final public domain, for example `https://cctv.kumarans.in`
- no trailing slash
- `DATABASE_URL` should come from Railway Postgres in production
- `CENTRAL_DASHBOARD_USERNAME` and `CENTRAL_DASHBOARD_PASSWORD` set the central login credentials (defaults: `admin` / `admin123` — always override in production)
- `HTTPS_ONLY=true` enforces secure session cookies on Railway (already the default on Railway)

### Railway startup

Railway reads `railway.toml` automatically:

```toml
[deploy]
startCommand = "gunicorn --bind 0.0.0.0:$PORT --workers 4 --timeout 120 --access-logfile - central_app:app"
healthcheckPath = "/health"
```

### Deploy flow

1. Push this repo to GitHub
2. Create a Railway project from the repo
3. Railway builds with Nixpacks (no Dockerfile needed)
4. Add Railway variables listed above
5. Add your custom domain in Railway
6. Point your DNS to Railway
7. Use the built-in app login for central access

## Adding A New Local Site With Cloudflare Tunnel

This is the repeatable pattern for each new site:

1. Run the local site app on the site machine
2. Create one subdomain for that site
3. Create one Cloudflare Tunnel for that site
4. Point the tunnel hostname to the local app port
5. Put that public hostname into local `Site Details`
6. Register the site against the central dashboard

Suggested hostname pattern:

- `mls-site.kumarans.in`
- `blr-site.kumarans.in`
- `mys-site.kumarans.in`

Example tunnel config:

```yaml
tunnel: <tunnel-id>
credentials-file: /Users/<user>/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: mls-site.kumarans.in
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Typical tunnel commands:

```bash
cloudflared tunnel login
cloudflared tunnel create mls-site
cloudflared tunnel route dns mls-site mls-site.kumarans.in
cloudflared tunnel --config /path/to/cloudflared-mls-site.yml run mls-site
```

Then update the local site:

- `Dashboard URL = https://mls-site.kumarans.in`
- `Refresh URL = https://mls-site.kumarans.in/api/central-refresh`
- `Central API URL = https://cctv.kumarans.in/api/site-summary`
- `Central API Key = generated-from-central`

The central dashboard will then:

- show that site summary
- open the site dashboard by clicking the site card
- receive quick updates from the local site

## Important Production Notes

### 1. Do not use `local-dev-key` in production

Every site should be formally registered and use its generated key.

### 2. `api_url` must use HTTPS

The local site refuses to sync with the central dashboard if `api_url` does not start with `https://`.
This is enforced in code to prevent API keys from being sent over plain HTTP.

```ini
; Correct
api_url = https://cctv.kumarans.in/api/site-summary

; Will NOT work — sync will be blocked
api_url = http://cctv.kumarans.in/api/site-summary
```

### 3. Central cloud should use Postgres in production

The central dashboard supports:

- local testing: SQLite fallback (`central_dashboard.db`)
- production: Postgres through `DATABASE_URL`

Use Railway Postgres for the central dashboard in production.

### 4. Local site and central cloud are different deployments

- local site code runs near cameras
- central dashboard runs in the cloud
- local site data sync happens through API
- code deployments happen through Git push + Railway deploy

## Git / GitHub Flow

Recommended flow for central dashboard updates:

1. Make changes locally
2. Test locally
3. Commit to Git
4. Push to GitHub
5. Railway auto-deploys

## Troubleshooting

### Local site shows on central dashboard but not under registered keys

That usually means the site is syncing with a fallback key and has not been formally registered yet.

Use:

- local dashboard -> `Edit Site Details` -> `Register This Site`

### Local site cannot sync to central

Check:

- `api_url`
- `api_key`
- central domain is reachable
- HTTPS certificate is valid
- revoked keys have not been deleted from central

### Deleted key but site still appears briefly

The central dashboard removes the registration immediately, but the site may try to sync again until its local config is updated. Once the revoked key is rejected, syncing stops.

### Railway deploy starts but central URLs look wrong

Make sure:

- `CENTRAL_PUBLIC_URL` is set correctly
- it uses your public domain
- it does not have a trailing slash

## Current Architecture Summary

- `app.py` = local site operations
- `central_app.py` = central cloud operations
- `central_sync.py` = bridge from local site to central cloud

This lets you run many local sites independently while still getting one central overview in the cloud.
