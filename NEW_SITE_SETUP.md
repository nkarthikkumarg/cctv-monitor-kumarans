# New Site Setup

This guide explains how to bring a brand new local site online and connect it to the central dashboard.

Use this for every new site deployment.

## What You Need

- A machine at the site that can reach the cameras
- This project copied to that machine
- Python environment set up
- `go2rtc` installed on that machine for browser-based live video in the popup
- `cloudflared` installed on that machine
- Access to the central dashboard at `https://cctv.kumarans.in`
- Access to Cloudflare for tunnel login

For the recommended Linux deployment model, also see:

- [LOCAL_SERVER_SETUP.md](deploy/linux/LOCAL_SERVER_SETUP.md)

## Naming Recommendation

Use one subdomain per site.

Examples:

- `mls-site.kumarans.in`
- `blr-site.kumarans.in`
- `mys-site.kumarans.in`

Use a short hostname that is easy to recognize.

## Step 1. Start The Local Site App

From the project folder, run:

```bash
./.venv/bin/python run_local.py
```

Check locally:

- `http://127.0.0.1:5001/login`
- `http://127.0.0.1:5001/api/health`

If this page opens, the local app is running.

For production, the preferred model is not to run this manually. Use the Linux service setup in:

- [LOCAL_SERVER_SETUP.md](deploy/linux/LOCAL_SERVER_SETUP.md)

## Step 2. Create The Site In Central

Open:

- `https://cctv.kumarans.in`

Then:

1. Sign in to the central dashboard
2. Open `Add New Site`
3. Enter:
   - `Site ID`
   - `Site Name`
   - `Campus`
4. Generate the site key

You will use these values on the local site:

- `site_id`
- `site_name`
- `campus`
- `api_key`
- `Central API URL = https://cctv.kumarans.in/api/site-summary`

**Important:** The `Central API URL` must start with `https://`. The local app blocks sync if the URL uses plain `http://`, to prevent API keys from being sent unencrypted.

## Step 3. Login To Cloudflare Tunnel

On the site machine:

```bash
cloudflared tunnel login
```

This opens Cloudflare login/authorization.

## Step 4. Create A Tunnel For The Site

Example:

```bash
cloudflared tunnel create blr-site
```

This creates:

- a tunnel name
- a tunnel ID
- a credentials JSON file in `~/.cloudflared/`

## Step 5. Create The Tunnel Config File

Create a config file like this:

```yaml
tunnel: <tunnel-id>
credentials-file: /Users/<user>/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: blr-site.kumarans.in
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Example:

```yaml
tunnel: 12345678-abcd-1234-abcd-1234567890ab
credentials-file: /Users/your-user/.cloudflared/12345678-abcd-1234-abcd-1234567890ab.json

ingress:
  - hostname: blr-site.kumarans.in
    service: http://127.0.0.1:8080
  - service: http_status:404
```

Store this file in the project folder if you want, for example:

- `cloudflared-blr-site.yml`

## Step 6. Create The DNS Route For The Subdomain

Run:

```bash
cloudflared tunnel route dns blr-site blr-site.kumarans.in
```

This creates the hostname mapping in Cloudflare DNS for that tunnel.

## Step 7. Start The Tunnel

Run:

```bash
cloudflared tunnel --config /path/to/cloudflared-blr-site.yml run blr-site
```

Example:

```bash
cloudflared tunnel --config "cloudflared-blr-site.yml" run blr-site
```

Check in browser:

- `https://blr-site.kumarans.in/login`

If this page opens, the public site URL is working.

## Step 8. Update Local Site Details

On the local site dashboard, open:

- `Edit Site Details`

Set these values:

- `Enable central sync = true`
- `Site ID = <generated site id>`
- `Site Name = <site name>`
- `Campus = <campus>`
- `Dashboard URL = https://blr-site.kumarans.in`
- `Refresh URL = https://blr-site.kumarans.in/api/central-refresh`
- `Central API URL = https://cctv.kumarans.in/api/site-summary`
- `Central API Key = <generated api key>`

Also fill local-only fields if needed:

- `Site Address`
- `Point of Contact`
- `Contact Phone`
- `Contact Email`

Save the settings.

## Step 9. Verify Central Sync

After saving:

1. Wait a few seconds
2. Open the central dashboard
3. Look for the site card under the configured campus

The card should show:

- total cameras
- online
- offline
- maintenance

## Step 10. Verify Click-Through

From the central dashboard:

1. Click the site card
2. It should open the local site dashboard through the public site URL

## Step 11. Verify Automatic Updates

Check that:

- local status changes appear on central without manual page reload
- the site badge changes between `Live` and `Stale` correctly

## Common Values Summary

For a sample site `blr-site.kumarans.in`:

- `Dashboard URL = https://blr-site.kumarans.in`
- `Refresh URL = https://blr-site.kumarans.in/api/central-refresh`
- `Central API URL = https://cctv.kumarans.in/api/site-summary`

## Troubleshooting

### Local app opens, public site does not

Check:

- tunnel is running
- hostname in tunnel config matches exactly
- `cloudflared tunnel route dns ...` was run
- Cloudflare DNS proxy is enabled for the tunnel hostname if required in your setup

### Public site opens, but central does not show the site

Check local `Site Details`:

- `Enable central sync = true`
- correct `Central API URL` — must start with `https://`, not `http://`
- correct `Central API Key`
- correct `Site ID`

### Central shows the site, but click-through fails

Check:

- `Dashboard URL` is correct
- tunnel is running
- public site login page opens directly in browser

### Central updates work, but site shows stale

Check:

- local app is still running
- tunnel is still running
- local site can still push to central

## Recommended Operations Pattern

Keep these running on the site machine:

1. Local Flask app
2. go2rtc
3. Caddy
4. Cloudflare Tunnel

If either stops, remote access or sync behavior will be affected.

For production, configure auto-start so reboot/power failure does not break operations:

- Linux: use [deploy/linux/LOCAL_SERVER_SETUP.md](deploy/linux/LOCAL_SERVER_SETUP.md) and enable `cammonitor`, `go2rtc`, `caddy` services. Keep cloudflared running as a service as well.
- Windows: use [deploy/windows/README.md](deploy/windows/README.md). The installer now creates startup tasks by default for app/go2rtc/caddy/cloudflared.
