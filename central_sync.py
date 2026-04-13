"""
central_sync.py — Push local site summary to the central dashboard.
"""
import configparser
import json
import logging
import os
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone, timedelta
from urllib.parse import quote

import certifi
import db

cfg = configparser.ConfigParser()
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.ini")
cfg.read(CONFIG_PATH)
log = logging.getLogger(__name__)
SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
_status = {
    "enabled": False,
    "healthy": False,
    "last_attempt_at": None,
    "last_success_at": None,
    "last_error": "",
    "api_url": "",
}


def reload_config():
    cfg.clear()
    cfg.read(CONFIG_PATH)


def _enabled():
    return cfg.getboolean("central", "enabled", fallback=False)


def get_status():
    _status["enabled"] = _enabled()
    _status["api_url"] = cfg.get("central", "api_url", fallback="").strip()
    return dict(_status)


def build_payload():
    stats = db.get_stats()
    dashboard_url = cfg.get("central", "dashboard_url", fallback="").strip()
    if not dashboard_url:
        host = cfg.get("web", "host", fallback="127.0.0.1")
        port = cfg.getint("web", "port", fallback=5000)
        host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
        dashboard_url = f"http://{host}:{port}"

    return {
        "site_id": cfg.get("central", "site_id", fallback="local-site").strip() or "local-site",
        "site_name": cfg.get("central", "site_name", fallback="Local Site").strip() or "Local Site",
        "campus": cfg.get("central", "campus", fallback="Local Campus").strip(),
        "site_address": cfg.get("central", "site_address", fallback="").strip(),
        "contact_name": cfg.get("central", "contact_name", fallback="").strip(),
        "contact_phone": cfg.get("central", "contact_phone", fallback="").strip(),
        "contact_email": cfg.get("central", "contact_email", fallback="").strip(),
        "dashboard_url": dashboard_url,
        "refresh_url": cfg.get("central", "refresh_url", fallback="").strip() or f"{dashboard_url.rstrip('/')}/api/central-refresh",
        "site_api_key": cfg.get("central", "api_key", fallback="local-dev-key"),
        "total": stats.get("total", 0),
        "online": stats.get("online", 0),
        "offline": stats.get("offline", 0),
        "maintenance": stats.get("maintenance", 0),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


def push_summary():
    _status["enabled"] = _enabled()
    _status["api_url"] = cfg.get("central", "api_url", fallback="").strip()
    _status["last_attempt_at"] = datetime.now(timezone.utc).isoformat()

    if not _enabled():
        _status["healthy"] = False
        _status["last_error"] = "Central sync disabled"
        return False

    url = cfg.get("central", "api_url", fallback="").strip()
    if not url:
        log.warning("Central sync enabled but api_url is missing.")
        _status["healthy"] = False
        _status["last_error"] = "Central API URL missing"
        return False
    if not url.lower().startswith("https://"):
        log.warning(
            "Central sync refused: api_url must use HTTPS to protect the API key. "
            "Current value starts with '%s'. Update config.ini [central] api_url.",
            url[:30],
        )
        _status["healthy"] = False
        _status["last_error"] = "api_url must be HTTPS"
        return False

    payload = build_payload()
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "X-API-Key": cfg.get("central", "api_key", fallback="local-dev-key"),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT) as resp:
            ok = 200 <= resp.status < 300
            if ok:
                log.info("Central sync successful for site '%s'.", payload["site_name"])
                _status["healthy"] = True
                _status["last_success_at"] = datetime.now(timezone.utc).isoformat()
                _status["last_error"] = ""
            else:
                log.warning("Central sync returned HTTP %s.", resp.status)
                _status["healthy"] = False
                _status["last_error"] = f"HTTP {resp.status}"
            return ok
    except urllib.error.HTTPError as exc:
        log.warning("Central sync failed with HTTP %s.", exc.code)
        _status["healthy"] = False
        _status["last_error"] = f"HTTP {exc.code}"
        return False
    except Exception as exc:
        log.warning("Central sync failed: %s", exc)
        _status["healthy"] = False
        _status["last_error"] = str(exc)
        return False


def sync_users():
    if not _enabled():
        return False
    api_url = cfg.get("central", "api_url", fallback="").strip()
    site_id = cfg.get("central", "site_id", fallback="").strip()
    api_key = cfg.get("central", "api_key", fallback="").strip()
    if not api_url or not site_id or not api_key:
        log.warning("Central user sync skipped: missing api_url, site_id, or api_key.")
        return False
    if not api_url.lower().startswith("https://"):
        log.warning("Central user sync refused: api_url must use HTTPS.")
        return False
    if api_url.endswith("/api/site-summary"):
        url = api_url[:-len("/api/site-summary")] + f"/api/site-users?site_id={quote(site_id, safe='')}"
    else:
        log.warning("Central user sync skipped: unsupported api_url format.")
        return False

    req = urllib.request.Request(url, headers={"X-API-Key": api_key}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=15, context=SSL_CONTEXT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        log.warning("Central user sync failed with HTTP %s.", exc.code)
        return False
    except Exception as exc:
        log.warning("Central user sync failed: %s", exc)
        return False

    offline_days = int(data.get("offline_valid_days") or 30)
    valid_until = (datetime.now(timezone.utc) + timedelta(days=offline_days)).isoformat()
    seen = []
    for user in data.get("users", []):
        username = (user.get("username") or "").strip()
        if not username:
            continue
        seen.append(username)
        db.upsert_central_user(
            username=username,
            display_name=(user.get("display_name") or username),
            password_hash=user.get("password_hash") or "",
            role=(user.get("role") or "viewer").strip().lower(),
            active=bool(user.get("active")),
            central_user_id=user.get("id"),
            valid_until=valid_until,
            central_updated_at=user.get("updated_at"),
            deleted=bool(user.get("deleted")),
        )
    db.mark_missing_central_users_deleted(seen, valid_until)
    log.info("Central user sync successful. %d user(s) processed.", len(seen))
    return True


def delete_remote_site(site_id, api_url, api_key):
    site_id = (site_id or "").strip()
    api_url = (api_url or "").strip()
    api_key = api_key or ""
    if not site_id or not api_url or not api_key:
        return False
    if not api_url.lower().startswith("https://"):
        log.warning("Central site cleanup refused: api_url must use HTTPS.")
        return False
    if api_url.endswith("/api/site-summary"):
        delete_url = f"{api_url}/{quote(site_id, safe='')}"
    else:
        return False
    req = urllib.request.Request(
        delete_url,
        headers={"X-API-Key": api_key},
        method="DELETE",
    )
    try:
        with urllib.request.urlopen(req, timeout=10, context=SSL_CONTEXT) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        log.warning("Central site cleanup failed for '%s': %s", site_id, exc)
        return False
