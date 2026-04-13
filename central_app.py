"""
central_app.py — Lightweight central dashboard for site summaries.
Run: python central_app.py
"""
import json
import logging
import logging.handlers
import os
import ssl
import secrets
import threading
import time
import base64
import hashlib
import hmac
import certifi
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import wraps
import urllib.error
import urllib.request
from urllib.parse import urlencode

from flask import Flask, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
USE_POSTGRES = bool(DATABASE_URL and not DATABASE_URL.startswith("sqlite"))

if USE_POSTGRES:
    import psycopg
    from psycopg.rows import dict_row
else:
    import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "central_dashboard.db")
API_KEY = os.environ.get("CENTRAL_API_KEY", "local-dev-key")
CENTRAL_HOST = os.environ.get("CENTRAL_HOST", "0.0.0.0")
CENTRAL_PORT = int(os.environ.get("PORT") or os.environ.get("CENTRAL_PORT", "5100"))
CENTRAL_PUBLIC_URL = (os.environ.get("CENTRAL_PUBLIC_URL", "").strip() or
                      os.environ.get("RAILWAY_PUBLIC_DOMAIN", "").strip())
CENTRAL_DASHBOARD_USERNAME = os.environ.get("CENTRAL_DASHBOARD_USERNAME", "admin")
CENTRAL_DASHBOARD_PASSWORD = os.environ.get("CENTRAL_DASHBOARD_PASSWORD", "admin123")
CENTRAL_SECRET_KEY = os.environ.get("CENTRAL_SECRET_KEY", "change-this-central-secret")

# ── Startup warnings ──────────────────────────────────────────────────────────
_WEAK_SECRETS = {"", "change-this-central-secret"}

def _check_startup():
    warnings = []
    if CENTRAL_SECRET_KEY in _WEAK_SECRETS or len(CENTRAL_SECRET_KEY) < 32:
        warnings.append("CENTRAL_SECRET_KEY env var must be set to a strong random value (>= 32 chars)")
    if CENTRAL_DASHBOARD_PASSWORD in ("admin123", ""):
        warnings.append("CENTRAL_DASHBOARD_PASSWORD env var must be changed from the default")
    if API_KEY in ("local-dev-key", ""):
        warnings.append("CENTRAL_API_KEY env var should be set to a strong random value")
    if USE_POSTGRES and not DATABASE_URL:
        warnings.append("DATABASE_URL is not set — data will be lost on container restart")
    for w in warnings:
        logging.warning("Central startup warning: %s", w)
    return warnings

# ── Logging setup ─────────────────────────────────────────────────────────────
_LOG_FMT = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
_sh = logging.StreamHandler()
_sh.setFormatter(_LOG_FMT)
logging.basicConfig(level=logging.INFO, handlers=[_sh])
log = logging.getLogger(__name__)

# ── SSL context for outbound requests ────────────────────────────────────────
_SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())

# ── Login rate limiting ───────────────────────────────────────────────────────
_login_attempts: dict = defaultdict(list)
_login_lock = threading.Lock()
_LOGIN_WINDOW = 300
_LOGIN_MAX = 20

def _check_login_rate_limit(ip: str) -> bool:
    now = time.monotonic()
    with _login_lock:
        _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _LOGIN_WINDOW]
        if len(_login_attempts[ip]) >= _LOGIN_MAX:
            return True
        _login_attempts[ip].append(now)
        return False

def _clear_login_attempts(ip: str) -> None:
    with _login_lock:
        _login_attempts.pop(ip, None)

app = Flask(__name__)
app.secret_key = CENTRAL_SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # True in production (Railway/HTTPS). Set HTTPS_ONLY=false env var for local HTTP dev.
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ONLY", "true").lower() not in ("false", "0", "no"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=12),
)

# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def _add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self'"
    )
    return response


def _get_csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]

def _valid_login_csrf() -> bool:
    expected = session.get("_csrf")
    provided = request.form.get("_csrf")
    return bool(expected and provided and hmac.compare_digest(expected, provided))


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("central_user"):
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


@contextmanager
def get_db():
    if USE_POSTGRES:
        conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    else:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _sql(query):
    return query.replace("?", "%s") if USE_POSTGRES else query


def db_execute(conn, query, params=()):
    return conn.execute(_sql(query), params)


def db_fetchone(conn, query, params=()):
    row = db_execute(conn, query, params).fetchone()
    return dict(row) if row else None


def db_fetchall(conn, query, params=()):
    return [dict(r) for r in db_execute(conn, query, params).fetchall()]


def id_column_sql():
    return "BIGSERIAL PRIMARY KEY" if USE_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"


def init_db():
    with get_db() as conn:
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS site_summaries (
                site_id TEXT PRIMARY KEY,
                site_name TEXT NOT NULL,
                dashboard_url TEXT NOT NULL,
                refresh_url TEXT,
                site_api_key TEXT,
                campus TEXT,
                site_address TEXT,
                contact_name TEXT,
                contact_phone TEXT,
                contact_email TEXT,
                total INTEGER DEFAULT 0,
                online INTEGER DEFAULT 0,
                offline INTEGER DEFAULT 0,
                maintenance INTEGER DEFAULT 0,
                updated_at TEXT,
                last_received_at TEXT NOT NULL,
                raw_payload TEXT
            )
        """)
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS site_registrations (
                site_id TEXT PRIMARY KEY,
                site_name TEXT NOT NULL,
                campus TEXT,
                api_key TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS users (
                id """ + id_column_sql() + """,
                username TEXT UNIQUE NOT NULL,
                display_name TEXT,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                active INTEGER NOT NULL DEFAULT 1,
                deleted INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        db_execute(conn, """
            CREATE TABLE IF NOT EXISTS audit (
                id """ + id_column_sql() + """,
                ts TEXT NOT NULL,
                user_name TEXT,
                event_type TEXT,
                description TEXT,
                target TEXT,
                ip_address TEXT,
                result TEXT
            )
        """)
        if USE_POSTGRES:
            for col in ("refresh_url", "site_api_key", "site_address", "contact_name", "contact_phone", "contact_email"):
                db_execute(conn, f"ALTER TABLE site_summaries ADD COLUMN IF NOT EXISTS {col} TEXT")
            db_execute(conn, "ALTER TABLE users ADD COLUMN IF NOT EXISTS display_name TEXT")
        else:
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(site_summaries)").fetchall()]
            if "refresh_url" not in cols:
                conn.execute("ALTER TABLE site_summaries ADD COLUMN refresh_url TEXT")
            if "site_api_key" not in cols:
                conn.execute("ALTER TABLE site_summaries ADD COLUMN site_api_key TEXT")
            if "site_address" not in cols:
                conn.execute("ALTER TABLE site_summaries ADD COLUMN site_address TEXT")
            if "contact_name" not in cols:
                conn.execute("ALTER TABLE site_summaries ADD COLUMN contact_name TEXT")
            if "contact_phone" not in cols:
                conn.execute("ALTER TABLE site_summaries ADD COLUMN contact_phone TEXT")
            if "contact_email" not in cols:
                conn.execute("ALTER TABLE site_summaries ADD COLUMN contact_email TEXT")
            user_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "display_name" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
        ensure_default_admin(conn)


def add_audit(user_name, event_type, description, target, ip_address, result):
    with get_db() as conn:
        db_execute(conn, """
            INSERT INTO audit (ts, user_name, event_type, description, target, ip_address, result)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (utc_now_iso(), user_name, event_type, description, target, ip_address, result))


def get_audit_log(limit=100, offset=0, event_type=None, search=None, result=None, user_name=None, date_from=None, date_to=None):
    with get_db() as conn:
        query = "SELECT * FROM audit"
        params = []
        filters = []
        if user_name:
            filters.append("user_name=?")
            params.append(user_name)
        if event_type and event_type != "all":
            filters.append("event_type=?")
            params.append(event_type)
        if result and result != "all":
            filters.append("result=?")
            params.append(result)
        if search:
            filters.append("(user_name LIKE ? OR description LIKE ? OR target LIKE ?)")
            params.extend([f"%{search}%"] * 3)
        if date_from:
            filters.append("ts >= ?")
            params.append(f"{date_from}T00:00:00")
        if date_to:
            filters.append("ts <= ?")
            params.append(f"{date_to}T23:59:59")
        if filters:
            query += " WHERE " + " AND ".join(filters)
        count_query = "SELECT COUNT(*) AS total FROM audit"
        if filters:
            count_query += " WHERE " + " AND ".join(filters)
        total_row = db_fetchone(conn, count_query, params)
        total = int((total_row or {}).get("total") or 0)
        query += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        page_params = list(params) + [limit, offset]
        items = db_fetchall(conn, query, page_params)
        return {"items": items, "total": total}


def get_audit_users():
    with get_db() as conn:
        rows = db_fetchall(conn, """
            SELECT DISTINCT user_name
            FROM audit
            WHERE user_name IS NOT NULL AND TRIM(user_name) <> ''
            ORDER BY user_name
        """)
    return [r["user_name"] for r in rows]


def ensure_default_admin(conn):
    existing = db_fetchone(conn, "SELECT * FROM users WHERE username=?", (CENTRAL_DASHBOARD_USERNAME,))
    now = utc_now_iso()
    if existing:
        if existing.get("role") != "admin" or not existing.get("active"):
            db_execute(
                conn,
                "UPDATE users SET display_name=?, role='admin', active=1, deleted=0, updated_at=? WHERE LOWER(username)=LOWER(?)",
                ("Administrator", now, CENTRAL_DASHBOARD_USERNAME),
            )
        return
    db_execute(conn, """
        INSERT INTO users (username, display_name, password_hash, role, active, deleted, created_at, updated_at)
        VALUES (?, ?, ?, 'admin', 1, 0, ?, ?)
    """, (CENTRAL_DASHBOARD_USERNAME, "Administrator", generate_password_hash(CENTRAL_DASHBOARD_PASSWORD), now, now))


def central_api_url():
    if CENTRAL_PUBLIC_URL:
        base = CENTRAL_PUBLIC_URL
        if not base.startswith(("http://", "https://")):
            base = f"https://{base}"
        return f"{base.rstrip('/')}/api/site-summary"
    return f"http://127.0.0.1:{CENTRAL_PORT}/api/site-summary"


def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()


def resolve_log_range(preset, from_str, to_str):
    today = datetime.now().date()
    if preset == "1m":
        start = today - timedelta(days=29)
        end = today
    elif preset == "3m":
        start = today - timedelta(days=89)
        end = today
    elif preset == "custom" and from_str and to_str:
        start = datetime.strptime(from_str, "%Y-%m-%d").date()
        end = datetime.strptime(to_str, "%Y-%m-%d").date()
        if end < start:
            start, end = end, start
    else:
        start = today - timedelta(days=6)
        end = today
    return start.isoformat(), end.isoformat()


def lookup_registered_site(site_id):
    with get_db() as conn:
        return db_fetchone(conn, "SELECT * FROM site_registrations WHERE site_id=?", (site_id,))


def is_valid_site_auth(site_id, auth):
    """Master key OR registered per-site key (used for user-sync, refresh, delete)."""
    if not auth:
        return False
    if hmac.compare_digest(auth, API_KEY):
        return True
    reg = lookup_registered_site(site_id)
    site_key = (reg or {}).get("api_key") or ""
    return bool(site_key and hmac.compare_digest(auth, site_key))


def is_registered_site_auth(site_id, auth):
    """Strict check: only a registered per-site key is accepted.
    Used for /api/site-summary so sites cannot push data until an
    admin has explicitly registered them via 'Add New Site'."""
    if not auth or not site_id:
        return False
    reg = lookup_registered_site(site_id)
    site_key = (reg or {}).get("api_key") or ""
    return bool(site_key and hmac.compare_digest(auth, site_key))


def current_central_user():
    user_id = session.get("central_user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return db_fetchone(conn, "SELECT * FROM users WHERE id=?", (user_id,))


def central_actor_name():
    user = current_central_user()
    if not user:
        return session.get("central_user") or "system"
    return user.get("display_name") or user.get("username") or "system"


def _b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def build_site_sso_url(site, user):
    dashboard_url = (site.get("dashboard_url") or "").strip()
    site_api_key = (site.get("site_api_key") or "").strip()
    if not dashboard_url or not site_api_key or not user:
        return dashboard_url
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "username": user["username"],
        "display_name": user.get("display_name") or user["username"],
        "role": user.get("role") or "viewer",
        "iat": now,
        "exp": now + 90,
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(site_api_key.encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).digest()
    token = f"{payload_b64}.{_b64url_encode(signature)}"
    return f"{dashboard_url.rstrip('/')}/sso-login?{urlencode({'token': token})}"


def trigger_user_sync_for_sites():
    results = []
    with get_db() as conn:
        rows = db_fetchall(conn, "SELECT site_id, site_name, dashboard_url, site_api_key FROM site_summaries ORDER BY site_name")
    for row in rows:
        dashboard_url = (row.get("dashboard_url") or "").strip()
        api_key = row.get("site_api_key") or ""
        if not dashboard_url:
            results.append({"site_id": row["site_id"], "success": False, "error": "No dashboard URL"})
            continue
        sync_url = f"{dashboard_url.rstrip('/')}/api/central-sync-users"
        req = urllib.request.Request(
            sync_url,
            data=b"{}",
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=_SSL_CONTEXT) as resp:
                results.append({"site_id": row["site_id"], "success": 200 <= resp.status < 300})
        except Exception as exc:
            results.append({"site_id": row["site_id"], "success": False, "error": str(exc)})
    return results


def central_role_required(*roles):
    role_rank = {"viewer": 1, "operator": 2, "admin": 3}
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_central_user()
            if not user:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Unauthorized"}), 401
                return redirect(url_for("login", next=request.path))
            current_rank = role_rank.get(user.get("role"), 0)
            needed_rank = max(role_rank.get(role, 0) for role in roles)
            if current_rank < needed_rank:
                if request.path.startswith("/api/"):
                    return jsonify({"error": "Forbidden"}), 403
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not _valid_login_csrf():
            error = "Invalid request. Please refresh and try again."
            return render_template_string(LOGIN_HTML, error=error, csrf_token=_get_csrf_token())
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        ip = request.remote_addr
        if _check_login_rate_limit(ip):
            add_audit(username, "login", "Central login blocked — rate limit exceeded", "Central Dashboard", ip, "failed")
            error = "Too many login attempts. Please wait a few minutes and try again."
            return render_template_string(LOGIN_HTML, error=error, csrf_token=_get_csrf_token())
        with get_db() as conn:
            user = db_fetchone(conn, "SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (username,))
        if user and user.get("active") and not user.get("deleted") and user.get("password_hash") and check_password_hash(user["password_hash"], password):
            _clear_login_attempts(ip)
            session["central_user"] = user["username"]
            session["central_user_id"] = user["id"]
            session["central_user_role"] = user["role"]
            add_audit(user.get("display_name") or user["username"], "login", "Central user logged in successfully", "Central Dashboard", ip, "success")
            return redirect(request.args.get("next") or url_for("dashboard"))
        add_audit(username, "login", "Failed central login attempt", "Central Dashboard", ip, "failed")
        error = "Invalid username or password"
    return render_template_string(LOGIN_HTML, error=error, csrf_token=_get_csrf_token())


@app.route("/logout")
@login_required
def logout():
    add_audit(central_actor_name(), "logout", "Central user logged out", "Central Dashboard", request.remote_addr, "success")
    session.pop("central_user", None)
    session.pop("central_user_id", None)
    session.pop("central_user_role", None)
    return redirect(url_for("login"))


@app.route("/api/site-summary", methods=["POST"])
def upsert_site_summary():
    payload = request.get_json(silent=True) or {}
    site_id = (payload.get("site_id") or "").strip()
    site_name = (payload.get("site_name") or "").strip()
    dashboard_url = (payload.get("dashboard_url") or "").strip()
    if not site_id or not site_name or not dashboard_url:
        return jsonify({"error": "site_id, site_name, and dashboard_url are required"}), 400
    auth = request.headers.get("X-API-Key", "")
    if not is_registered_site_auth(site_id, auth):
        return jsonify({"error": "Unauthorized: site must be registered via the central dashboard before syncing"}), 401

    with get_db() as conn:
        refresh_url = (payload.get("refresh_url") or "").strip()
        db_execute(conn, """
            DELETE FROM site_summaries
            WHERE site_id <> ?
              AND site_api_key = ?
              AND (dashboard_url = ? OR (? <> '' AND refresh_url = ?))
        """, (site_id, auth, dashboard_url, refresh_url, refresh_url))
        db_execute(conn, """
            INSERT INTO site_summaries (
                site_id, site_name, dashboard_url, campus, site_address, contact_name,
                contact_phone, contact_email, total, online, offline,
                maintenance, updated_at, last_received_at, raw_payload, refresh_url, site_api_key
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(site_id) DO UPDATE SET
                site_name=excluded.site_name,
                dashboard_url=excluded.dashboard_url,
                campus=excluded.campus,
                site_address=excluded.site_address,
                contact_name=excluded.contact_name,
                contact_phone=excluded.contact_phone,
                contact_email=excluded.contact_email,
                total=excluded.total,
                online=excluded.online,
                offline=excluded.offline,
                maintenance=excluded.maintenance,
                updated_at=excluded.updated_at,
                last_received_at=excluded.last_received_at,
                raw_payload=excluded.raw_payload,
                refresh_url=excluded.refresh_url,
                site_api_key=excluded.site_api_key
        """, (
            site_id,
            site_name,
            dashboard_url,
            (payload.get("campus") or "").strip(),
            (payload.get("site_address") or "").strip(),
            (payload.get("contact_name") or "").strip(),
            (payload.get("contact_phone") or "").strip(),
            (payload.get("contact_email") or "").strip(),
            int(payload.get("total") or 0),
            int(payload.get("online") or 0),
            int(payload.get("offline") or 0),
            int(payload.get("maintenance") or 0),
            payload.get("updated_at") or utc_now_iso(),
            utc_now_iso(),
            json.dumps(payload),
            refresh_url,
            auth,
        ))
    return jsonify({"success": True, "site_id": site_id})


@app.route("/api/site-summary/<site_id>", methods=["DELETE"])
def delete_site_summary(site_id):
    auth = request.headers.get("X-API-Key", "")
    site_id = (site_id or "").strip()
    if not site_id or not is_valid_site_auth(site_id, auth):
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        db_execute(conn, "DELETE FROM site_summaries WHERE site_id=?", (site_id,))
    return jsonify({"success": True, "site_id": site_id})


@app.route("/api/sites")
@login_required
def api_sites():
    user = current_central_user()
    with get_db() as conn:
        rows = db_fetchall(conn, "SELECT * FROM site_summaries ORDER BY COALESCE(campus, ''), site_name")
    for row in rows:
        row["sso_url"] = build_site_sso_url(row, user)
    return jsonify(rows)


@app.route("/api/registrations")
@login_required
def api_registrations():
    with get_db() as conn:
        return jsonify({
            "central_api_url": central_api_url(),
            "items": db_fetchall(conn, "SELECT * FROM site_registrations ORDER BY COALESCE(campus, ''), site_name")
        })


@app.route("/api/users", methods=["GET", "POST"])
@login_required
@central_role_required("admin")
def api_users():
    if request.method == "GET":
        with get_db() as conn:
            return jsonify(db_fetchall(conn, """
                SELECT id, username, display_name, role, active, deleted, created_at, updated_at
                FROM users
                ORDER BY username
            """))

    payload = request.get_json(silent=True) or {}
    username = (payload.get("username") or "").strip()
    display_name = (payload.get("display_name") or username).strip()
    password = payload.get("password") or ""
    role = (payload.get("role") or "viewer").strip().lower()
    active = 1 if payload.get("active", True) else 0
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if role not in {"viewer", "operator", "admin"}:
        return jsonify({"error": "invalid role"}), 400
    now = utc_now_iso()
    with get_db() as conn:
        if db_fetchone(conn, "SELECT id FROM users WHERE LOWER(username)=LOWER(?)", (username,)):
            return jsonify({"error": "username already exists"}), 400
        db_execute(conn, """
            INSERT INTO users (username, display_name, password_hash, role, active, deleted, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        """, (username, display_name, generate_password_hash(password), role, active, now, now))
        user = db_fetchone(conn, """
            SELECT id, username, display_name, role, active, deleted, created_at, updated_at
            FROM users WHERE LOWER(username)=LOWER(?)
        """, (username,))
    add_audit(central_actor_name(), "user", f"Created central user {display_name or username}", username, request.remote_addr, "success")
    return jsonify({"success": True, "user": user, "site_sync": trigger_user_sync_for_sites()})


@app.route("/api/users/<int:user_id>", methods=["PATCH"])
@login_required
@central_role_required("admin")
def api_update_user(user_id):
    payload = request.get_json(silent=True) or {}
    with get_db() as conn:
        user = db_fetchone(conn, "SELECT * FROM users WHERE id=?", (user_id,))
        if not user:
            return jsonify({"error": "user not found"}), 404
        if user["id"] == session.get("central_user_id"):
            if payload.get("active") is False:
                return jsonify({"error": "You cannot disable your own account"}), 400
            if payload.get("role") and payload.get("role") != "admin":
                return jsonify({"error": "You cannot remove your own admin access"}), 400
        role = (payload.get("role") or user["role"]).strip().lower()
        display_name = (payload.get("display_name") or user.get("display_name") or user["username"]).strip()
        if role not in {"viewer", "operator", "admin"}:
            return jsonify({"error": "invalid role"}), 400
        active = user["active"] if payload.get("active") is None else (1 if payload.get("active") else 0)
        deleted = user["deleted"] if payload.get("deleted") is None else (1 if payload.get("deleted") else 0)
        password_hash = user["password_hash"]
        if payload.get("password"):
            password_hash = generate_password_hash(payload["password"])
        db_execute(conn, """
            UPDATE users
            SET display_name=?, role=?, active=?, deleted=?, password_hash=?, updated_at=?
            WHERE id=?
        """, (display_name, role, active, deleted, password_hash, utc_now_iso(), user_id))
        updated = db_fetchone(conn, """
            SELECT id, username, display_name, role, active, deleted, created_at, updated_at
            FROM users WHERE id=?
        """, (user_id,))
    add_audit(central_actor_name(), "user", f"Updated central user {updated.get('display_name') or updated['username']}", updated["username"], request.remote_addr, "success")
    return jsonify({"success": True, "user": updated, "site_sync": trigger_user_sync_for_sites()})


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@central_role_required("admin")
def api_delete_user(user_id):
    with get_db() as conn:
        user = db_fetchone(conn, """
            SELECT id, username, display_name, role
            FROM users
            WHERE id=?
        """, (user_id,))
        if not user:
            return jsonify({"error": "user not found"}), 404
        if user["id"] == session.get("central_user_id"):
            return jsonify({"error": "You cannot delete your own account"}), 400
        db_execute(conn, "DELETE FROM users WHERE id=?", (user_id,))
    add_audit(central_actor_name(), "user", f"Deleted central user {user.get('display_name') or user['username']}", user["username"], request.remote_addr, "success")
    return jsonify({
        "success": True,
        "deleted_user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user.get("display_name") or user["username"],
        },
        "site_sync": trigger_user_sync_for_sites(),
    })


@app.route("/api/site-users", methods=["GET"])
def api_site_users():
    site_id = (request.args.get("site_id") or "").strip()
    auth = request.headers.get("X-API-Key", "")
    if not site_id:
        return jsonify({"error": "site_id is required"}), 400
    if not is_valid_site_auth(site_id, auth):
        return jsonify({"error": "Unauthorized"}), 401
    with get_db() as conn:
        users = db_fetchall(conn, """
            SELECT id, username, display_name, password_hash, role, active, deleted, updated_at
            FROM users
            ORDER BY username
        """)
    return jsonify({
        "success": True,
        "site_id": site_id,
        "synced_at": utc_now_iso(),
        "offline_valid_days": 30,
        "users": users,
    })


@app.route("/api/register-site", methods=["POST"])
@login_required
@central_role_required("admin")
def register_site():
    payload = request.get_json(silent=True) or {}
    site_id = (payload.get("site_id") or "").strip()
    site_name = (payload.get("site_name") or "").strip()
    campus = (payload.get("campus") or "").strip()
    rotate = bool(payload.get("rotate"))
    if not site_id or not site_name:
        return jsonify({"error": "site_id and site_name are required"}), 400

    now = utc_now_iso()
    with get_db() as conn:
        existing = db_fetchone(conn, "SELECT api_key FROM site_registrations WHERE site_id=?", (site_id,))
        api_key = secrets.token_urlsafe(24) if rotate or not existing else existing["api_key"]
        db_execute(conn, """
            INSERT INTO site_registrations (site_id, site_name, campus, api_key, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(site_id) DO UPDATE SET
                site_name=excluded.site_name,
                campus=excluded.campus,
                api_key=excluded.api_key,
                updated_at=excluded.updated_at
        """, (site_id, site_name, campus, api_key, now, now))
    add_audit(central_actor_name(), "site", f"Registered site {site_name}", site_id, request.remote_addr, "success")
    return jsonify({
        "success": True,
        "site_id": site_id,
        "site_name": site_name,
        "campus": campus,
        "api_key": api_key,
        "central_api_url": central_api_url(),
        "connect_steps": {
            "enabled": True,
            "site_id": site_id,
            "site_name": site_name,
            "campus": campus,
            "api_url": central_api_url(),
            "api_key": api_key,
        }
    })


@app.route("/api/register-site/<site_id>", methods=["DELETE"])
@login_required
@central_role_required("admin")
def delete_registered_site(site_id):
    site_id = (site_id or "").strip()
    if not site_id:
        return jsonify({"error": "site_id is required"}), 400
    with get_db() as conn:
        db_execute(conn, "DELETE FROM site_registrations WHERE site_id=?", (site_id,))
        db_execute(conn, "DELETE FROM site_summaries WHERE site_id=?", (site_id,))
    add_audit(central_actor_name(), "site", f"Deleted site registration {site_id}", site_id, request.remote_addr, "success")
    return jsonify({"success": True, "site_id": site_id})


@app.route("/api/refresh-sites", methods=["POST"])
@login_required
@central_role_required("operator")
def refresh_sites():
    results = []
    with get_db() as conn:
        rows = db_fetchall(conn, "SELECT site_id, site_name, refresh_url, site_api_key FROM site_summaries ORDER BY site_name")
    for row in rows:
        refresh_url = row.get("refresh_url") or ""
        api_key = row.get("site_api_key") or ""
        if not refresh_url:
            results.append({"site_id": row["site_id"], "site_name": row["site_name"], "success": False, "error": "No refresh URL"})
            continue
        req = urllib.request.Request(
            refresh_url,
            data=b"{}",
            headers={"Content-Type": "application/json", "X-API-Key": api_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20, context=_SSL_CONTEXT) as resp:
                results.append({"site_id": row["site_id"], "site_name": row["site_name"], "success": 200 <= resp.status < 300})
        except urllib.error.HTTPError as exc:
            results.append({"site_id": row["site_id"], "site_name": row["site_name"], "success": False, "error": f"HTTP {exc.code}"})
        except Exception as exc:
            results.append({"site_id": row["site_id"], "site_name": row["site_name"], "success": False, "error": str(exc)})
    add_audit(central_actor_name(), "monitor", f"Triggered refresh for {len(results)} site(s)", "Central Dashboard", request.remote_addr, "success")
    return jsonify({
        "success": True,
        "requested": len(results),
        "ok": sum(1 for x in results if x["success"]),
        "failed": sum(1 for x in results if not x["success"]),
        "results": results,
    })


@app.route("/api/audit")
@login_required
def api_audit():
    event_type = request.args.get("type")
    search = request.args.get("q")
    result = request.args.get("result")
    audit_user = request.args.get("user")
    preset = request.args.get("preset", "7d")
    page = max(1, int(request.args.get("page") or 1))
    page_size = max(10, min(200, int(request.args.get("page_size") or 50)))
    date_from, date_to = resolve_log_range(preset, request.args.get("from"), request.args.get("to"))
    if session.get("central_user_role") != "admin":
        audit_user = central_actor_name()
    data = get_audit_log(
        limit=page_size,
        offset=(page - 1) * page_size,
        event_type=event_type,
        search=search,
        result=result,
        user_name=audit_user,
        date_from=date_from,
        date_to=date_to,
    )
    data["page"] = page
    data["page_size"] = page_size
    data["date_from"] = date_from
    data["date_to"] = date_to
    data["preset"] = preset
    return jsonify(data)


@app.route("/api/audit-users")
@login_required
@central_role_required("admin")
def api_audit_users():
    return jsonify(get_audit_users())


@app.route("/")
@login_required
def dashboard():
    return render_template_string(HTML, user=central_actor_name(), role=session.get("central_user_role"))


@app.route("/connect-site")
@login_required
@central_role_required("admin")
def connect_site_page():
    return render_template_string(CONNECT_HTML, user=central_actor_name())


@app.route("/users")
@login_required
@central_role_required("admin")
def users_page():
    return render_template_string(USERS_HTML, user=central_actor_name())


@app.route("/audit")
@login_required
def audit_page():
    return render_template_string(AUDIT_HTML, user=central_actor_name(), role=session.get("central_user_role"))


LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Central Dashboard Login</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:linear-gradient(180deg,#eef4f8 0%,#dfe8ee 100%);display:flex;align-items:center;justify-content:center;min-height:100vh;color:#1f2937;padding:24px}
    .card{width:460px;max-width:100%;background:#fff;border:1px solid #d8e3ea;border-radius:22px;padding:30px;box-shadow:0 24px 60px rgba(15,23,42,.12)}
    .brand{display:grid;justify-items:center;text-align:center;margin-bottom:22px}
    .brand img{width:92px;height:auto;display:block}
    .eyebrow{font-size:11px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#0f766e;margin-top:14px}
    .logo{font-size:24px;font-weight:800;color:#0f172a;line-height:1.2;margin-top:10px}
    .sub{font-size:13px;color:#64748b;margin-top:10px}
    .field{display:grid;gap:6px;margin-bottom:14px}
    .field label{font-size:12px;font-weight:600;color:#475569}
    .field input{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:10px;font-size:14px}
    .btn{width:100%;padding:11px 14px;border:none;border-radius:10px;background:#1f4ed8;color:#fff;font-weight:700;cursor:pointer}
    .err{font-size:12px;color:#b91c1c;background:#fff1f2;border:1px solid #fecdd3;padding:10px 12px;border-radius:10px;margin-bottom:14px}
    .warn{font-size:12px;color:#7c2d12;background:#fff7ed;border:1px solid #fed7aa;padding:12px 14px;border-radius:12px;margin-top:18px;line-height:1.5}
  </style>
</head>
<body>
  <form class="card" method="POST">
    <div class="brand">
      <img src="https://kumarans.org/images/loader_logo.png?v=ats-cms.1.0" alt="Sri Kumarans logo">
      <div class="eyebrow">Authorized Access</div>
      <div class="logo">Sri Kumarans Childrens Home Educational Council</div>
      <div class="sub">Central camera dashboard access for approved operations and administrative users only.</div>
    </div>
    {% if error %}<div class="err">{{ error }}</div>{% endif %}
    <div class="field">
      <label>Username</label>
      <input name="username" autocomplete="username" autofocus>
    </div>
    <div class="field">
      <label>Password</label>
      <input name="password" type="password" autocomplete="current-password">
    </div>
    <input type="hidden" name="_csrf" value="{{ csrf_token }}">
    <button class="btn" type="submit">Sign In</button>
    <div class="warn">
      Warning: This system is restricted to authorized personnel of Sri Kumarans Childrens Home Educational Council. Unauthorized access, use, or distribution of information from this dashboard is prohibited and may be monitored and investigated.
    </div>
  </form>
</body>
</html>"""


HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Central Camera Dashboard</title>
  <style>
:root{--bg:#f3f6fb;--surface:#ffffff;--line:#dbe3ef;--line-strong:#c8d4e5;--text:#1f2a37;--muted:#6b7a90;--primary:#1f6feb;--primary-soft:#e8f1ff;--ok:#16a34a;--danger:#dc2626;--warn:#d97706;--shadow:0 10px 30px rgba(15,23,42,.06)}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:linear-gradient(180deg,#f8fafc 0%,var(--bg) 100%);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
    .topbar{padding:14px 24px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}
    .top-row{position:relative;display:grid;grid-template-columns:1fr auto;align-items:center;gap:14px}
    .brand{display:flex;align-items:center;gap:12px;min-width:0}
    .brand-mark{display:flex;align-items:center;justify-content:center;flex:0 0 auto}
    .brand-mark img{width:342px;max-width:100%;height:auto;object-fit:contain;filter:drop-shadow(0 2px 6px rgba(15,23,42,.10))}
    .brand-copy{display:flex;flex-direction:column;gap:2px;min-width:0}
    .school{font-size:18px;font-weight:700;color:var(--text);line-height:1.15}
    .titlebar{position:absolute;left:50%;transform:translateX(-50%);font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.02em;text-align:center;pointer-events:none;white-space:nowrap}
    .top-actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;flex-wrap:nowrap}
    .wrap{padding:24px;flex:1;width:100%}
    .hero{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:18px}
    .hero h1{font-size:28px;letter-spacing:-0.03em}
    .hero p{font-size:13px;color:var(--muted);margin-top:6px}
    .stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:18px}
    .card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:16px;box-shadow:var(--shadow)}
    .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
    .value{font-size:28px;font-weight:700;margin-top:8px}
    .campus-group{margin-bottom:24px}
    .campus-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
    .campus-title{font-size:16px;font-weight:700;color:#0f172a}
    .campus-meta{font-size:12px;color:var(--muted)}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
    .site{position:relative;background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:18px 18px 18px 22px;text-decoration:none;color:inherit;display:block;transition:transform .15s, box-shadow .15s;overflow:hidden;box-shadow:var(--shadow)}
    .site:hover{transform:translateY(-1px);box-shadow:0 10px 24px rgba(15,23,42,.08)}
    .site::before{content:'';position:absolute;left:0;top:0;bottom:0;width:6px;background:#cbd5e1}
    .site.live::before{background:#16a34a}
    .site.issue::before{background:#dc2626}
    .site.maint::before{background:#ea580c}
    .site.stale-card::before{background:#a16207}
    .sitehead{display:flex;align-items:start;justify-content:space-between;gap:10px;margin-bottom:12px}
    .sitename{font-size:18px;font-weight:700}
    .campus{font-size:12px;color:var(--muted);margin-top:4px}
    .site-sub{font-size:12px;color:#475569;margin-top:8px;display:grid;gap:4px}
    .site-sub div{min-width:0;overflow-wrap:anywhere}
    .badge{font-size:10px;padding:4px 8px;border-radius:999px;font-weight:600}
    .badge.live{background:#eafaf1;color:#166534}
    .badge.stale{background:#fff7ed;color:#9a3412}
    .metrics{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-top:10px}
    .metric{padding:12px;border-radius:12px;background:#f8fafc;min-width:0}
    .metric .k{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
    .metric .v{font-size:22px;font-weight:700;margin-top:6px;line-height:1}
    .meta{font-size:12px;color:var(--muted);margin-top:14px;display:grid;gap:4px}
    .empty{background:#fff;border:1px dashed #cbd5e1;border-radius:16px;padding:30px;text-align:center;color:#6b7280}
    .btn{padding:7px 11px;border-radius:10px;border:1px solid var(--line);background:#fff;cursor:pointer;text-decoration:none;color:#475569;font-weight:600;font-size:11px;line-height:1.2}
    .btn:hover{background:#f8fbff;border-color:var(--line-strong)}
    .btn.primary{background:var(--primary);color:#fff;border-color:var(--primary)}
    .footer-note{padding:8px 24px 24px;color:#7a879a;font-size:11px;line-height:1.6;text-align:center;margin-top:auto}
    @media (max-width: 980px){.top-row{grid-template-columns:1fr;justify-items:start}.titlebar{position:static;transform:none;justify-self:start;text-align:left;white-space:normal;pointer-events:auto}.top-actions{justify-content:flex-start;flex-wrap:wrap}}
    @media (max-width: 1100px){.stats{grid-template-columns:repeat(3,minmax(0,1fr))}}
    @media (max-width: 900px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
    @media (max-width: 560px){.stats,.metrics{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="topbar">
    <div class="top-row">
      <div class="brand">
        <div class="brand-mark"><img src="https://kumarans.org/images/Sri%20Kumaran%20Childrens%20Home.png" alt="Sri Kumaran logo"></div>
      </div>
      <div class="titlebar">Central CCTV Operations Console</div>
      <div class="top-actions">
        {% if role == 'admin' %}<a class="btn primary" href="/connect-site">Add New Site</a>{% endif %}
        <a class="btn" href="/audit">Audit Log</a>
        {% if role == 'admin' %}<a class="btn" href="/users">User Management</a>{% endif %}
        <a class="btn" href="/logout">Sign out ({{ user }})</a>
      </div>
    </div>
  </div>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1>Site Overview</h1>
        <p>Brief live summaries for each site. Click any site card to open its full local dashboard.</p>
      </div>
      <div class="sub" id="lastSync">Last sync: —</div>
    </div>
    <div class="stats">
      <div class="card"><div class="label">Sites</div><div class="value" id="sSites">0</div></div>
      <div class="card"><div class="label">Total Cameras</div><div class="value" id="sTotal">0</div></div>
      <div class="card"><div class="label">Online</div><div class="value" id="sOnline" style="color:#15803d">0</div></div>
      <div class="card"><div class="label">Offline</div><div class="value" id="sOffline" style="color:#b91c1c">0</div></div>
      <div class="card"><div class="label">Maintenance</div><div class="value" id="sMaint" style="color:#c2410c">0</div></div>
    </div>
    <div class="grid" id="siteGrid"></div>
  </div>
  <div class="footer-note">
    © Sri Kumaran Childrens Home Educational Council. All rights reserved. Authorized operational use only. Activity on this monitoring system may be logged and reviewed.
  </div>
  <script>
    function fmtDateTime(v){
      if(!v) return '—';
      const d = new Date(v);
      if(Number.isNaN(d.getTime())) return v;
      const dd=String(d.getDate()).padStart(2,'0');
      const mm=String(d.getMonth()+1).padStart(2,'0');
      const yyyy=d.getFullYear();
      let hh=d.getHours();
      const min=String(d.getMinutes()).padStart(2,'0');
      const ap=hh>=12?'PM':'AM';
      hh=hh%12||12;
      return `${dd}-${mm}-${yyyy} ${String(hh).padStart(2,'0')}:${min} ${ap}`;
    }
    function isStale(v){
      if(!v) return true;
      const age = Date.now() - new Date(v).getTime();
      return age > 180000;
    }
    async function loadSites(){
      const r = await fetch('/api/sites');
      const sites = await r.json();
      document.getElementById('sSites').textContent = sites.length;
      document.getElementById('sTotal').textContent = sites.reduce((a, s) => a + (s.total || 0), 0);
      document.getElementById('sOnline').textContent = sites.reduce((a, s) => a + (s.online || 0), 0);
      document.getElementById('sOffline').textContent = sites.reduce((a, s) => a + (s.offline || 0), 0);
      document.getElementById('sMaint').textContent = sites.reduce((a, s) => a + (s.maintenance || 0), 0);
      document.getElementById('lastSync').textContent = 'Last sync: ' + fmtDateTime(new Date());
      const grid = document.getElementById('siteGrid');
      if(!sites.length){
        grid.innerHTML = '<div class="empty">No site summaries received yet. Start the local site app and central sync, then refresh.</div>';
        return;
      }
      const grouped = sites.reduce((acc, site) => {
        const key = site.campus || 'Unassigned Campus';
        (acc[key] ||= []).push(site);
        return acc;
      }, {});
      grid.innerHTML = Object.entries(grouped).map(([campus, items]) => {
        const total = items.reduce((a, s) => a + (s.total || 0), 0);
        return `<section class="campus-group">
          <div class="campus-head">
            <div class="campus-title">${campus}</div>
            <div class="campus-meta">${items.length} site${items.length === 1 ? '' : 's'} • ${total} cameras</div>
          </div>
          <div class="grid">
          ${items.map(site => {
            const stale = isStale(site.last_received_at);
            const cls = stale ? 'stale-card' : (site.offline || 0) > 0 ? 'issue' : (site.maintenance || 0) > 0 ? 'maint' : 'live';
            return `<a class="site ${cls}" href="${site.sso_url || site.dashboard_url}">
          <div class="sitehead">
            <div>
              <div class="sitename">${site.site_name}</div>
              <div class="campus">${site.site_id ? 'ID: ' + site.site_id : 'No site id'}</div>
            </div>
            <span class="badge ${stale ? 'stale' : 'live'}">${stale ? 'Stale' : 'Live'}</span>
          </div>
          <div class="metrics">
            <div class="metric"><div class="k">Total</div><div class="v">${site.total || 0}</div></div>
            <div class="metric"><div class="k">Online</div><div class="v" style="color:#15803d">${site.online || 0}</div></div>
            <div class="metric"><div class="k">Offline</div><div class="v" style="color:#b91c1c">${site.offline || 0}</div></div>
            <div class="metric"><div class="k">Maintenance</div><div class="v" style="color:#c2410c">${site.maintenance || 0}</div></div>
          </div>
          <div class="site-sub">
            ${site.site_address ? `<div>${site.site_address}</div>` : ''}
            ${site.contact_name || site.contact_phone || site.contact_email ? `<div>POC: ${[site.contact_name, site.contact_phone, site.contact_email].filter(Boolean).join(' • ')}</div>` : ''}
          </div>
          <div class="meta">Site updated: ${fmtDateTime(site.updated_at)}<br>Central received: ${fmtDateTime(site.last_received_at)}</div>
        </a>`;
          }).join('')}
          </div>
        </section>`;
      }).join('');
    }
    loadSites();
    setInterval(loadSites, 5000);
  </script>
</body>
</html>"""


CONNECT_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Connect New Site</title>
  <style>
    :root{--bg:#f3f6fb;--surface:#ffffff;--line:#dbe3ef;--line-strong:#c8d4e5;--text:#1f2a37;--muted:#6b7a90;--primary:#1f6feb;--shadow:0 10px 30px rgba(15,23,42,.06)}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:linear-gradient(180deg,#f8fafc 0%,var(--bg) 100%);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
    .topbar{padding:14px 24px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}
    .top-row{position:relative;display:grid;grid-template-columns:1fr auto;align-items:center;gap:14px}
    .brand{display:flex;align-items:center;gap:12px;min-width:0}
    .brand-mark{display:flex;align-items:center;justify-content:center;flex:0 0 auto}
    .brand-mark img{width:342px;max-width:100%;height:auto;object-fit:contain;filter:drop-shadow(0 2px 6px rgba(15,23,42,.10))}
    .titlebar{position:absolute;left:50%;transform:translateX(-50%);font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.02em;text-align:center;pointer-events:none;white-space:nowrap}
    .top-actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;flex-wrap:nowrap}
    .btn{padding:7px 11px;border-radius:10px;border:1px solid var(--line);background:#fff;cursor:pointer;text-decoration:none;color:#475569;font-weight:600;font-size:11px;line-height:1.2}
    .btn:hover{background:#f8fbff;border-color:var(--line-strong)}
    .btn.primary{background:var(--primary);color:#fff;border-color:var(--primary)}
    .btn.danger{background:#fff5f5;border-color:#fecaca;color:#b91c1c}
    .wrap{padding:24px;max-width:1200px;margin:0 auto;width:100%;flex:1}
    .hero{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:18px}
    .hero h1{font-size:28px;letter-spacing:-0.03em}
    .hero p{font-size:13px;color:var(--muted);margin-top:6px}
    .layout{display:grid;grid-template-columns:1.05fr .95fr;gap:18px}
    .card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:var(--shadow)}
    .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
    .title{font-size:22px;font-weight:700;margin-top:8px}
    .subtle{font-size:13px;color:#64748b;margin-top:8px}
    .form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:16px}
    .field{display:flex;flex-direction:column;gap:6px}
    .field.full{grid-column:1 / -1}
    .field label{font-size:12px;font-weight:600;color:#475569}
    .field input{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;font-size:13px}
    .result{margin-top:16px;padding:14px;border-radius:12px;background:#f8fafc;border:1px solid #dbe4f0;display:grid;gap:10px}
    .line{font-size:13px;color:#334155}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;overflow-wrap:anywhere}
    .hint-list{display:grid;gap:10px;margin-top:16px;font-size:13px;color:#475569}
    .hint-list strong{color:#0f172a}
    .reg-list{display:grid;gap:10px;margin-top:16px}
    .reg-item{padding:12px;border:1px solid var(--line);border-radius:12px;background:#f8fafc}
    .reg-item .name{font-size:14px;font-weight:700;color:#0f172a}
    .reg-item .meta{font-size:12px;color:#64748b;margin-top:4px}
    .reg-actions{display:flex;justify-content:flex-end;margin-top:10px}
    .empty{background:var(--surface);border:1px dashed #cbd5e1;border-radius:16px;padding:24px;text-align:center;color:#6b7280}
    .footer-note{padding:8px 24px 24px;color:#7a879a;font-size:11px;line-height:1.6;text-align:center;margin-top:auto}
    @media (max-width: 980px){.top-row{grid-template-columns:1fr;justify-items:start}.titlebar{position:static;transform:none;justify-self:start;text-align:left;white-space:normal;pointer-events:auto}.top-actions{justify-content:flex-start;flex-wrap:wrap}}
    @media (max-width: 900px){.layout,.form-grid{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="topbar">
    <div class="top-row">
      <div class="brand">
        <div class="brand-mark"><img src="https://kumarans.org/images/Sri%20Kumaran%20Childrens%20Home.png" alt="Sri Kumaran logo"></div>
      </div>
      <div class="titlebar">Connect New Site</div>
      <div class="top-actions">
        <a class="btn" href="/">Dashboard</a>
        <a class="btn" href="/audit">Audit Log</a>
        <a class="btn" href="/logout">Sign out</a>
      </div>
    </div>
  </div>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1>New Site Setup</h1>
        <p>Create a site key here, then paste the generated values into the local site's <strong>Site Details</strong> screen.</p>
      </div>
    </div>
    <div class="layout">
      <div class="card">
        <div class="label">Generate Key</div>
        <div class="title">One-click site registration</div>
        <div class="subtle">Enter the site basics, then generate the API key and connection values.</div>
        <form onsubmit="createRegistration(event)">
          <div class="form-grid">
            <div class="field">
              <label for="regSiteId">Site ID</label>
              <input id="regSiteId" required placeholder="blr-campus-1">
            </div>
            <div class="field">
              <label for="regSiteName">Site Name</label>
              <input id="regSiteName" required placeholder="Bangalore Campus">
            </div>
            <div class="field full">
              <label for="regCampus">Campus</label>
              <input id="regCampus" placeholder="South Campus">
            </div>
          </div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-top:16px;gap:10px">
            <span id="connectMsg" class="sub"></span>
            <button type="submit" class="btn primary">Generate API Key</button>
          </div>
        </form>
        <div class="result" id="connectResult" style="display:none"></div>
      </div>
      <div class="card">
        <div class="label">Connection Help</div>
        <div class="title">What to use on the local site</div>
        <div class="hint-list">
          <div><strong>Central API URL:</strong> <span class="mono" id="centralApiUrlLabel">—</span></div>
          <div><strong>Copy into local Site Details:</strong> enable central sync = true, Site ID = generated site ID, Site Name = generated site name, Campus = generated campus, Central API URL = value shown above, Central API Key = generated API key</div>
          <div><strong>Keep these as local-site values:</strong> Dashboard URL, Refresh URL, Site Address, Point of Contact, Contact Phone, and Contact Email</div>
          <div><strong>Fast path:</strong> generate the site key here, then open the local site's Site Details form and copy those exact values into the matching fields</div>
        </div>
        <div class="label" style="margin-top:20px">Registered Site Keys</div>
        <div class="reg-list" id="registrationList"></div>
      </div>
    </div>
  </div>
  <script>
    async function loadRegistrations(){
      const r = await fetch('/api/registrations');
      const data = await r.json();
      document.getElementById('centralApiUrlLabel').textContent = data.central_api_url || '—';
      const list = document.getElementById('registrationList');
      if(!data.items.length){
        list.innerHTML = '<div class="empty">No site keys generated yet.</div>';
        return;
      }
      list.innerHTML = data.items.map(item => `<div class="reg-item">
        <div class="name">${item.site_name}</div>
        <div class="meta">${item.site_id}${item.campus ? ' • ' + item.campus : ''}</div>
        <div class="meta mono" style="margin-top:6px">${item.api_key}</div>
        <div class="reg-actions">
          <button class="btn danger" onclick="deleteRegistration('${item.site_id}','${(item.site_name || '').replace(/'/g, "\\'")}')">Delete Key</button>
        </div>
      </div>`).join('');
    }
    async function createRegistration(event){
      event.preventDefault();
      const msg = document.getElementById('connectMsg');
      msg.textContent = 'Generating API key...';
      const payload = {
        site_id: document.getElementById('regSiteId').value.trim(),
        site_name: document.getElementById('regSiteName').value.trim(),
        campus: document.getElementById('regCampus').value.trim()
      };
      const r = await fetch('/api/register-site', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await r.json();
      if(!r.ok){
        msg.textContent = data.error || 'Could not generate API key';
        return;
      }
      msg.textContent = 'Site connection details generated.';
      const result = document.getElementById('connectResult');
      result.style.display = 'grid';
      result.innerHTML = `
        <div class="line"><strong>Site ID:</strong> <span class="mono">${data.site_id}</span></div>
        <div class="line"><strong>Site Name:</strong> ${data.site_name}</div>
        <div class="line"><strong>Campus:</strong> ${data.campus || '—'}</div>
        <div class="line"><strong>Central API URL:</strong> <span class="mono">${data.central_api_url}</span></div>
        <div class="line"><strong>Generated API Key:</strong> <span class="mono">${data.api_key}</span></div>
        <div class="line"><strong>Use on local site:</strong> paste <span class="mono">site_id</span>, <span class="mono">site_name</span>, <span class="mono">campus</span>, <span class="mono">api_url</span>, and <span class="mono">api_key</span> into Site Details.</div>`;
      await loadRegistrations();
    }
    async function deleteRegistration(siteId, siteName){
      const ok = confirm(`Delete the key for ${siteName}? This site will stop communicating with the cloud until a new key is generated.`);
      if(!ok) return;
      const confirmName = prompt(`Type DELETE to confirm removing the key for ${siteName}.`);
      if((confirmName || '').trim().toUpperCase() !== 'DELETE'){
        alert('Deletion cancelled. The confirmation word did not match.');
        return;
      }
      const r = await fetch(`/api/register-site/${encodeURIComponent(siteId)}`, {method:'DELETE'});
      const data = await r.json();
      if(!r.ok){
        alert(data.error || 'Could not delete the site key');
        return;
      }
      await loadRegistrations();
      alert(`Deleted key for ${siteName}. Any local site using that key can no longer sync to the cloud.`);
    }
    loadRegistrations();
  </script>
  <div class="footer-note">
    © Sri Kumaran Childrens Home Educational Council. All rights reserved. Authorized operational use only. Activity on this monitoring system may be logged and reviewed.
  </div>
</body>
</html>"""


USERS_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Central Users</title>
  <style>
    :root{--bg:#f3f6fb;--surface:#ffffff;--line:#dbe3ef;--line-strong:#c8d4e5;--text:#1f2a37;--muted:#6b7a90;--primary:#1f6feb;--primary-soft:#e8f1ff;--shadow:0 10px 30px rgba(15,23,42,.06)}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:linear-gradient(180deg,#f8fafc 0%,var(--bg) 100%);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
    .topbar{padding:14px 24px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}
    .top-row{position:relative;display:grid;grid-template-columns:1fr auto;align-items:center;gap:14px}
    .brand{display:flex;align-items:center;gap:12px;min-width:0}
    .brand-mark{display:flex;align-items:center;justify-content:center;flex:0 0 auto}
    .brand-mark img{width:342px;max-width:100%;height:auto;object-fit:contain;filter:drop-shadow(0 2px 6px rgba(15,23,42,.10))}
    .titlebar{position:absolute;left:50%;transform:translateX(-50%);font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.02em;text-align:center;pointer-events:none;white-space:nowrap}
    .top-actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;flex-wrap:nowrap}
    .btn{padding:7px 11px;border-radius:10px;border:1px solid var(--line);background:#fff;cursor:pointer;text-decoration:none;color:#475569;font-weight:600;font-size:11px;line-height:1.2}
    .btn:hover{background:#f8fbff;border-color:var(--line-strong)}
    .btn.primary{background:var(--primary);color:#fff;border-color:var(--primary)}
    .wrap{padding:24px;max-width:1200px;margin:0 auto;width:100%;flex:1}
    .layout{display:grid;grid-template-columns:360px 1fr;gap:18px}
    .card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:18px;box-shadow:var(--shadow)}
    .title{font-size:22px;font-weight:700}
    .subtle{font-size:13px;color:var(--muted);margin-top:6px}
    .form-grid{display:grid;gap:12px;margin-top:16px}
    .field{display:flex;flex-direction:column;gap:6px}
    .field label{font-size:12px;font-weight:600;color:#475569}
    .field input,.field select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:10px;font-size:13px}
    .msg{margin-top:12px;font-size:12px;color:var(--muted)}
    table{width:100%;border-collapse:collapse}
    th{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;padding:8px 12px;border-bottom:2px solid var(--line);white-space:nowrap}
    td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
    tr:last-child td{border-bottom:none}
    tr:hover td{background:#fafbfd}
    .user-name-input{border:1px solid transparent;background:transparent;font-size:13px;font-weight:500;color:var(--text);padding:5px 8px;border-radius:8px;width:100%;min-width:110px;transition:border-color .15s,background .15s}
    .user-name-input:hover{border-color:var(--line);background:#f8fafc}
    .user-name-input:focus{border-color:var(--primary);background:#fff;outline:none;box-shadow:0 0 0 3px rgba(31,111,235,.08)}
    .user-select{appearance:none;-webkit-appearance:none;border:1px solid transparent;background:transparent;font-size:12px;font-weight:600;padding:5px 22px 5px 10px;border-radius:8px;cursor:pointer;transition:border-color .15s,background .15s;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%236b7a90' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 7px center}
    .user-select:hover{border-color:var(--line);background-color:#f8fafc;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%236b7a90' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 7px center}
    .user-select:focus{border-color:var(--primary);background-color:#fff;outline:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%236b7a90' stroke-width='1.5' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 7px center}
    .role-admin{color:#7c3aed}.role-operator{color:#0369a1}.role-viewer{color:#475569}
    .status-active{color:#16a34a}.status-disabled{color:#b91c1c}
    .uname-badge{font-size:11px;font-family:ui-monospace,monospace;color:var(--muted);background:#f1f5f9;padding:3px 9px;border-radius:999px;white-space:nowrap;display:inline-block}
    .pwd-cell{display:flex;align-items:center;gap:6px}
    .pwd-input{border:1px solid var(--line);background:#f8fafc;font-size:12px;padding:5px 8px;border-radius:8px;width:110px;transition:border-color .15s}
    .pwd-input:focus{border-color:var(--primary);background:#fff;outline:none;box-shadow:0 0 0 3px rgba(31,111,235,.08)}
    .btn-set{font-size:11px;font-weight:600;padding:5px 10px;border-radius:8px;border:1px solid var(--line);background:#fff;cursor:pointer;color:#475569;white-space:nowrap}
    .btn-set:hover{background:#f0f7ff;border-color:var(--primary);color:var(--primary)}
    .btn-del{font-size:11px;font-weight:600;padding:5px 10px;border-radius:8px;border:1px solid #fecaca;background:#fff5f5;cursor:pointer;color:#b91c1c;white-space:nowrap}
    .btn-del:hover{background:#fee2e2}
    .empty{padding:24px;text-align:center;color:#6b7280}
    .footer-note{padding:8px 24px 24px;color:#7a879a;font-size:11px;line-height:1.6;text-align:center;margin-top:auto}
    @media (max-width: 980px){.top-row{grid-template-columns:1fr;justify-items:start}.titlebar{position:static;transform:none;justify-self:start;text-align:left;white-space:normal;pointer-events:auto}.top-actions{justify-content:flex-start;flex-wrap:wrap}}
    @media (max-width: 900px){.layout{grid-template-columns:1fr}}
  </style>
</head>
<body>
  <div class="topbar">
    <div class="top-row">
      <div class="brand">
        <div class="brand-mark"><img src="https://kumarans.org/images/Sri%20Kumaran%20Childrens%20Home.png" alt="Sri Kumaran logo"></div>
      </div>
      <div class="titlebar">Central User Management</div>
      <div class="top-actions">
        <a class="btn" href="/">Back to Dashboard</a>
        <a class="btn" href="/audit">Audit Log</a>
        <a class="btn" href="/logout">Sign out ({{ user }})</a>
      </div>
    </div>
  </div>
  <div class="wrap">
    <div class="layout">
      <div class="card">
        <div class="title">Create User</div>
        <div class="subtle">New users created here sync down to local sites and stay valid offline for 30 days after sync.</div>
        <div class="form-grid">
          <div class="field">
            <label>Full Name</label>
            <input id="newDisplayName" placeholder="e.g. Rajesh Kumar">
          </div>
          <div class="field">
            <label>Username</label>
            <input id="newUsername" placeholder="e.g. rajesh.kumar">
          </div>
          <div class="field">
            <label>Initial Password</label>
            <input id="newPassword" type="password" placeholder="Set a temporary password">
          </div>
          <div class="field">
            <label>Role</label>
            <select id="newRole">
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <button class="btn primary" onclick="createUser()">Create User</button>
          <div class="msg" id="createMsg"></div>
        </div>
      </div>
      <div class="card">
        <div class="title">Existing Users</div>
        <div class="subtle">Role changes and deletions are pushed to local sites immediately, then picked up again on background sync.</div>
        <div style="overflow:auto;margin-top:16px">
          <table>
            <thead><tr><th>Display Name</th><th>Username</th><th>Role</th><th>Status</th><th>Set Password</th><th></th></tr></thead>
            <tbody id="userRows"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>
  <div class="footer-note">
    © Sri Kumaran Childrens Home Educational Council. All rights reserved. Authorized operational use only. Activity on this monitoring system may be logged and reviewed.
  </div>
  <script>
    function esc(v){
      return String(v || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
    }
    async function loadUsers(){
      const r=await fetch('/api/users');
      const users=await r.json();
      const tbody=document.getElementById('userRows');
      if(!users.length){
        tbody.innerHTML='<tr><td colspan="6" class="empty">No users found.</td></tr>';
        return;
      }
      const roleColor = {admin:'role-admin',operator:'role-operator',viewer:'role-viewer'};
      const statusColor = {true:'status-active',false:'status-disabled'};
      tbody.innerHTML=users.map(u=>`<tr>
        <td><input class="user-name-input" value="${esc(u.display_name || u.username || '')}" onchange="patchUser(${u.id}, {display_name:this.value})"></td>
        <td><span class="uname-badge">${esc(u.username)}</span></td>
        <td>
          <select class="user-select ${roleColor[u.role]||'role-viewer'}" onchange="this.className='user-select '+({admin:'role-admin',operator:'role-operator',viewer:'role-viewer'}[this.value]||'role-viewer');patchUser(${u.id}, {role:this.value})">
            <option value="viewer" ${u.role==='viewer'?'selected':''}>Viewer</option>
            <option value="operator" ${u.role==='operator'?'selected':''}>Operator</option>
            <option value="admin" ${u.role==='admin'?'selected':''}>Admin</option>
          </select>
        </td>
        <td>
          <select class="user-select ${u.active?'status-active':'status-disabled'}" onchange="this.className='user-select '+(this.value==='true'?'status-active':'status-disabled');patchUser(${u.id}, {active:this.value==='true'})">
            <option value="true" ${u.active?'selected':''}>Active</option>
            <option value="false" ${!u.active?'selected':''}>Disabled</option>
          </select>
        </td>
        <td><div class="pwd-cell"><input id="pwd_${u.id}" class="pwd-input" type="password" placeholder="New password"><button class="btn-set" onclick="updatePassword(${u.id})">Set</button></div></td>
        <td><button class="btn-del" data-user-id="${u.id}" data-display-name="${esc(u.display_name || u.username || '')}" data-username="${esc(u.username || '')}" onclick="deleteUserFromButton(this)">Remove</button></td>
      </tr>`).join('');
    }
    async function createUser(){
      const msg=document.getElementById('createMsg');
      msg.textContent='Creating user...';
      const r=await fetch('/api/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({
        display_name: document.getElementById('newDisplayName').value.trim(),
        username: document.getElementById('newUsername').value.trim(),
        password: document.getElementById('newPassword').value,
        role: document.getElementById('newRole').value,
        active: true
      })});
      const d=await r.json();
      if(!r.ok){ msg.textContent=d.error || 'Could not create user'; return; }
      msg.textContent=`Created ${d.user.display_name || d.user.username}. User sync pushed to ${d.site_sync.filter(x=>x.success).length} site(s).`;
      document.getElementById('newDisplayName').value='';
      document.getElementById('newUsername').value='';
      document.getElementById('newPassword').value='';
      document.getElementById('newRole').value='viewer';
      loadUsers();
    }
    async function patchUser(id, changes){
      const r=await fetch(`/api/users/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify(changes)});
      const d=await r.json();
      if(!r.ok){ alert(d.error || 'Could not update user'); return; }
    }
    async function updatePassword(id){
      const input=document.getElementById(`pwd_${id}`);
      if(!input.value) return;
      const r=await fetch(`/api/users/${id}`,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({password: input.value})});
      const d=await r.json();
      if(!r.ok){ alert(d.error || 'Could not update password'); return; }
      input.value='';
      alert(`Updated password for ${d.user.username}.`);
    }
    function deleteUserFromButton(btn){
      return deleteUser(btn.dataset.userId, btn.dataset.displayName, btn.dataset.username);
    }
    async function deleteUser(id, displayName, username){
      if(!confirm(`Delete ${displayName || username} completely from central? This will remove local access on synced sites too.`)) return;
      const typed=prompt(`Type DELETE to permanently remove ${displayName || username} (${username}).`);
      if(typed !== 'DELETE') return;
      const r=await fetch(`/api/users/${id}`,{method:'DELETE'});
      const d=await r.json();
      if(!r.ok){ alert(d.error || 'Could not delete user'); return; }
      alert(`Deleted ${d.deleted_user.display_name || d.deleted_user.username}. Sync pushed to ${d.site_sync.filter(x=>x.success).length} site(s).`);
      loadUsers();
    }
    loadUsers();
  </script>
</body>
</html>"""


AUDIT_HTML = """<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Central Audit Log</title>
  <style>
    :root{--bg:#f3f6fb;--surface:#ffffff;--line:#dbe3ef;--line-strong:#c8d4e5;--text:#1f2a37;--muted:#6b7a90;--primary:#1f6feb;--shadow:0 10px 30px rgba(15,23,42,.06)}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:system-ui,sans-serif;background:linear-gradient(180deg,#f8fafc 0%,var(--bg) 100%);color:var(--text);min-height:100vh;display:flex;flex-direction:column}
    .topbar{padding:14px 24px;background:rgba(255,255,255,.96);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}
    .top-row{position:relative;display:grid;grid-template-columns:1fr auto;align-items:center;gap:14px}
    .brand{display:flex;align-items:center;gap:12px;min-width:0}
    .brand-mark{display:flex;align-items:center;justify-content:center;flex:0 0 auto}
    .brand-mark img{width:342px;max-width:100%;height:auto;object-fit:contain;filter:drop-shadow(0 2px 6px rgba(15,23,42,.10))}
    .titlebar{position:absolute;left:50%;transform:translateX(-50%);font-size:20px;font-weight:700;color:var(--text);letter-spacing:-.02em;text-align:center;pointer-events:none;white-space:nowrap}
    .top-actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;flex-wrap:nowrap}
    .wrap{padding:24px;flex:1}
    .stats{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:12px;margin-bottom:18px}
    .card{background:#fff;border:1px solid var(--line);border-radius:14px;padding:16px;box-shadow:var(--shadow)}
    .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
    .value{font-size:28px;font-weight:700;margin-top:8px}
    .sub{font-size:12px;color:var(--muted)}
    .fbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px;margin-bottom:16px;box-shadow:var(--shadow)}
    .srch{padding:10px 12px;border:1px solid var(--line);border-radius:10px;font-size:13px;background:#fff}
    .btn{padding:7px 11px;border-radius:10px;border:1px solid var(--line);background:#fff;cursor:pointer;text-decoration:none;color:#475569;font-weight:600;font-size:11px;line-height:1.2}
    .btn:hover{background:#f8fbff;border-color:var(--line-strong)}
    .chip{padding:8px 12px;border-radius:20px;border:1px solid var(--line);font-size:11px;cursor:pointer;background:#fff;color:#64748b;font-weight:600}
    .chip.active{background:var(--primary);color:#fff;border-color:var(--primary)}
    .table-wrap{overflow:auto}
    table{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;box-shadow:var(--shadow)}
    th,td{padding:10px 12px;text-align:left;border-bottom:1px solid var(--line);font-size:12px}
    th{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;background:#f8fafc}
    .badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:10px;font-weight:600}
    .pager{display:flex;align-items:center;gap:10px;justify-content:flex-end;margin-top:14px;flex-wrap:wrap}
    .footer-note{padding:8px 24px 24px;color:#7a879a;font-size:11px;line-height:1.6;text-align:center;margin-top:auto}
    @media (max-width: 980px){.top-row{grid-template-columns:1fr;justify-items:start}.titlebar{position:static;transform:none;justify-self:start;text-align:left;white-space:normal;pointer-events:auto}.top-actions{justify-content:flex-start;flex-wrap:wrap}}
    @media (max-width: 900px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}
  </style>
</head>
<body>
  <div class="topbar">
    <div class="top-row">
      <div class="brand">
        <div class="brand-mark"><img src="https://kumarans.org/images/Sri%20Kumaran%20Childrens%20Home.png" alt="Sri Kumaran logo"></div>
      </div>
      <div class="titlebar">Central Audit Log</div>
      <div class="top-actions">
        <a class="btn" href="/">Back to Dashboard</a>
        {% if role == 'admin' %}<a class="btn" href="/users">User Management</a>{% endif %}
        <a class="btn" href="/logout">Sign out ({{ user }})</a>
      </div>
    </div>
  </div>
  <div class="wrap">
    <div class="stats">
      <div class="card"><div class="label">Total Events</div><div class="value" id="sTot">0</div></div>
      <div class="card"><div class="label">Logins</div><div class="value" id="sLg">0</div></div>
      <div class="card"><div class="label">Users</div><div class="value" id="sUsr">0</div></div>
      <div class="card"><div class="label">Sites</div><div class="value" id="sSite">0</div></div>
      <div class="card"><div class="label">Monitor</div><div class="value" id="sMon">0</div></div>
    </div>
    <div class="fbar">
      <input class="srch" type="search" id="sq" placeholder="Search user, target, action...">
      <select class="srch" id="auditType">
        <option value="all">All Types</option>
        <option value="login">Login</option>
        <option value="logout">Logout</option>
        <option value="user">User</option>
        <option value="site">Site</option>
        <option value="monitor">Monitor</option>
      </select>
      <select class="srch" id="auditResult">
        <option value="all">All Results</option>
        <option value="success">Success</option>
        <option value="failed">Failed</option>
      </select>
      <select class="srch" id="auditPageSize" onchange="setAuditPageSize(this.value)">
        <option value="25">25 / page</option>
        <option value="50" selected>50 / page</option>
        <option value="100">100 / page</option>
        <option value="200">200 / page</option>
      </select>
      {% if role == 'admin' %}
      <select class="srch" id="auditUser">
        <option value="all">All Users</option>
      </select>
      {% endif %}
      <button class="chip active" data-preset="7d" onclick="pickPreset('7d')">7 Days</button>
      <button class="chip" data-preset="1m" onclick="pickPreset('1m')">1 Month</button>
      <button class="chip" data-preset="3m" onclick="pickPreset('3m')">3 Months</button>
      <input class="srch" id="fromDate" style="width:150px" type="date">
      <input class="srch" id="toDate" style="width:150px" type="date">
      <button class="btn" onclick="applyCustomRange()">Custom Range</button>
      <button class="btn" onclick="clearFilters()">Clear Filters</button>
      <div style="flex:1"></div>
      <span class="sub" id="rcnt">0 records</span>
    </div>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Timestamp</th><th>User</th><th>Type</th><th>Description</th><th>Target</th><th>IP</th><th>Result</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
    <div class="pager">
      <span class="sub" id="pageInfo">Page 1</span>
      <button class="btn" id="prevBtn" onclick="changePage(-1)">Previous</button>
      <div id="auditPageNums" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap"></div>
      <button class="btn" id="nextBtn" onclick="changePage(1)">Next</button>
    </div>
  </div>
  <div class="footer-note">
    © Sri Kumaran Childrens Home Educational Council. All rights reserved. Authorized operational use only. Activity on this monitoring system may be logged and reviewed.
  </div>
  <script>
    const COLORS={login:['#ebf5fb','#1a5276'],logout:['#f5f5f5','#666'],user:['#f0ebfe','#5b2c8f'],site:['#fef5e7','#9c640c'],monitor:['#ebf3ff','#2457a6']};
    let auditPage=1;
    let auditPageSize=50;
    let currentPreset='7d';
    function fmtDateTime(v){
      if(!v) return '—';
      const d=new Date(v);
      if(Number.isNaN(d.getTime())) return v;
      const dd=String(d.getDate()).padStart(2,'0');
      const mm=String(d.getMonth()+1).padStart(2,'0');
      const yyyy=d.getFullYear();
      let hh=d.getHours();
      const min=String(d.getMinutes()).padStart(2,'0');
      const ap=hh>=12?'PM':'AM';
      hh=hh%12||12;
      return `${dd}-${mm}-${yyyy} ${String(hh).padStart(2,'0')}:${min} ${ap}`;
    }
    async function loadAuditUsers(){
      const userSel=document.getElementById('auditUser');
      if(!userSel) return;
      const r=await fetch('/api/audit-users');
      if(!r.ok) return;
      const users=await r.json();
      userSel.innerHTML='<option value="all">All Users</option>'+users.map(u=>`<option value="${String(u||'').replace(/"/g,'&quot;')}">${u}</option>`).join('');
    }
    function syncPresetButtons(active){
      document.querySelectorAll('.chip[data-preset]').forEach(btn=>btn.classList.toggle('active', btn.dataset.preset===active));
    }
    function pickPreset(preset){
      currentPreset=preset;
      syncPresetButtons(preset);
      auditPage=1;
      loadAudit();
    }
    function applyCustomRange(){
      currentPreset='custom';
      syncPresetButtons('');
      auditPage=1;
      loadAudit();
    }
    function clearFilters(){
      auditPage=1;
      currentPreset='7d';
      syncPresetButtons('7d');
      document.getElementById('sq').value='';
      document.getElementById('auditType').value='all';
      document.getElementById('auditResult').value='all';
      document.getElementById('fromDate').value='';
      document.getElementById('toDate').value='';
      const u=document.getElementById('auditUser');
      if(u) u.value='all';
      loadAudit();
    }
    function setAuditPageSize(value){
      auditPageSize=Math.max(25, Math.min(200, parseInt(value || '50', 10) || 50));
      auditPage=1;
      loadAudit();
    }
    function changePage(step){
      auditPage=Math.max(1, auditPage + step);
      loadAudit();
    }
    function setPage(page){
      if(page<1 || page===auditPage) return;
      auditPage=page;
      loadAudit();
    }
    function buildPageTokens(current, total){
      if(total<=7){
        const out=[];
        for(let i=1;i<=total;i++) out.push(i);
        return out;
      }
      if(current<=4) return [1,2,3,4,5,'...',total];
      if(current>=total-3) return [1,'...',total-4,total-3,total-2,total-1,total];
      return [1,'...',current-1,current,current+1,'...',total];
    }
    function renderPageNumbers(totalPages){
      const holder=document.getElementById('auditPageNums');
      if(!holder) return;
      const tokens=buildPageTokens(auditPage,totalPages);
      holder.innerHTML=tokens.map(tok=>{
        if(tok==='...') return '<span style="font-size:11px;color:#94a3b8;padding:0 2px">...</span>';
        const active=tok===auditPage;
        return `<button class="btn ${active?'active':''}" ${active?'disabled':''} onclick="setPage(${tok})" style="${active?'background:#1f6feb;color:#fff;border-color:#1f6feb;':''}">${tok}</button>`;
      }).join('');
    }
    async function loadAudit(){
      const p=new URLSearchParams();
      const q=document.getElementById('sq').value;
      const type=document.getElementById('auditType').value;
      const result=document.getElementById('auditResult').value;
      const userSel=document.getElementById('auditUser');
      const auditUser=userSel?userSel.value:'all';
      p.set('preset', currentPreset);
      p.set('page', String(auditPage));
      p.set('page_size', String(auditPageSize));
      if(currentPreset==='custom'){
        p.set('from', document.getElementById('fromDate').value);
        p.set('to', document.getElementById('toDate').value);
      }
      if(q) p.set('q', q);
      if(type && type!=='all') p.set('type', type);
      if(result && result!=='all') p.set('result', result);
      if(auditUser && auditUser!=='all') p.set('user', auditUser);
      const r=await fetch('/api/audit?'+p.toString());
      const data=await r.json();
      const rows=data.items || [];
      const total=data.total || 0;
      const totalPages=Math.max(1, Math.ceil(total / auditPageSize));
      if(auditPage > totalPages){
        auditPage=totalPages;
        return loadAudit();
      }
      if(data.date_from) document.getElementById('fromDate').value=data.date_from;
      if(data.date_to) document.getElementById('toDate').value=data.date_to;
      document.getElementById('sTot').textContent=total;
      document.getElementById('sLg').textContent=rows.filter(x=>x.event_type==='login').length;
      document.getElementById('sUsr').textContent=rows.filter(x=>x.event_type==='user').length;
      document.getElementById('sSite').textContent=rows.filter(x=>x.event_type==='site').length;
      document.getElementById('sMon').textContent=rows.filter(x=>x.event_type==='monitor').length;
      document.getElementById('rcnt').textContent=`${data.date_from} to ${data.date_to}`;
      document.getElementById('pageInfo').textContent=`Page ${auditPage} of ${totalPages}`;
      document.getElementById('prevBtn').disabled=auditPage<=1;
      document.getElementById('nextBtn').disabled=auditPage>=totalPages;
      renderPageNumbers(totalPages);
      document.getElementById('rows').innerHTML=rows.map(row=>{
        const cl=COLORS[row.event_type]||['#f5f5f5','#666'];
        const ok=row.result==='success';
        return `<tr>
          <td style="font-family:ui-monospace,monospace;color:#64748b">${fmtDateTime(row.ts)}</td>
          <td style="font-weight:600">${row.user_name||''}</td>
          <td><span class="badge" style="background:${cl[0]};color:${cl[1]}">${row.event_type||''}</span></td>
          <td>${row.description||''}</td>
          <td style="font-family:ui-monospace,monospace;color:#64748b">${row.target||''}</td>
          <td style="font-family:ui-monospace,monospace;color:#94a3b8">${row.ip_address||''}</td>
          <td><span class="badge" style="background:${ok?'#eafaf1':'#fdecea'};color:${ok?'#166534':'#991b1b'}">${row.result||''}</span></td>
        </tr>`;
      }).join('') || '<tr><td colspan="7" style="padding:22px;text-align:center;color:#6b7280">No audit records found for the current filters.</td></tr>';
    }
    document.getElementById('sq').addEventListener('input', ()=>{auditPage=1;loadAudit();});
    document.getElementById('auditType').addEventListener('change', ()=>{auditPage=1;loadAudit();});
    document.getElementById('auditResult').addEventListener('change', ()=>{auditPage=1;loadAudit();});
    const auditUserSel=document.getElementById('auditUser');
    if(auditUserSel){
      auditUserSel.addEventListener('change', ()=>{auditPage=1;loadAudit();});
    }
    loadAuditUsers().then(loadAudit);
  </script>
</body>
</html>"""


def _init_db_with_retry(retries=6, delay=5):
    for attempt in range(retries):
        try:
            init_db()
            return
        except Exception as exc:
            if attempt < retries - 1:
                log.warning("DB init attempt %d/%d failed (%s) — retrying in %ds", attempt + 1, retries, exc, delay)
                time.sleep(delay)
            else:
                log.error("DB init failed after %d attempts: %s", retries, exc)
                raise

_init_db_with_retry()
_check_startup()


@app.route("/health")
def health():
    """Unauthenticated health/readiness check for Railway/Render/load-balancers."""
    return jsonify({"ok": True}), 200


if __name__ == "__main__":
    app.run(host=CENTRAL_HOST, port=CENTRAL_PORT, debug=False, use_reloader=False)
