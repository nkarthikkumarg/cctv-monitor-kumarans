"""
db.py — All SQLite database operations for CamMonitor
Storage philosophy:
  - NEVER log every ping result
  - Only log STATE CHANGES (online → offline, offline → online)
  - Store one daily snapshot per camera per day for trend reports
  - Retain all event data for 1 year (365 days)
"""
import configparser
import os
import sqlite3
import threading
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(__file__)
CONFIG_PATH = os.path.join(BASE_DIR, "config.ini")
cfg = configparser.ConfigParser()
DB_PATH = ""
RETENTION_DAYS = 365

_lock = threading.Lock()

def _resolve_db_path(raw_path):
    raw_path = (raw_path or "").strip() or "cam_monitor.db"
    if os.path.isabs(raw_path):
        return raw_path
    return os.path.abspath(os.path.join(BASE_DIR, raw_path))

def reload_config():
    global DB_PATH, RETENTION_DAYS
    cfg.clear()
    cfg.read(CONFIG_PATH)
    DB_PATH = _resolve_db_path(cfg.get("database", "db_path", fallback="cam_monitor.db"))
    RETENTION_DAYS = cfg.getint("monitor", "history_retention_days", fallback=365)

reload_config()

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn

def init_db():
    reload_config()
    with _lock:
        with get_db() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS cameras (
                    ip TEXT PRIMARY KEY, name TEXT, location TEXT, zone TEXT,
                    nvr_name TEXT, nvr_ip TEXT, nvr_channel INTEGER, brand TEXT,
                    username TEXT, password TEXT, notes TEXT, rtsp_url TEXT, active INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS status (
                    ip TEXT PRIMARY KEY, online INTEGER DEFAULT 1,
                    last_seen TEXT, offline_since TEXT,
                    last_alert_sent TEXT, last_recovery_sent TEXT,
                    maintenance INTEGER DEFAULT 0, health_pct REAL DEFAULT 100.0
                );
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT, event TEXT, ts TEXT, duration_s INTEGER
                );
                CREATE TABLE IF NOT EXISTS daily_snapshots (
                    date TEXT, ip TEXT,
                    total_checks INTEGER DEFAULT 0,
                    offline_events INTEGER DEFAULT 0,
                    downtime_min INTEGER DEFAULT 0,
                    uptime_pct REAL DEFAULT 100.0,
                    PRIMARY KEY (date, ip)
                );
                CREATE TABLE IF NOT EXISTS alert_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT, alert_type TEXT, target TEXT, channel TEXT, message TEXT
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT, user TEXT, event_type TEXT,
                    description TEXT, target TEXT, ip_address TEXT, result TEXT
                );
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    display_name TEXT,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    active INTEGER NOT NULL DEFAULT 1,
                    source TEXT NOT NULL DEFAULT 'local',
                    central_user_id INTEGER,
                    valid_until TEXT,
                    central_updated_at TEXT,
                    central_deleted INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_ip_ts   ON events(ip, ts);
                CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_snapshots_date ON daily_snapshots(date);
                CREATE INDEX IF NOT EXISTS idx_snapshots_ip   ON daily_snapshots(ip);
                CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit(ts);
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE TABLE IF NOT EXISTS nvr_status (
                    nvr_ip TEXT PRIMARY KEY,
                    nvr_name TEXT,
                    online INTEGER DEFAULT 1,
                    last_seen TEXT,
                    offline_since TEXT
                );
            """)
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(cameras)").fetchall()]
            if "nvr_ip" not in cols:
                conn.execute("ALTER TABLE cameras ADD COLUMN nvr_ip TEXT")
            if "rtsp_url" not in cols:
                conn.execute("ALTER TABLE cameras ADD COLUMN rtsp_url TEXT")
            user_cols = [r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "display_name" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
            if "source" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'local'")
            if "central_user_id" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN central_user_id INTEGER")
            if "valid_until" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN valid_until TEXT")
            if "central_updated_at" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN central_updated_at TEXT")
            if "central_deleted" not in user_cols:
                conn.execute("ALTER TABLE users ADD COLUMN central_deleted INTEGER NOT NULL DEFAULT 0")
    print(f"[DB] Initialised: {DB_PATH}")


def ensure_default_admin(username, password, display_name=None):
    username = (username or "").strip()
    password = password or ""
    display_name = (display_name or username).strip()
    if not username or not password:
        return
    now = datetime.now().isoformat()
    with _lock:
        with get_db() as conn:
            existing = conn.execute("SELECT id, role FROM users WHERE LOWER(username)=LOWER(?)", (username,)).fetchone()
            if existing:
                if existing["role"] != "admin":
                    conn.execute("UPDATE users SET role='admin', active=1, source='local', central_deleted=0, display_name=?, updated_at=? WHERE LOWER(username)=LOWER(?)", (display_name, now, username))
                return
            conn.execute("""
                INSERT INTO users (username, display_name, password_hash, role, active, source, central_deleted, created_at, updated_at)
                VALUES (?, ?, ?, 'admin', 1, 'local', 0, ?, ?)
            """, (username, display_name, generate_password_hash(password), now, now))


def get_user_by_username(username):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", ((username or "").strip(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return dict(row) if row else None


def verify_user(username, password):
    user = get_user_by_username(username)
    if not user or not user.get("active") or user.get("central_deleted"):
        return None
    if not check_password_hash(user["password_hash"], password or ""):
        return None
    return user


def list_users():
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, username, display_name, role, active, source, central_user_id, valid_until, created_at, updated_at FROM users ORDER BY username"
        ).fetchall()]

def create_user(username, password, role="viewer", active=True, display_name=None):
    username = (username or "").strip()
    display_name = (display_name or username).strip()
    if not username:
        raise ValueError("Username is required")
    if not password:
        raise ValueError("Password is required")
    role = (role or "viewer").strip().lower()
    if role not in {"viewer", "operator", "admin"}:
        raise ValueError("Invalid role")
    now = datetime.now().isoformat()
    with _lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO users (username, display_name, password_hash, role, active, source, central_deleted, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 'local', 0, ?, ?)
            """, (username, display_name, generate_password_hash(password), role, 1 if active else 0, now, now))
    return get_user_by_username(username)

def update_user(user_id, role=None, active=None, password=None, display_name=None):
    current = get_user_by_id(user_id)
    if not current:
        raise ValueError("User not found")
    next_role = (role or current["role"]).strip().lower()
    if next_role not in {"viewer", "operator", "admin"}:
        raise ValueError("Invalid role")
    next_active = current["active"] if active is None else (1 if active else 0)
    next_hash = current["password_hash"] if not password else generate_password_hash(password)
    next_name = (display_name or current.get("display_name") or current["username"]).strip()
    now = datetime.now().isoformat()
    with _lock:
        with get_db() as conn:
            conn.execute("""
                UPDATE users
                SET display_name=?, role=?, active=?, password_hash=?, updated_at=?
                WHERE id=?
            """, (next_name, next_role, next_active, next_hash, now, user_id))
    return get_user_by_id(user_id)

def upsert_central_user(username, display_name, password_hash, role, active, central_user_id, valid_until, central_updated_at, deleted=False):
    username = (username or "").strip()
    display_name = (display_name or username).strip()
    if not username:
        return
    now = datetime.now().isoformat()
    with _lock:
        with get_db() as conn:
            existing = conn.execute("SELECT id, source FROM users WHERE LOWER(username)=LOWER(?)", (username,)).fetchone()
            if existing and existing["source"] == "local":
                return
            conn.execute("""
                INSERT INTO users (
                    username, display_name, password_hash, role, active, source, central_user_id,
                    valid_until, central_updated_at, central_deleted, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'central', ?, ?, ?, ?, ?, ?)
                ON CONFLICT(username) DO UPDATE SET
                    display_name=excluded.display_name,
                    password_hash=excluded.password_hash,
                    role=excluded.role,
                    active=excluded.active,
                    source='central',
                    central_user_id=excluded.central_user_id,
                    valid_until=excluded.valid_until,
                    central_updated_at=excluded.central_updated_at,
                    central_deleted=excluded.central_deleted,
                    updated_at=excluded.updated_at
            """, (
                username,
                display_name,
                password_hash,
                role,
                1 if active else 0,
                central_user_id,
                valid_until,
                central_updated_at,
                1 if deleted else 0,
                now,
                now,
            ))


def list_synced_users():
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM users WHERE source='central' ORDER BY username"
        ).fetchall()]


def mark_missing_central_users_deleted(seen_usernames, valid_until):
    seen = set(seen_usernames or [])
    now = datetime.now().isoformat()
    with _lock:
        with get_db() as conn:
            rows = conn.execute("SELECT username FROM users WHERE source='central'").fetchall()
            for row in rows:
                if row["username"] not in seen:
                    conn.execute("""
                        UPDATE users
                        SET active=0, central_deleted=1, valid_until=?, updated_at=?
                        WHERE username=?
                    """, (valid_until, now, row["username"]))

def _calc_uptime_pct(total_checks, downtime_min):
    tc = total_checks or 0
    if tc <= 0:
        return 100.0
    dm = min(downtime_min or 0, tc)
    return round(((tc - dm) / tc) * 100, 1)

def _get_health_map(conn, days=7):
    cutoff = (datetime.now() - timedelta(days=days-1)).strftime("%Y-%m-%d")
    rows = conn.execute("""
        SELECT ip, SUM(total_checks) AS total_checks, SUM(downtime_min) AS downtime_min
        FROM daily_snapshots
        WHERE date >= ?
        GROUP BY ip
    """, (cutoff,)).fetchall()
    return {
        row["ip"]: _calc_uptime_pct(row["total_checks"], row["downtime_min"])
        for row in rows
    }

def get_all_cameras():
    with get_db() as conn:
        health_map = _get_health_map(conn, days=7)
        cameras = [dict(r) for r in conn.execute(
            "SELECT c.*, s.online, s.last_seen, s.offline_since, s.health_pct, s.maintenance "
            "FROM cameras c LEFT JOIN status s ON c.ip=s.ip WHERE c.active=1 ORDER BY c.name"
        ).fetchall()]
        for cam in cameras:
            cam["health_7d"] = health_map.get(cam["ip"], 100.0)
        return cameras

def get_camera(ip):
    with get_db() as conn:
        health_map = _get_health_map(conn, days=7)
        row = conn.execute(
            "SELECT c.*, s.online, s.last_seen, s.offline_since, s.health_pct, s.maintenance "
            "FROM cameras c LEFT JOIN status s ON c.ip=s.ip WHERE c.ip=?", (ip,)
        ).fetchone()
        if not row:
            return None
        cam = dict(row)
        cam["health_7d"] = health_map.get(ip, 100.0)
        return cam

def upsert_camera(data):
    with _lock:
        with get_db() as conn:
            conn.execute("""
                INSERT INTO cameras (ip,name,location,zone,nvr_name,nvr_ip,nvr_channel,brand,username,password,notes,rtsp_url,active)
                VALUES (:ip,:name,:location,:zone,:nvr_name,:nvr_ip,:nvr_channel,:brand,:username,:password,:notes,:rtsp_url,1)
                ON CONFLICT(ip) DO UPDATE SET
                    name=excluded.name, location=excluded.location, zone=excluded.zone,
                    nvr_name=excluded.nvr_name, nvr_ip=excluded.nvr_ip, nvr_channel=excluded.nvr_channel,
                    brand=excluded.brand, username=excluded.username,
                    password=excluded.password, notes=excluded.notes, rtsp_url=excluded.rtsp_url, active=1
            """, data)
            conn.execute(
                "INSERT OR IGNORE INTO status (ip, online, last_seen) VALUES (?,1,?)",
                (data["ip"], datetime.now().isoformat())
            )

def update_camera(original_ip, data):
    original_ip = (original_ip or "").strip()
    new_ip = (data.get("ip") or "").strip()
    if not original_ip or not new_ip:
        raise ValueError("Camera IP is required")
    with _lock:
        with get_db() as conn:
            existing = conn.execute("SELECT ip FROM cameras WHERE ip=?", (original_ip,)).fetchone()
            if not existing:
                raise ValueError("Camera not found")
            if new_ip != original_ip:
                conflict = conn.execute("SELECT ip FROM cameras WHERE ip=? AND active=1", (new_ip,)).fetchone()
                if conflict:
                    raise ValueError("Another camera already uses this IP address")
                # Purge soft-deleted camera + all orphaned rows for new_ip across
                # every table that has an ip FK, so the subsequent UPDATE doesn't
                # hit UNIQUE constraint violations.
                conn.execute("DELETE FROM cameras WHERE ip=? AND active=0", (new_ip,))
                conn.execute("DELETE FROM status WHERE ip=?", (new_ip,))
                conn.execute("DELETE FROM events WHERE ip=?", (new_ip,))
                conn.execute("DELETE FROM daily_snapshots WHERE ip=?", (new_ip,))
                conn.execute("UPDATE cameras SET ip=? WHERE ip=?", (new_ip, original_ip))
                conn.execute("UPDATE status SET ip=? WHERE ip=?", (new_ip, original_ip))
                conn.execute("UPDATE events SET ip=? WHERE ip=?", (new_ip, original_ip))
                conn.execute("UPDATE daily_snapshots SET ip=? WHERE ip=?", (new_ip, original_ip))
            conn.execute("""
                UPDATE cameras
                SET name=?, location=?, zone=?, nvr_name=?, nvr_ip=?, nvr_channel=?, brand=?,
                    username=?, password=?, notes=?, rtsp_url=?, active=1
                WHERE ip=?
            """, (
                data.get("name", ""),
                data.get("location", ""),
                data.get("zone", ""),
                data.get("nvr_name", ""),
                data.get("nvr_ip", ""),
                data.get("nvr_channel", 1),
                data.get("brand", ""),
                data.get("username", ""),
                data.get("password", ""),
                data.get("notes", ""),
                data.get("rtsp_url", ""),
                new_ip,
            ))
    return get_camera(new_ip)

def deactivate_camera(ip):
    with _lock:
        with get_db() as conn:
            conn.execute("UPDATE cameras SET active=0 WHERE ip=?", (ip,))

def set_maintenance(ip, state, user="system"):
    with _lock:
        with get_db() as conn:
            conn.execute("UPDATE status SET maintenance=? WHERE ip=?", (1 if state else 0, ip))
            cam = conn.execute(
                "SELECT name, location, zone, nvr_name, nvr_channel FROM cameras WHERE ip=?",
                (ip,)
            ).fetchone()
    if cam:
        details = " | ".join([
            cam["name"] or "Unnamed camera",
            cam["location"] or "No location",
            cam["zone"] or "No zone",
            f"{cam['nvr_name'] or 'No NVR'} Ch.{cam['nvr_channel'] or 1}",
        ])
        description = f"Maintenance {'ENABLED' if state else 'DISABLED'} for {ip} ({details})"
        target = f"{cam['name'] or ip} | {ip}"
    else:
        description = f"Maintenance {'ENABLED' if state else 'DISABLED'} for {ip}"
        target = ip
    add_audit(user, "maintenance", description, target, "system", "success")

def bulk_set_maintenance(ips, state, user="system"):
    with _lock:
        with get_db() as conn:
            for ip in ips:
                conn.execute("UPDATE status SET maintenance=? WHERE ip=?", (1 if state else 0, ip))
    add_audit(user, "bulk", f"Bulk maintenance {'ON' if state else 'OFF'} — {len(ips)} cameras", f"{len(ips)} cameras", "system", "success")

def bulk_update_zone(ips, zone, user="system"):
    with _lock:
        with get_db() as conn:
            for ip in ips:
                conn.execute("UPDATE cameras SET zone=? WHERE ip=?", (zone, ip))
    add_audit(user, "bulk", f"Zone -> '{zone}' for {len(ips)} cameras", f"{len(ips)} cameras", "system", "success")

def bulk_update_nvr(ips, nvr_name, user="system"):
    with _lock:
        with get_db() as conn:
            for ip in ips:
                conn.execute("UPDATE cameras SET nvr_name=? WHERE ip=?", (nvr_name, ip))
    add_audit(user, "bulk", f"NVR -> '{nvr_name}' for {len(ips)} cameras", f"{len(ips)} cameras", "system", "success")

# ── Status Updates ─────────────────────────────────────────────────────────────
# monitor.py holds fail_streak + prev_state IN MEMORY — never written per ping.
# These functions are only called on actual STATE CHANGES.

def record_went_offline(ip, now_str):
    with _lock:
        with get_db() as conn:
            conn.execute("UPDATE status SET online=0, offline_since=? WHERE ip=?", (now_str, ip))
            conn.execute("INSERT INTO events (ip, event, ts) VALUES (?,?,?)", (ip, "offline", now_str))
            today = now_str[:10]
            conn.execute("""
                INSERT INTO daily_snapshots (date, ip, offline_events, downtime_min, total_checks)
                VALUES (?,?,1,0,0)
                ON CONFLICT(date, ip) DO UPDATE SET offline_events = offline_events + 1
            """, (today, ip))

def record_came_online(ip, now_str):
    with _lock:
        with get_db() as conn:
            row = conn.execute("SELECT offline_since FROM status WHERE ip=?", (ip,)).fetchone()
            duration_s = None
            if row and row["offline_since"]:
                try:
                    duration_s = int((datetime.fromisoformat(now_str) - datetime.fromisoformat(row["offline_since"])).total_seconds())
                except Exception:
                    pass
            conn.execute("UPDATE status SET online=1, last_seen=?, offline_since=NULL WHERE ip=?", (now_str, ip))
            conn.execute("INSERT INTO events (ip, event, ts, duration_s) VALUES (?,?,?,?)", (ip, "online", now_str, duration_s))
            # NOTE: downtime_min is NOT written here. tick_downtime() accumulates it
            # incrementally each poll while the camera is offline, so we avoid
            # double-counting the outage duration on recovery.

def update_last_seen(ip, now_str):
    with get_db() as conn:
        conn.execute("UPDATE status SET last_seen=?, online=1 WHERE ip=?", (now_str, ip))

def update_last_seen_bulk(ips, now_str):
    """Update last_seen for all still-online cameras in a single transaction."""
    if not ips:
        return
    with get_db() as conn:
        conn.executemany(
            "UPDATE status SET last_seen=?, online=1 WHERE ip=?",
            [(now_str, ip) for ip in ips]
        )

def tick_daily_check(ip):
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.execute("""
            INSERT INTO daily_snapshots (date, ip, total_checks, offline_events, downtime_min)
            VALUES (?,?,1,0,0)
            ON CONFLICT(date, ip) DO UPDATE SET total_checks = total_checks + 1
        """, (today, ip))

def tick_daily_checks_bulk(ips):
    """Increment total_checks for all IPs in a single transaction. O(1) transactions regardless of count."""
    if not ips:
        return
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.executemany("""
            INSERT INTO daily_snapshots (date, ip, total_checks, offline_events, downtime_min)
            VALUES (?,?,1,0,0)
            ON CONFLICT(date, ip) DO UPDATE SET total_checks = total_checks + 1
        """, [(today, ip) for ip in ips])

def tick_downtime(ip, minutes: int):
    """Accumulate downtime while a camera is offline, one poll interval at a time.

    Called each poll cycle for cameras that are currently offline so that
    downtime_min reflects the ongoing outage in real time — not just after
    the camera recovers (which is when record_came_online writes the lump sum).
    """
    if minutes <= 0:
        return
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.execute("""
            INSERT INTO daily_snapshots (date, ip, total_checks, offline_events, downtime_min)
            VALUES (?,?,0,0,?)
            ON CONFLICT(date, ip) DO UPDATE SET downtime_min = downtime_min + ?
        """, (today, ip, minutes, minutes))

def tick_downtime_bulk(ip_minutes_pairs):
    """Accumulate downtime for multiple offline cameras in a single transaction."""
    if not ip_minutes_pairs:
        return
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        conn.executemany("""
            INSERT INTO daily_snapshots (date, ip, total_checks, offline_events, downtime_min)
            VALUES (?,?,0,0,?)
            ON CONFLICT(date, ip) DO UPDATE SET downtime_min = downtime_min + ?
        """, [(today, ip, m, m) for ip, m in ip_minutes_pairs if m > 0])

def mark_alert_sent(ip, alert_type="offline"):
    now = datetime.now().isoformat()
    with _lock:
        with get_db() as conn:
            col = "last_alert_sent" if alert_type == "offline" else "last_recovery_sent"
            conn.execute(f"UPDATE status SET {col}=? WHERE ip=?", (now, ip))

def log_alert(alert_type, target, channel, message):
    with _lock:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO alert_log (ts,alert_type,target,channel,message) VALUES (?,?,?,?,?)",
                (datetime.now().isoformat(), alert_type, target, channel, message)
            )

def get_status(ip):
    with get_db() as conn:
        row = conn.execute("SELECT * FROM status WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

def get_offline_cameras():
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT c.*, s.offline_since, s.last_alert_sent, s.maintenance "
            "FROM cameras c JOIN status s ON c.ip=s.ip WHERE s.online=0 AND c.active=1"
        ).fetchall()]

def compute_uptime_pcts():
    today = datetime.now().strftime("%Y-%m-%d")
    with get_db() as conn:
        rows = conn.execute(
            "SELECT ip, total_checks, downtime_min FROM daily_snapshots WHERE date=?", (today,)
        ).fetchall()
        pairs = [(_calc_uptime_pct(r["total_checks"], r["downtime_min"]), r["ip"]) for r in rows]
        if pairs:
            conn.executemany("UPDATE status SET health_pct=? WHERE ip=?", pairs)

def get_camera_history(ip, limit=20):
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM events WHERE ip=? ORDER BY ts DESC LIMIT ?", (ip, limit)
        ).fetchall()]

def get_camera_event_log(limit=500, event_type=None, zone=None, nvr=None, search=None, date_from=None, date_to=None, offset=0):
    with get_db() as conn:
        q = (
            "SELECT e.ts, e.event, e.duration_s, e.ip, c.name, c.zone, c.nvr_name "
            "FROM events e JOIN cameras c ON e.ip=c.ip"
        )
        params, filters = [], []
        if event_type and event_type != "all":
            filters.append("e.event=?")
            params.append(event_type)
        if zone:
            filters.append("c.zone=?")
            params.append(zone)
        if nvr:
            filters.append("c.nvr_name=?")
            params.append(nvr)
        if search:
            filters.append("(e.ip LIKE ? OR c.name LIKE ? OR c.zone LIKE ? OR c.nvr_name LIKE ?)")
            params += [f"%{search}%"] * 4
        if date_from:
            filters.append("e.ts>=?")
            params.append(f"{date_from}T00:00:00")
        if date_to:
            filters.append("e.ts<=?")
            params.append(f"{date_to}T23:59:59")
        if filters:
            q += " WHERE " + " AND ".join(filters)
        count_q = "SELECT COUNT(*) FROM (" + q + ")"
        total = conn.execute(count_q, params).fetchone()[0]
        q += " ORDER BY e.ts DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        items = [dict(r) for r in conn.execute(q, params).fetchall()]
        return {"items": items, "total": total}

def get_monthly_report(year, month):
    prefix = f"{year}-{month:02d}"
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT d.ip, c.name, c.zone, c.nvr_name,
                SUM(d.total_checks) as total_checks,
                SUM(d.offline_events) as offline_events,
                SUM(d.downtime_min) as total_downtime_min,
                ROUND((SUM(d.total_checks) - MIN(SUM(d.downtime_min), SUM(d.total_checks)))
                    * 100.0 / MAX(SUM(d.total_checks),1), 1) as uptime_pct
            FROM daily_snapshots d JOIN cameras c ON d.ip=c.ip
            WHERE d.date LIKE ?
            GROUP BY d.ip ORDER BY uptime_pct ASC
        """, (f"{prefix}%",)).fetchall()]

def get_worst_cameras(days=30, limit=10):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT d.ip, c.name, c.zone, c.nvr_name,
                SUM(d.offline_events) as offline_events,
                SUM(d.downtime_min) as total_downtime_min,
                ROUND((SUM(d.total_checks) - MIN(SUM(d.downtime_min), SUM(d.total_checks)))
                    * 100.0 / MAX(SUM(d.total_checks),1), 1) as uptime_pct
            FROM daily_snapshots d JOIN cameras c ON d.ip=c.ip
            WHERE d.date >= ?
            GROUP BY d.ip ORDER BY uptime_pct ASC LIMIT ?
        """, (cutoff, limit)).fetchall()]

def get_daily_event_count(days=30):
    cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT date, SUM(offline_events) as total_offline
            FROM daily_snapshots WHERE date >= ?
            GROUP BY date ORDER BY date ASC
        """, (cutoff,)).fetchall()]


def get_report_overview(date_from, date_to):
    with get_db() as conn:
        row = conn.execute("""
            SELECT
                COALESCE(SUM(total_checks), 0) as total_checks,
                COALESCE(SUM(offline_events), 0) as offline_events,
                COALESCE(SUM(downtime_min), 0) as downtime_min
            FROM daily_snapshots
            WHERE date BETWEEN ? AND ?
        """, (date_from, date_to)).fetchone()
        total_checks = row["total_checks"] or 0
        downtime_min = row["downtime_min"] or 0
        return {
            "total_checks": total_checks,
            "offline_events": row["offline_events"] or 0,
            "downtime_min": downtime_min,
            "uptime_pct": _calc_uptime_pct(total_checks, downtime_min),
        }


def get_report_daily_trend(date_from, date_to):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT
                date,
                COALESCE(SUM(offline_events), 0) as offline_events,
                COALESCE(SUM(downtime_min), 0) as downtime_min
            FROM daily_snapshots
            WHERE date BETWEEN ? AND ?
            GROUP BY date
            ORDER BY date ASC
        """, (date_from, date_to)).fetchall()]


def get_report_worst_cameras(date_from, date_to, limit=10):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT
                d.ip, c.name, c.zone, c.nvr_name,
                SUM(d.offline_events) as offline_events,
                SUM(d.downtime_min) as total_downtime_min,
                ROUND((SUM(d.total_checks) - MIN(SUM(d.downtime_min), SUM(d.total_checks)))
                    * 100.0 / MAX(SUM(d.total_checks),1), 1) as uptime_pct
            FROM daily_snapshots d
            JOIN cameras c ON d.ip = c.ip
            WHERE d.date BETWEEN ? AND ?
            GROUP BY d.ip
            ORDER BY total_downtime_min DESC, offline_events DESC, uptime_pct ASC
            LIMIT ?
        """, (date_from, date_to, limit)).fetchall()]


def get_report_zone_summary(date_from, date_to):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT
                COALESCE(c.zone, 'Unassigned') as zone,
                COUNT(DISTINCT c.ip) as camera_count,
                COALESCE(SUM(d.offline_events), 0) as offline_events,
                COALESCE(SUM(d.downtime_min), 0) as downtime_min,
                ROUND((SUM(d.total_checks) - MIN(SUM(d.downtime_min), SUM(d.total_checks)))
                    * 100.0 / MAX(SUM(d.total_checks),1), 1) as uptime_pct
            FROM cameras c
            LEFT JOIN daily_snapshots d ON d.ip = c.ip AND d.date BETWEEN ? AND ?
            WHERE c.active = 1
            GROUP BY COALESCE(c.zone, 'Unassigned')
            ORDER BY downtime_min DESC, offline_events DESC, zone ASC
        """, (date_from, date_to)).fetchall()]


def get_report_nvr_summary(date_from, date_to):
    with get_db() as conn:
        return [dict(r) for r in conn.execute("""
            SELECT
                COALESCE(c.nvr_name, 'Unassigned') as nvr_name,
                COUNT(DISTINCT c.ip) as camera_count,
                COALESCE(SUM(d.offline_events), 0) as offline_events,
                COALESCE(SUM(d.downtime_min), 0) as downtime_min,
                ROUND((SUM(d.total_checks) - MIN(SUM(d.downtime_min), SUM(d.total_checks)))
                    * 100.0 / MAX(SUM(d.total_checks),1), 1) as uptime_pct
            FROM cameras c
            LEFT JOIN daily_snapshots d ON d.ip = c.ip AND d.date BETWEEN ? AND ?
            WHERE c.active = 1
            GROUP BY COALESCE(c.nvr_name, 'Unassigned')
            ORDER BY downtime_min DESC, offline_events DESC, nvr_name ASC
        """, (date_from, date_to)).fetchall()]


def get_unique_nvr_ips():
    """Return list of {nvr_ip, nvr_name} for all active cameras with an nvr_ip set."""
    with get_db() as conn:
        rows = conn.execute("""
            SELECT DISTINCT
                TRIM(nvr_ip) as nvr_ip,
                COALESCE(NULLIF(TRIM(nvr_name), ''), TRIM(nvr_ip)) as nvr_name
            FROM cameras
            WHERE active=1 AND TRIM(COALESCE(nvr_ip,'')) != ''
            ORDER BY nvr_name
        """).fetchall()
        return [dict(r) for r in rows]


def upsert_nvr_status(nvr_ip, nvr_name, online, now):
    """Update NVR ping state. Called each poll cycle by monitor."""
    with get_db() as conn:
        existing = conn.execute(
            "SELECT online, offline_since FROM nvr_status WHERE nvr_ip=?", (nvr_ip,)
        ).fetchone()
        if existing is None:
            offline_since = None if online else now
            conn.execute(
                "INSERT INTO nvr_status (nvr_ip, nvr_name, online, last_seen, offline_since) VALUES (?,?,?,?,?)",
                (nvr_ip, nvr_name, 1 if online else 0, now if online else None, offline_since),
            )
        else:
            was_online = bool(existing["online"])
            if online:
                conn.execute(
                    "UPDATE nvr_status SET nvr_name=?, online=1, last_seen=?, offline_since=NULL WHERE nvr_ip=?",
                    (nvr_name, now, nvr_ip),
                )
            else:
                offline_since = existing["offline_since"] or (now if was_online else None)
                conn.execute(
                    "UPDATE nvr_status SET nvr_name=?, online=0, offline_since=? WHERE nvr_ip=?",
                    (nvr_name, offline_since, nvr_ip),
                )


def get_nvr_status_map():
    """Return {nvr_ip: {online, last_seen, offline_since}} from DB."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM nvr_status").fetchall()
        return {r["nvr_ip"]: dict(r) for r in rows}


def get_nvr_endpoints():
    with get_db() as conn:
        rows = [dict(r) for r in conn.execute("""
            SELECT
                COALESCE(NULLIF(TRIM(nvr_name), ''), 'Unassigned') as nvr_name,
                COALESCE(NULLIF(TRIM(nvr_ip), ''), '') as nvr_ip,
                COUNT(*) as total_cameras
            FROM cameras
            WHERE active = 1
            GROUP BY COALESCE(NULLIF(TRIM(nvr_name), ''), 'Unassigned'), COALESCE(NULLIF(TRIM(nvr_ip), ''), '')
            ORDER BY nvr_name ASC, nvr_ip ASC
        """).fetchall()]
        items = []
        for row in rows:
            cams = [dict(r) for r in conn.execute("""
                SELECT ip, name, location, zone, nvr_channel, brand
                FROM cameras
                WHERE active = 1
                  AND COALESCE(NULLIF(TRIM(nvr_name), ''), 'Unassigned') = ?
                  AND COALESCE(NULLIF(TRIM(nvr_ip), ''), '') = ?
                ORDER BY nvr_channel ASC, name ASC
            """, (row["nvr_name"], row["nvr_ip"])).fetchall()]
            items.append({
                "nvr_name": row["nvr_name"],
                "nvr_ip": row["nvr_ip"],
                "total_cameras": row["total_cameras"],
                "zones": sorted({(cam.get("zone") or "Unassigned") for cam in cams}),
                "locations": sorted({(cam.get("location") or "").strip() for cam in cams if (cam.get("location") or "").strip()}),
                "brands": sorted({(cam.get("brand") or "").strip().capitalize() for cam in cams if (cam.get("brand") or "").strip()}),
                "cameras": cams,
            })
        return items


def get_nvr_monitor_data(days=7):
    cutoff = (datetime.now() - timedelta(days=max(days - 1, 0))).strftime("%Y-%m-%d")
    with get_db() as conn:
        health_map = _get_health_map(conn, days=days)
        camera_rows = [dict(r) for r in conn.execute("""
            SELECT
                c.ip, c.name, c.location, c.zone, c.nvr_name, c.nvr_channel, c.brand,
                s.online, s.last_seen, s.offline_since, s.maintenance, s.health_pct
            FROM cameras c
            LEFT JOIN status s ON c.ip = s.ip
            WHERE c.active = 1
            ORDER BY COALESCE(c.nvr_name, 'Unassigned'), c.nvr_channel, c.name
        """).fetchall()]
        trend_rows = [dict(r) for r in conn.execute("""
            SELECT
                COALESCE(c.nvr_name, 'Unassigned') as nvr_name,
                COALESCE(SUM(d.offline_events), 0) as offline_events_7d,
                COALESCE(SUM(d.downtime_min), 0) as downtime_min_7d,
                COALESCE(SUM(d.total_checks), 0) as total_checks_7d
            FROM cameras c
            LEFT JOIN daily_snapshots d ON d.ip = c.ip AND d.date >= ?
            WHERE c.active = 1
            GROUP BY COALESCE(c.nvr_name, 'Unassigned')
        """, (cutoff,)).fetchall()]
        event_rows = [dict(r) for r in conn.execute("""
            SELECT
                COALESCE(c.nvr_name, 'Unassigned') as nvr_name,
                e.ts, e.event, e.ip, c.name, c.zone
            FROM events e
            JOIN cameras c ON c.ip = e.ip
            WHERE c.active = 1
            ORDER BY e.ts DESC
            LIMIT 300
        """).fetchall()]

    trend_map = {row["nvr_name"]: row for row in trend_rows}
    events_by_nvr = {}
    for row in event_rows:
        events_by_nvr.setdefault(row["nvr_name"], [])
        if len(events_by_nvr[row["nvr_name"]]) < 6:
            events_by_nvr[row["nvr_name"]].append(row)

    grouped = {}
    for cam in camera_rows:
        nvr_name = (cam.get("nvr_name") or "").strip() or "Unassigned"
        cam["health_7d"] = health_map.get(cam["ip"], 100.0)
        grouped.setdefault(nvr_name, []).append(cam)

    nvrs = []
    for nvr_name, cams in grouped.items():
        total = len(cams)
        online = sum(1 for c in cams if c.get("online") and not c.get("maintenance"))
        offline = sum(1 for c in cams if not c.get("online"))
        maintenance = sum(1 for c in cams if c.get("maintenance"))
        healthy = sum(1 for c in cams if c.get("health_7d", 100.0) >= 99.0)
        degraded = sum(1 for c in cams if 90.0 <= (c.get("health_7d", 100.0) or 0) < 99.0)
        average_health = round(sum(c.get("health_7d", 100.0) or 0 for c in cams) / total, 1) if total else 100.0
        last_seen_values = [c.get("last_seen") for c in cams if c.get("last_seen")]
        offline_since_values = [c.get("offline_since") for c in cams if c.get("offline_since")]
        zones = sorted({(c.get("zone") or "Unassigned") for c in cams})
        locations = sorted({(c.get("location") or "").strip() for c in cams if (c.get("location") or "").strip()})
        brands = sorted({(c.get("brand") or "").strip().capitalize() for c in cams if (c.get("brand") or "").strip()})
        trend = trend_map.get(nvr_name, {})

        if total and maintenance == total:
            status = "maintenance"
        elif total and offline == total:
            status = "offline"
        elif offline > 0 or maintenance > 0 or average_health < 99.0:
            status = "degraded"
        else:
            status = "online"

        if status == "offline":
            summary = "All mapped cameras are offline."
        elif status == "maintenance":
            summary = "All mapped cameras are in maintenance mode."
        elif status == "degraded":
            summary = "One or more mapped cameras need attention."
        else:
            summary = "Mapped cameras are healthy."

        nvrs.append({
            "nvr_name": nvr_name,
            "status": status,
            "status_summary": summary,
            "total_cameras": total,
            "online_cameras": online,
            "offline_cameras": offline,
            "maintenance_cameras": maintenance,
            "healthy_cameras": healthy,
            "degraded_cameras": degraded,
            "average_health_7d": average_health,
            "offline_events_7d": trend.get("offline_events_7d", 0) or 0,
            "downtime_min_7d": trend.get("downtime_min_7d", 0) or 0,
            "total_checks_7d": trend.get("total_checks_7d", 0) or 0,
            "last_seen": max(last_seen_values) if last_seen_values else None,
            "offline_since": min(offline_since_values) if offline_since_values else None,
            "zones": zones,
            "locations": locations,
            "brands": brands,
            "cameras": cams,
            "recent_events": events_by_nvr.get(nvr_name, []),
        })

    status_counts = {
        "total": len(nvrs),
        "online": sum(1 for n in nvrs if n["status"] == "online"),
        "offline": sum(1 for n in nvrs if n["status"] == "offline"),
        "degraded": sum(1 for n in nvrs if n["status"] == "degraded"),
        "maintenance": sum(1 for n in nvrs if n["status"] == "maintenance"),
        "mapped_cameras": sum(n["total_cameras"] for n in nvrs),
    }
    return {"summary": status_counts, "items": nvrs}

def get_stats():
    with get_db() as conn:
        total       = conn.execute("SELECT COUNT(*) FROM cameras WHERE active=1").fetchone()[0]
        online      = conn.execute("SELECT COUNT(*) FROM status s JOIN cameras c ON s.ip=c.ip WHERE s.online=1 AND s.maintenance=0 AND c.active=1").fetchone()[0]
        offline     = conn.execute("SELECT COUNT(*) FROM status s JOIN cameras c ON s.ip=c.ip WHERE s.online=0 AND c.active=1").fetchone()[0]
        maintenance = conn.execute("SELECT COUNT(*) FROM status WHERE maintenance=1").fetchone()[0]
        return {"total": total, "online": online, "offline": offline, "maintenance": maintenance}

def get_zones():
    with get_db() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT zone FROM cameras WHERE active=1 AND zone IS NOT NULL ORDER BY zone").fetchall()]

def get_locations():
    with get_db() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT location FROM cameras WHERE active=1 AND location IS NOT NULL AND TRIM(location)<>'' ORDER BY location").fetchall()]

def get_nvrs():
    with get_db() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT nvr_name FROM cameras WHERE active=1 AND nvr_name IS NOT NULL ORDER BY nvr_name").fetchall()]

def add_audit(user, event_type, description, target, ip_address, result):
    with _lock:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO audit (ts,user,event_type,description,target,ip_address,result) VALUES (?,?,?,?,?,?,?)",
                (datetime.now().isoformat(), user, event_type, description, target, ip_address, result)
            )

def get_audit_log(limit=200, event_type=None, search=None, result=None, user=None, date_from=None, date_to=None, offset=0):
    with get_db() as conn:
        q, params, filters = "SELECT * FROM audit", [], []
        if user:
            filters.append("user=?"); params.append(user)
        if event_type and event_type != "all":
            filters.append("event_type=?"); params.append(event_type)
        if result and result != "all":
            filters.append("result=?"); params.append(result)
        if search:
            filters.append("(user LIKE ? OR description LIKE ? OR target LIKE ?)"); params += [f"%{search}%"]*3
        if date_from:
            filters.append("ts>=?"); params.append(f"{date_from}T00:00:00")
        if date_to:
            filters.append("ts<=?"); params.append(f"{date_to}T23:59:59")
        if filters: q += " WHERE " + " AND ".join(filters)
        count_q = "SELECT COUNT(*) FROM (" + q + ")"
        total = conn.execute(count_q, params).fetchone()[0]
        q += " ORDER BY ts DESC LIMIT ? OFFSET ?"; params.extend([limit, offset])
        items = [dict(r) for r in conn.execute(q, params).fetchall()]
        return {"items": items, "total": total}

def get_audit_users():
    with get_db() as conn:
        return [r[0] for r in conn.execute(
            "SELECT DISTINCT user FROM audit WHERE user IS NOT NULL AND TRIM(user)<>'' ORDER BY user"
        ).fetchall()]

def get_audit_stats():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT event_type, COUNT(*) as total FROM audit GROUP BY event_type"
        ).fetchall()
        stats = {"total": 0}
        for row in rows:
            stats[row["event_type"]] = row["total"]
            stats["total"] += row["total"]
        return stats

def purge_old_data():
    cutoff      = (datetime.now() - timedelta(days=RETENTION_DAYS)).isoformat()
    cutoff_date = cutoff[:10]
    with _lock:
        with get_db() as conn:
            r1 = conn.execute("DELETE FROM events WHERE ts<?", (cutoff,)).rowcount
            r2 = conn.execute("DELETE FROM daily_snapshots WHERE date<?", (cutoff_date,)).rowcount
            r3 = conn.execute("DELETE FROM alert_log WHERE ts<?", (cutoff,)).rowcount
            r4 = conn.execute("DELETE FROM audit WHERE ts<?", (cutoff,)).rowcount
            conn.execute("VACUUM")
    print(f"[DB] Purged: {r1} events, {r2} snapshots, {r3} alerts, {r4} audit rows")

def load_cameras_from_csv():
    import csv
    csv_path = cfg.get("cameras", "csv_path", fallback="cameras.csv")
    path = os.path.join(os.path.dirname(__file__), csv_path)
    if not os.path.exists(path): return 0
    # Collect IPs that were explicitly deleted (active=0) so we don't resurrect them.
    with _lock:
        with get_db() as conn:
            deleted_ips = {r[0] for r in conn.execute("SELECT ip FROM cameras WHERE active=0").fetchall()}
    count = 0
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ip = row.get("ip", "").strip()
            if not ip: continue
            if ip in deleted_ips:
                continue  # Camera was manually deleted — do not resurrect from CSV
            upsert_camera({"ip": ip, "name": row.get("name",""), "location": row.get("location",""),
                "zone": row.get("zone",""), "nvr_name": row.get("nvr_name",""), "nvr_ip": row.get("nvr_ip",""),
                "nvr_channel": row.get("nvr_channel",1), "brand": row.get("brand","").lower(),
                "username": row.get("username","admin"), "password": row.get("password",""),
                "notes": row.get("notes",""), "rtsp_url": row.get("rtsp_url","")})
            count += 1
    return count
