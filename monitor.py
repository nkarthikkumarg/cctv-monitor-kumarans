"""
monitor.py — Ping engine with IN-MEMORY state tracking.

Key principle:
  - fail_streak and prev_online are kept in a Python dict (RAM only)
  - DB is written ONLY when a camera changes state (online <-> offline)
  - tick_daily_check() increments total_checks counter once per poll per camera
  - No row is inserted or updated in the DB for every ping result
"""
import subprocess, platform, logging, configparser, os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from apscheduler.schedulers.background import BackgroundScheduler

import db, alerts, central_sync

cfg = configparser.ConfigParser()
cfg.read(os.path.join(os.path.dirname(__file__), "config.ini"))
log = logging.getLogger(__name__)

POLL_INTERVAL = 60
MAX_WORKERS = 150
PING_TIMEOUT = 1000
STATUS_FAIL_THRESHOLD = 2
ALERT_FAIL_THRESHOLD = 2
COOLDOWN_MIN = 30
DAILY_TIME = "08:00"
USER_SYNC_INTERVAL = 900
IS_WINDOWS     = platform.system().lower() == "windows"

scheduler = BackgroundScheduler()


def reload_settings():
    global POLL_INTERVAL, MAX_WORKERS, PING_TIMEOUT, STATUS_FAIL_THRESHOLD
    global ALERT_FAIL_THRESHOLD, COOLDOWN_MIN, DAILY_TIME, USER_SYNC_INTERVAL
    cfg.read(os.path.join(os.path.dirname(__file__), "config.ini"))
    POLL_INTERVAL = cfg.getint("monitor", "poll_interval", fallback=60)
    MAX_WORKERS = cfg.getint("monitor", "max_workers", fallback=150)
    PING_TIMEOUT = cfg.getint("monitor", "ping_timeout_ms", fallback=1000)
    STATUS_FAIL_THRESHOLD = cfg.getint(
        "monitor",
        "status_retries",
        fallback=cfg.getint("monitor", "ping_retries", fallback=2),
    )
    ALERT_FAIL_THRESHOLD = max(
        STATUS_FAIL_THRESHOLD,
        cfg.getint("monitor", "alert_ping_retries", fallback=STATUS_FAIL_THRESHOLD),
    )
    COOLDOWN_MIN = cfg.getint("monitor", "alert_cooldown_minutes", fallback=30)
    DAILY_TIME = cfg.get("email", "daily_report_time", fallback="08:00")
    USER_SYNC_INTERVAL = cfg.getint("monitor", "user_sync_interval_sec", fallback=900)


def reschedule_jobs():
    if not scheduler.running:
        return
    h, m = DAILY_TIME.split(":")
    scheduler.reschedule_job("poll", trigger="interval", seconds=POLL_INTERVAL)
    scheduler.reschedule_job("central_sync", trigger="interval", seconds=POLL_INTERVAL)
    scheduler.reschedule_job("user_sync", trigger="interval", seconds=USER_SYNC_INTERVAL)
    scheduler.reschedule_job("daily", trigger="cron", hour=int(h), minute=int(m))

# ── In-memory state (never written to DB per-ping) ────────────────────────────
# { ip: { "online": bool, "fail_streak": int } }
_state = {}
# { nvr_ip: { "online": bool, "fail_streak": int } }
_nvr_state = {}

def _init_state():
    """Load current DB status into memory on startup."""
    for cam in db.get_all_cameras():
        ip = cam["ip"]
        _state[ip] = {
            "online": bool(cam.get("online", 1)),
            "fail_streak": 0,
            "alerted_offline": False,
        }
    nvr_map = db.get_nvr_status_map()
    for nvr_ip, row in nvr_map.items():
        _nvr_state[nvr_ip] = {
            "online": bool(row.get("online", 1)),
            "fail_streak": 0,
        }

# ── Ping ──────────────────────────────────────────────────────────────────────
def _ping(ip):
    try:
        if IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", str(PING_TIMEOUT), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, PING_TIMEOUT // 1000)), ip]
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=5).returncode == 0
    except Exception:
        return False


def ping_host(ip):
    ip = (ip or "").strip()
    if not ip:
        return False
    return _ping(ip)

# ── Poll cycle ────────────────────────────────────────────────────────────────
def poll_all():
    cameras = db.get_all_cameras()
    if not cameras:
        return
    now = datetime.now().isoformat()
    log.info("Polling %d cameras...", len(cameras))

    # Ensure all cameras are in state dict
    for cam in cameras:
        if cam["ip"] not in _state:
            _state[cam["ip"]] = {"online": True, "fail_streak": 0, "alerted_offline": False}

    newly_offline, newly_recovered = [], []
    alertable_offline, alertable_recovered = [], []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {ex.submit(_ping, cam["ip"]): cam for cam in cameras}
        for future in as_completed(futures):
            cam = futures[future]
            ip  = cam["ip"]
            try:
                is_up = future.result()
            except Exception:
                is_up = False

            st = _state[ip]

            if is_up:
                # ── Camera is responding ──────────────────────────────────────
                was_alerted = st.get("alerted_offline", False)
                st["fail_streak"] = 0

                if not st["online"]:
                    # State change: offline → online
                    st["online"] = True
                    st["alerted_offline"] = False
                    db.record_came_online(ip, now)
                    newly_recovered.append(cam)
                    if was_alerted:
                        alertable_recovered.append(cam)
                else:
                    # Still online — just update last_seen (lightweight)
                    db.update_last_seen(ip, now)

            else:
                # ── Camera not responding ────────────────────────────────────
                st["fail_streak"] += 1

                if st["online"] and st["fail_streak"] >= STATUS_FAIL_THRESHOLD:
                    # State change: online → offline (confirmed after N failures)
                    st["online"] = False
                    st["alerted_offline"] = False
                    db.record_went_offline(ip, now)
                    newly_offline.append(cam)
                if (not st["online"] and
                        not st.get("alerted_offline") and
                        st["fail_streak"] >= ALERT_FAIL_THRESHOLD):
                    st["alerted_offline"] = True
                    alertable_offline.append(cam)
                # else: still failing but not yet confirmed, or already offline
                # → nothing written to DB

                # Accumulate downtime in real time while camera is confirmed offline.
                # Without this, downtime_min is only written on recovery, causing the
                # health % to stay at 100% for the duration of an ongoing outage.
                if not st["online"]:
                    db.tick_downtime(ip, POLL_INTERVAL // 60 or 1)

            # Always tick daily check counter (one write per camera per poll)
            db.tick_daily_check(ip)

    # Recompute health % from today's snapshot (fast aggregation)
    db.compute_uptime_pcts()

    # ── NVR ping ─────────────────────────────────────────────────────────────
    nvr_list = db.get_unique_nvr_ips()
    if nvr_list:
        now_nvr = datetime.now().isoformat()
        for nvr in nvr_list:
            if nvr["nvr_ip"] not in _nvr_state:
                _nvr_state[nvr["nvr_ip"]] = {"online": True, "fail_streak": 0}

        with ThreadPoolExecutor(max_workers=min(32, len(nvr_list))) as ex:
            nvr_futures = {ex.submit(_ping, nvr["nvr_ip"]): nvr for nvr in nvr_list}
            for future in as_completed(nvr_futures):
                nvr = nvr_futures[future]
                nvr_ip = nvr["nvr_ip"]
                nvr_name = nvr["nvr_name"]
                try:
                    is_up = future.result()
                except Exception:
                    is_up = False
                st = _nvr_state[nvr_ip]
                if is_up:
                    if not st["online"]:
                        log.info("NVR back online: %s (%s)", nvr_name, nvr_ip)
                    st["online"] = True
                    st["fail_streak"] = 0
                else:
                    st["fail_streak"] += 1
                    if st["online"] and st["fail_streak"] >= STATUS_FAIL_THRESHOLD:
                        st["online"] = False
                        log.warning("NVR went offline: %s (%s)", nvr_name, nvr_ip)
                db.upsert_nvr_status(nvr_ip, nvr_name, st["online"], now_nvr)
        log.debug("NVR ping complete. %d NVRs checked.", len(nvr_list))

    # Dispatch alerts
    _dispatch_alerts(cameras, alertable_offline, alertable_recovered)
    if newly_offline or newly_recovered:
        if central_sync.push_summary():
            log.info(
                "Central sync pushed immediately after status change. Offline: %d, Recovered: %d",
                len(newly_offline),
                len(newly_recovered),
            )
        else:
            log.warning(
                "Immediate central sync after status change failed. Offline: %d, Recovered: %d",
                len(newly_offline),
                len(newly_recovered),
            )
    log.info("Poll complete. Offline: %d, Recovered: %d", len(newly_offline), len(newly_recovered))

# ── Alert dispatch ────────────────────────────────────────────────────────────
def _dispatch_alerts(all_cameras, newly_offline, newly_recovered):
    now = datetime.now()
    cooldown = timedelta(minutes=COOLDOWN_MIN)

    # Filter by cooldown
    to_alert_offline = []
    for cam in newly_offline:
        st = db.get_status(cam["ip"])
        if not st or st.get("maintenance"):
            continue
        last = st.get("last_alert_sent")
        if last and (now - datetime.fromisoformat(last)) < cooldown:
            continue
        to_alert_offline.append(cam)
        db.mark_alert_sent(cam["ip"], "offline")

    to_alert_recovery = []
    for cam in newly_recovered:
        st = db.get_status(cam["ip"])
        if not st or st.get("maintenance"):
            continue
        last = st.get("last_recovery_sent")
        if last and (now - datetime.fromisoformat(last)) < cooldown:
            continue
        to_alert_recovery.append(cam)
        db.mark_alert_sent(cam["ip"], "recovery")

    # NVR grouping: if ALL cameras on an NVR are offline → one grouped alert
    if to_alert_offline:
        nvr_groups = {}
        for cam in to_alert_offline:
            nvr = cam.get("nvr_name")
            if nvr:
                nvr_groups.setdefault(nvr, []).append(cam)

        nvr_alerted = set()
        for nvr, cams in nvr_groups.items():
            all_on_nvr = [c for c in all_cameras if c.get("nvr_name") == nvr]
            offline_on_nvr = [c for c in all_on_nvr if not _state.get(c["ip"], {}).get("online", True)]
            if len(offline_on_nvr) == len(all_on_nvr) > 1:
                alerts.send_nvr_alert(nvr, cams)
                nvr_alerted.update(c["ip"] for c in cams)

        individual = [c for c in to_alert_offline if c["ip"] not in nvr_alerted]
        if individual:
            alerts.send_offline_alert(individual)

    if to_alert_recovery:
        alerts.send_recovery_alert(to_alert_recovery)

# ── Daily report ──────────────────────────────────────────────────────────────
def send_daily_report():
    stats   = db.get_stats()
    offline = db.get_offline_cameras()
    worst   = db.get_worst_cameras(days=30, limit=5)
    alerts.send_daily_summary(stats, offline, worst)
    log.info("Daily summary report sent.")

# ── Scheduler ─────────────────────────────────────────────────────────────────
def start_scheduler():
    db.init_db()
    db.load_cameras_from_csv()
    reload_settings()
    _init_state()

    h, m = DAILY_TIME.split(":")
    scheduler.add_job(poll_all,           "interval", seconds=POLL_INTERVAL, id="poll",  replace_existing=True)
    scheduler.add_job(send_daily_report,  "cron",     hour=int(h), minute=int(m),         id="daily", replace_existing=True)
    scheduler.add_job(db.purge_old_data,  "cron",     hour=3, minute=0,                   id="purge", replace_existing=True)
    scheduler.add_job(central_sync.push_summary, "interval", seconds=POLL_INTERVAL, id="central_sync", replace_existing=True)
    scheduler.add_job(central_sync.sync_users, "interval", seconds=USER_SYNC_INTERVAL, id="user_sync", replace_existing=True)
    scheduler.start()
    log.info(
        "Scheduler started. Poll every %ds, status retries=%d, alert retries=%d, daily report at %s",
        POLL_INTERVAL,
        STATUS_FAIL_THRESHOLD,
        ALERT_FAIL_THRESHOLD,
        DAILY_TIME,
    )
    poll_all()  # Run immediately on startup
    central_sync.push_summary()
    central_sync.sync_users()

def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
