"""
alerts.py — Email (SMTP) and WhatsApp (Twilio) alert engine.
"""
import configparser
import logging
import os
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from notification_settings import load_settings

cfg = configparser.ConfigParser()
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.ini")
log = logging.getLogger(__name__)

EMAIL_ENABLED = False
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TLS = True
SENDER_EMAIL = ""
SENDER_PASSWORD = ""
SUBJECT_PREFIX = "[CAM ALERT]"

WA_ENABLED = False
WA_SID = ""
WA_TOKEN = ""
WA_FROM = ""

NOTIFY_OFFLINE = True
NOTIFY_RECOVERY = True
DAILY_ENABLED = True
SITE_NAME = "Local Site"


def reload_settings():
    global EMAIL_ENABLED, SMTP_HOST, SMTP_PORT, SMTP_TLS, SENDER_EMAIL, SENDER_PASSWORD
    global SUBJECT_PREFIX, WA_ENABLED, WA_SID, WA_TOKEN, WA_FROM
    global NOTIFY_OFFLINE, NOTIFY_RECOVERY, DAILY_ENABLED, SITE_NAME

    cfg.clear()
    cfg.read(CONFIG_PATH)

    EMAIL_ENABLED = cfg.getboolean("email", "enabled", fallback=False)
    SMTP_HOST = cfg.get("email", "smtp_host", fallback="smtp.gmail.com")
    SMTP_PORT = cfg.getint("email", "smtp_port", fallback=587)
    SMTP_TLS = cfg.getboolean("email", "smtp_use_tls", fallback=True)
    SENDER_EMAIL = cfg.get("email", "sender_email", fallback="")
    SENDER_PASSWORD = cfg.get("email", "sender_password", fallback="")
    SUBJECT_PREFIX = cfg.get("email", "subject_prefix", fallback="[CAM ALERT]")

    WA_ENABLED = cfg.getboolean("whatsapp", "enabled", fallback=False)
    WA_SID = cfg.get("whatsapp", "account_sid", fallback="")
    WA_TOKEN = cfg.get("whatsapp", "auth_token", fallback="")
    WA_FROM = cfg.get("whatsapp", "from_number", fallback="")

    NOTIFY_OFFLINE = cfg.getboolean("notifications", "notify_offline", fallback=True)
    NOTIFY_RECOVERY = cfg.getboolean("notifications", "notify_recovery", fallback=True)
    DAILY_ENABLED = cfg.getboolean("notifications", "daily_summary_enabled", fallback=True)
    SITE_NAME = cfg.get("central", "site_name", fallback="Local Site").strip() or "Local Site"


reload_settings()


class SafeDict(dict):
    def __missing__(self, key):
        return ""


def _format_message(template, recipient_name, context):
    settings = load_settings()
    greeting_template = settings.get("greeting_template") or "Dear {name},"
    display_name = recipient_name or "User"
    greeting = greeting_template.format_map(SafeDict({"name": display_name, **context}))
    return template.format_map(SafeDict({"name": display_name, "greeting": greeting, **context}))


def _iter_recipients():
    settings = load_settings()
    for recipient in settings.get("recipients", []):
        yield recipient


def _send_email(recipient, subject, body_html, body_text=None):
    if not EMAIL_ENABLED:
        log.info("[EMAIL DISABLED] Would send to %s: %s", recipient.get("email"), subject)
        return
    email = (recipient.get("email") or "").strip()
    if not email:
        return
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = email
        if body_text:
            msg.attach(MIMEText(body_text, "plain"))
        msg.attach(MIMEText(body_html, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as srv:
            if SMTP_TLS:
                srv.starttls()
            srv.login(SENDER_EMAIL, SENDER_PASSWORD)
            srv.sendmail(SENDER_EMAIL, [email], msg.as_string())
        log.info("Email sent to %s: %s", email, subject)
    except Exception as exc:
        log.error("Email failed for %s: %s", email, exc)


def _send_whatsapp(recipient, message):
    if not WA_ENABLED:
        log.info("[WHATSAPP DISABLED] Would send to %s: %s", recipient.get("whatsapp"), message[:80])
        return
    to_number = (recipient.get("whatsapp") or "").strip()
    if not to_number:
        return
    try:
        from twilio.rest import Client
        Client(WA_SID, WA_TOKEN).messages.create(body=message, from_=WA_FROM, to=to_number)
        log.info("WhatsApp sent to %s", to_number)
    except Exception as exc:
        log.error("WhatsApp failed for %s: %s", to_number, exc)


def _template(name):
    settings = load_settings()
    return settings.get("templates", {}).get(name, "")


def _send_personalized(subject, template_key, context_builder):
    reload_settings()
    template = _template(template_key)
    for recipient in _iter_recipients():
        name = recipient.get("name") or "User"
        context = context_builder(recipient)
        message = _format_message(template, name, context)
        body_html = (
            "<html><body style='font-family:Arial,sans-serif;white-space:pre-line;color:#222'>"
            f"{message}"
            "</body></html>"
        )
        if recipient.get("email_enabled") and recipient.get("email"):
            _send_email(recipient, subject, body_html, message)
        if recipient.get("whatsapp_enabled") and recipient.get("whatsapp"):
            _send_whatsapp(recipient, message)


def send_offline_alert(cameras):
    reload_settings()
    if not NOTIFY_OFFLINE or not cameras:
        return
    now = datetime.now().strftime("%d-%b-%Y %I:%M %p")
    count = len(cameras)
    subject = f"{SUBJECT_PREFIX} {count} Camera{'s' if count > 1 else ''} Offline - {now}"

    def context_builder(_recipient):
        first = cameras[0]
        lines = [
            f"Site: {SITE_NAME}",
            f"Time: {now}",
            f"Affected cameras: {count}",
            "",
        ]
        for cam in cameras:
            lines.append(
                f"- {cam.get('name','Camera')} | {cam.get('ip','')} | "
                f"{cam.get('location','')} / {cam.get('zone','')} | "
                f"Offline since {str(cam.get('offline_since','?'))[:16]}"
            )
        return {
            "site_name": SITE_NAME,
            "time": now,
            "camera_count": count,
            "camera_name": first.get("name", "Camera"),
            "ip": first.get("ip", ""),
            "location": first.get("location", ""),
            "zone": first.get("zone", ""),
            "nvr": first.get("nvr_name", ""),
            "offline_since": str(first.get("offline_since", "?"))[:16],
            "details": "\n".join(lines),
        }

    _send_personalized(subject, "offline", context_builder)


def send_recovery_alert(cameras):
    reload_settings()
    if not NOTIFY_RECOVERY or not cameras:
        return
    now = datetime.now().strftime("%d-%b-%Y %I:%M %p")
    count = len(cameras)
    subject = f"{SUBJECT_PREFIX} {count} Camera{'s' if count > 1 else ''} Back Online - {now}"

    def context_builder(_recipient):
        first = cameras[0]
        lines = [
            f"Site: {SITE_NAME}",
            f"Time: {now}",
            f"Recovered cameras: {count}",
            "",
        ]
        for cam in cameras:
            lines.append(
                f"- {cam.get('name','Camera')} | {cam.get('ip','')} | "
                f"{cam.get('location','')} / {cam.get('zone','')}"
            )
        return {
            "site_name": SITE_NAME,
            "time": now,
            "camera_count": count,
            "camera_name": first.get("name", "Camera"),
            "ip": first.get("ip", ""),
            "location": first.get("location", ""),
            "zone": first.get("zone", ""),
            "nvr": first.get("nvr_name", ""),
            "details": "\n".join(lines),
        }

    _send_personalized(subject, "recovery", context_builder)


def send_daily_summary(stats, offline_cameras, worst=None):
    reload_settings()
    if not DAILY_ENABLED:
        return
    now = datetime.now().strftime("%d-%b-%Y")
    pct = round((stats["online"] / stats["total"] * 100) if stats["total"] else 0, 1)
    subject = f"{SUBJECT_PREFIX} Daily Camera Report - {now}"

    def context_builder(_recipient):
        lines = [
            f"Site: {SITE_NAME}",
            f"Date: {now}",
            f"Total: {stats['total']}",
            f"Online: {stats['online']} ({pct}%)",
            f"Offline: {stats['offline']}",
            f"Maintenance: {stats['maintenance']}",
        ]
        if offline_cameras:
            lines.extend(["", "Currently offline cameras:"])
            for cam in offline_cameras:
                lines.append(
                    f"- {cam.get('name','Camera')} | {cam.get('ip','')} | "
                    f"{cam.get('location','')} | Offline since {str(cam.get('offline_since','?'))[:16]}"
                )
        return {
            "site_name": SITE_NAME,
            "date": now,
            "total": stats["total"],
            "online": stats["online"],
            "offline": stats["offline"],
            "maintenance": stats["maintenance"],
            "details": "\n".join(lines),
        }

    _send_personalized(subject, "daily", context_builder)


def send_nvr_alert(nvr_name, cameras):
    reload_settings()
    if not NOTIFY_OFFLINE or not cameras:
        return
    now = datetime.now().strftime("%d-%b-%Y %I:%M %p")
    subject = f"{SUBJECT_PREFIX} NVR Offline: {nvr_name} - {len(cameras)} cameras affected - {now}"

    def context_builder(_recipient):
        lines = [
            f"Site: {SITE_NAME}",
            f"Time: {now}",
            f"NVR: {nvr_name}",
            f"Affected cameras: {len(cameras)}",
            "",
        ]
        for cam in cameras:
            lines.append(f"- {cam.get('name','Camera')} | {cam.get('ip','')}")
        first = cameras[0]
        return {
            "site_name": SITE_NAME,
            "time": now,
            "camera_count": len(cameras),
            "camera_name": first.get("name", "Camera"),
            "ip": first.get("ip", ""),
            "location": first.get("location", ""),
            "zone": first.get("zone", ""),
            "nvr": nvr_name,
            "offline_since": str(first.get("offline_since", "?"))[:16],
            "details": "\n".join(lines),
        }

    _send_personalized(subject, "offline", context_builder)
