"""
notification_settings.py — Local notification recipients and templates.
"""
import json
import os

BASE_DIR = os.path.dirname(__file__)
SETTINGS_PATH = os.path.join(BASE_DIR, "notification_settings.json")

DEFAULT_SETTINGS = {
    "greeting_template": "Dear {name},",
    "templates": {
        "offline": "{greeting}\n\nCamera {camera_name} ({ip}) at {location} / {zone} is offline since {offline_since}.\nPlease investigate.",
        "recovery": "{greeting}\n\nCamera {camera_name} ({ip}) at {location} / {zone} is back online as of {time}.",
        "daily": "{greeting}\n\nDaily summary for {site_name} on {date}.\nTotal: {total}\nOnline: {online}\nOffline: {offline}\nMaintenance: {maintenance}",
    },
    "recipients": [],
}


def _deepcopy(value):
    return json.loads(json.dumps(value))


def load_settings():
    if not os.path.exists(SETTINGS_PATH):
        return _deepcopy(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return _deepcopy(DEFAULT_SETTINGS)

    settings = _deepcopy(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        settings["greeting_template"] = str(
            data.get("greeting_template") or settings["greeting_template"]
        )
        templates = data.get("templates") or {}
        if isinstance(templates, dict):
            for key in ("offline", "recovery", "daily"):
                if templates.get(key):
                    settings["templates"][key] = str(templates[key])
        recipients = data.get("recipients") or []
        if isinstance(recipients, list):
            clean = []
            for item in recipients:
                if not isinstance(item, dict):
                    continue
                clean.append({
                    "name": str(item.get("name") or "").strip(),
                    "email": str(item.get("email") or "").strip(),
                    "whatsapp": str(item.get("whatsapp") or "").strip(),
                    "email_enabled": bool(item.get("email_enabled")),
                    "whatsapp_enabled": bool(item.get("whatsapp_enabled")),
                })
            settings["recipients"] = clean
    return settings


def save_settings(data):
    settings = _deepcopy(DEFAULT_SETTINGS)
    if isinstance(data, dict):
        settings["greeting_template"] = str(
            data.get("greeting_template") or settings["greeting_template"]
        ).strip() or DEFAULT_SETTINGS["greeting_template"]
        templates = data.get("templates") or {}
        if isinstance(templates, dict):
            for key in ("offline", "recovery", "daily"):
                settings["templates"][key] = str(
                    templates.get(key) or DEFAULT_SETTINGS["templates"][key]
                ).strip() or DEFAULT_SETTINGS["templates"][key]
        recipients = []
        for item in data.get("recipients") or []:
            if not isinstance(item, dict):
                continue
            recipient = {
                "name": str(item.get("name") or "").strip(),
                "email": str(item.get("email") or "").strip(),
                "whatsapp": str(item.get("whatsapp") or "").strip(),
                "email_enabled": bool(item.get("email_enabled")),
                "whatsapp_enabled": bool(item.get("whatsapp_enabled")),
            }
            if recipient["name"] or recipient["email"] or recipient["whatsapp"]:
                recipients.append(recipient)
        settings["recipients"] = recipients

    with open(SETTINGS_PATH, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)
    return settings
