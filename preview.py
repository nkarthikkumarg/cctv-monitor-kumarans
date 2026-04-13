"""
preview.py — Brand-aware stream URL builder for Hikvision, Dahua, Prama
"""
from urllib.parse import quote, unquote, urlsplit, urlunsplit


def build_auth(username, password):
    if not username:
        return ""
    user = quote(username or "", safe="")
    pwd = quote(password or "", safe="")
    return f"{user}:{pwd}@" if password is not None else f"{user}@"


def normalize_rtsp_url(url):
    raw = (url or "").strip()
    if not raw or "://" not in raw:
        return raw
    parsed = urlsplit(raw)
    if "@" not in parsed.netloc:
        return raw
    auth, host = parsed.netloc.rsplit("@", 1)
    if ":" in auth:
        username, password = auth.split(":", 1)
    else:
        username, password = auth, ""
    # unquote before re-encoding to prevent double-encoding (e.g. %40 → %2540)
    safe_auth = build_auth(unquote(username), unquote(password))[:-1]
    return urlunsplit((parsed.scheme, f"{safe_auth}@{host}", parsed.path, parsed.query, parsed.fragment))

def get_stream_urls(ip, brand, username, password, channel=1):
    brand = (brand or "").lower()
    cred = build_auth(username, password)

    if brand == "hikvision":
        return {
            "mjpeg": f"http://{cred}{ip}/ISAPI/Streaming/channels/{channel}01/httppreview",
            "snapshot": f"http://{cred}{ip}/ISAPI/Streaming/channels/{channel}01/picture",
            "rtsp": f"rtsp://{cred}{ip}:554/Streaming/Channels/{channel}01",
        }
    elif brand == "dahua":
        return {
            "mjpeg": f"http://{cred}{ip}/cgi-bin/mjpg/video.cgi?channel={channel}&subtype=1",
            "snapshot": f"http://{cred}{ip}/cgi-bin/snapshot.cgi?channel={channel}",
            "rtsp": f"rtsp://{cred}{ip}:554/cam/realmonitor?channel={channel}&subtype=0",
        }
    elif brand == "prama":
        return {
            "mjpeg": f"http://{cred}{ip}/ISAPI/Streaming/channels/{channel}01/httppreview",
            "snapshot": f"http://{cred}{ip}/onvif/snapshot?channel={channel}",
            "rtsp": f"rtsp://{cred}{ip}:554/Streaming/Channels/{channel}01",
        }
    else:
        return {
            "mjpeg": f"http://{cred}{ip}/video.mjpg",
            "snapshot": f"http://{cred}{ip}/snapshot.jpg",
            "rtsp": f"rtsp://{cred}{ip}:554/stream",
        }

def get_preview_url(ip, brand, username, password, channel=1):
    urls = get_stream_urls(ip, brand, username, password, channel)
    return urls["mjpeg"], urls["snapshot"]
