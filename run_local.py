"""
run_local.py — Start the local CamMonitor service with scheduler enabled.
"""

import logging
import multiprocessing
import os

import app
import db
import monitor

try:
    from waitress import serve as waitress_serve
except Exception:  # pragma: no cover - fallback if gunicorn is unavailable
    waitress_serve = None


log = logging.getLogger(__name__)


def main():
    strict_startup = os.environ.get("CAMMONITOR_STRICT_STARTUP", "").strip().lower() in {"1", "true", "yes"}
    app.validate_runtime_settings(strict=strict_startup)
    db.init_db()
    monitor.start_scheduler()
    log.info("Starting CamMonitor local service on http://%s:%s", app.WEB_HOST, app.WEB_PORT)
    try:
        if waitress_serve is None:
            if strict_startup:
                raise RuntimeError("waitress is required when CAMMONITOR_STRICT_STARTUP=1")
            app.app.run(host=app.WEB_HOST, port=app.WEB_PORT, debug=False, use_reloader=False)
            return

        threads = max(4, min(16, (multiprocessing.cpu_count() or 2) * 2))
        waitress_serve(
            app.app,
            host=app.WEB_HOST,
            port=app.WEB_PORT,
            threads=threads,
            channel_timeout=60,
            cleanup_interval=30,
            ident="CamMonitor",
        )
    finally:
        monitor.stop_scheduler()


if __name__ == "__main__":
    main()
