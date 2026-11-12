"""
guardian/main.py
================
Starts Guardian on the ASUS Windows laptop.

    python -m guardian.main

Then open  http://127.0.0.1:8000  in your browser to see the SOC dashboard.
"""
from __future__ import annotations

import logging
import sys

import uvicorn

from api.server import create_app
from config.settings import get_settings
from notifications.windows_toast import notify


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    settings = get_settings()
    if len(settings.token) < 16:
        print("SN_TOKEN is missing or too short.\n"
              "  1) run:  python scripts/generate_token.py\n"
              "  2) paste the result into .env as SN_TOKEN=...\n"
              "  3) use the SAME value in .env on the Ubuntu laptop.")
        return 1
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    app = create_app(settings, notifier=notify)
    print("=" * 60)
    print(" Guardian SOC is starting")
    print(f"  Dashboard (ASUS only):  http://127.0.0.1:{settings.guardian_port}")
    print(f"  Nemesis sends to:       port {settings.guardian_port} (token protected)")
    print(f"  AI explanations:        {'ON' if settings.guardian_use_ai and settings.anthropic_api_key else 'off (built-in rules only)'}")
    print("=" * 60)
    uvicorn.run(app, host=settings.bind_host, port=settings.guardian_port, log_level="warning")
    return 0


if __name__ == "__main__":
    sys.exit(main())
