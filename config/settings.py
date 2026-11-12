"""
config/settings.py
==================
Loads all project settings from environment variables.

Simple idea:
  * You copy `.env.example` to `.env` and edit it.
  * This file reads `.env` and gives every other file one `Settings` object.
  * Real environment variables always win over `.env` (handy for systemd/CI).

No third-party package is needed, so it works the same on Ubuntu and Windows.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

# The folder that contains README.md, config/, nemesis/, guardian/ ...
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def load_env_file(path: Path | None = None) -> None:
    """Read KEY=VALUE lines from .env and put them in os.environ (if not set yet)."""
    path = path or (PROJECT_ROOT / ".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _get_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _get_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "") or default)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    # --- shared secret between the two laptops ---
    token: str
    # --- Guardian (Windows) address, used by Nemesis (Ubuntu) ---
    guardian_host: str
    guardian_port: int
    # --- Guardian web server ---
    bind_host: str
    dashboard_allow_lan: bool
    min_toast_severity: str
    guardian_use_ai: bool
    # --- Nemesis (Ubuntu) ---
    interval_seconds: int
    nemesis_use_ai: bool
    include_decoys: bool
    # --- optional AI ---
    anthropic_api_key: str
    ai_model: str
    # --- storage ---
    data_dir: Path

    @property
    def guardian_url(self) -> str:
        return f"http://{self.guardian_host}:{self.guardian_port}"

    @property
    def guardian_db_path(self) -> Path:
        return self.data_dir / "guardian.db"

    @property
    def nemesis_db_path(self) -> Path:
        return self.data_dir / "nemesis_memory.db"

    @property
    def outbox_dir(self) -> Path:
        return self.data_dir / "outbox"

    @property
    def mailbox_dir(self) -> Path:
        return self.data_dir / "shiro_mailbox"

    @property
    def files_dir(self) -> Path:
        return self.data_dir / "shiro_files"


def get_settings() -> Settings:
    load_env_file()
    env = os.environ.get
    return Settings(
        token=env("SN_TOKEN", ""),
        guardian_host=env("SN_GUARDIAN_HOST", "127.0.0.1"),
        guardian_port=_get_int("SN_GUARDIAN_PORT", 8000),
        bind_host=env("SN_BIND_HOST", "0.0.0.0"),
        dashboard_allow_lan=_get_bool("SN_DASHBOARD_ALLOW_LAN", False),
        min_toast_severity=(env("SN_MIN_TOAST_SEVERITY", "medium") or "medium").upper(),
        guardian_use_ai=_get_bool("SN_GUARDIAN_USE_AI", True),
        interval_seconds=_get_int("SN_INTERVAL_SECONDS", 1200),
        nemesis_use_ai=_get_bool("SN_NEMESIS_USE_AI", True),
        include_decoys=_get_bool("SN_INCLUDE_DECOYS", True),
        anthropic_api_key=env("ANTHROPIC_API_KEY", ""),
        ai_model=env("SN_AI_MODEL", "claude-haiku-5-5") or "claude-haiku-5-5",
        data_dir=Path(env("SN_DATA_DIR") or (PROJECT_ROOT / "data")),
    )


def load_safety_policy() -> dict:
    """Read config/safety_policy.json (the rules the Safety Validator enforces)."""
    return json.loads((PROJECT_ROOT / "config" / "safety_policy.json").read_text(encoding="utf-8"))


def load_profile() -> dict:
    """Read config/shiro_profile.json (Shiro, coworkers, fake servers)."""
    return json.loads((PROJECT_ROOT / "config" / "shiro_profile.json").read_text(encoding="utf-8"))
