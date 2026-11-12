"""
shiro/event_generator.py
========================
Builds the "evidence" - log events - that Shiro's fake environment produces.

Every event has the same shape, whatever the source:

    {
      "event_id":  "uuid",
      "timestamp": "2026-11-11T09:00:00.000000Z",
      "source":    "auth | email | endpoint | network | dns | web | cloud",
      "host":      "SHIRO-PC-001",
      "user":      "shiro.user",
      "action":    "login_failed",
      "details":   { ... anything extra ... },
      "simulated": true
    }

Notice there is NO field saying "this is an attack". Guardian must work it out.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone


def canonical_ts(dt: datetime) -> str:
    """One fixed timestamp format everywhere (UTC), so text sorting = time sorting."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_event(source: str, action: str, host: str, user: str, details: dict, when: datetime) -> dict:
    return {
        "event_id": str(uuid.uuid4()),
        "timestamp": canonical_ts(when),
        "source": source,
        "host": host,
        "user": user,
        "action": action,
        "details": details,
        "simulated": True,
    }
