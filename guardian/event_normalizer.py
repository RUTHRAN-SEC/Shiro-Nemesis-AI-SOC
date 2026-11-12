"""
guardian/event_normalizer.py
============================
Guardian receives events from many "sources" (auth, email, firewall, web ...).
The normalizer makes them all look the same and REJECTS bad data, so the rest
of Guardian can trust what it gets.

Rules:
  * required: timestamp, source, action
  * timestamps are converted to one UTC format
  * text is cut to a sane length; details must be a small dict
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

VALID_SOURCES = {"auth", "email", "endpoint", "network", "dns", "web", "cloud"}
MAX_DETAILS_BYTES = 8000


def _parse_ts(value) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"bad timestamp '{value}'") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _clean(value, default: str, limit: int = 120) -> str:
    text = str(value).strip() if value not in (None, "") else default
    return text[:limit]


def normalize_event(raw: dict) -> dict:
    """Return a clean event dict, or raise ValueError explaining what is wrong."""
    if not isinstance(raw, dict):
        raise ValueError("event must be an object")
    source = _clean(raw.get("source"), "").lower()
    if source not in VALID_SOURCES:
        raise ValueError(f"unknown source '{source}'")
    action = _clean(raw.get("action"), "").lower()
    if not action:
        raise ValueError("missing action")
    details = raw.get("details") or {}
    if not isinstance(details, dict):
        raise ValueError("details must be an object")
    if len(json.dumps(details)) > MAX_DETAILS_BYTES:
        raise ValueError("details too large")
    ts = _parse_ts(raw.get("timestamp"))
    return {
        "event_id": _clean(raw.get("event_id"), str(uuid.uuid4()), 64),
        "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "source": source,
        "host": _clean(raw.get("host"), "unknown"),
        "user": _clean(raw.get("user"), "unknown"),
        "action": action,
        "details": details,
    }
