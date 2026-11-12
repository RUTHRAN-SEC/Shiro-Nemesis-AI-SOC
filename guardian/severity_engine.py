"""
guardian/severity_engine.py
===========================
Turns a rule's starting severity + extra clues into the final severity and a 0-100 risk score.
"""
from __future__ import annotations

from storage.models import SEVERITIES

_BASE_SCORE = {"LOW": 20, "MEDIUM": 45, "HIGH": 70, "CRITICAL": 90}


def final_severity(base: str, bump: int = 0) -> str:
    """bump=+1 means 'this is worse than usual' (e.g. a login SUCCEEDED after many failures)."""
    idx = SEVERITIES.index(base) + bump
    return SEVERITIES[max(0, min(len(SEVERITIES) - 1, idx))]


def risk_score(severity: str, event_count: int) -> int:
    return min(100, _BASE_SCORE[severity] + min(10, event_count // 10))
