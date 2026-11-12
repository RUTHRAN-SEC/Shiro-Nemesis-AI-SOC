"""
guardian/detection_engine.py
============================
Runs every rule in guardian/rules.py over a list of recent events and returns the detections.

One broken rule must never stop the others, so every rule runs inside its own try/except.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from guardian.rules import RULES, Match, Rule

log = logging.getLogger("detection")

# Rules look at events from the last 20 minutes (relative to the newest event received).
LOOKBACK_MINUTES = 20


@dataclass
class Detection:
    rule: Rule
    match: Match


def run_rules(events: list[dict]) -> list[Detection]:
    events = sorted(events, key=lambda e: e["ts"])
    detections: list[Detection] = []
    for rule in RULES:
        try:
            for match in rule.check(events):
                detections.append(Detection(rule, match))
        except Exception:
            log.exception("Rule %s crashed - skipping it", rule.id)
    return detections
