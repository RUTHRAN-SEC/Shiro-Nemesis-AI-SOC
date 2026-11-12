"""
storage/models.py
=================
Small shared constants and helpers used by both laptops.
"""
from __future__ import annotations

import json
import sqlite3

# Severity levels, lowest to highest.
SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# What a SOC analyst can mark an alert as.
ALERT_STATUSES = ["open", "investigating", "closed_true_positive", "closed_false_positive"]


def severity_rank(name: str) -> int:
    """LOW=0 ... CRITICAL=3. Unknown names count as LOW."""
    try:
        return SEVERITIES.index(name.upper())
    except ValueError:
        return 0


def row_to_dict(row: sqlite3.Row | None, json_columns: tuple[str, ...] = ()) -> dict | None:
    """Turn a database row into a normal dict, decoding JSON text columns."""
    if row is None:
        return None
    data = dict(row)
    for col in json_columns:
        if col in data and isinstance(data[col], str):
            try:
                data[col] = json.loads(data[col])
            except json.JSONDecodeError:
                pass
    return data
