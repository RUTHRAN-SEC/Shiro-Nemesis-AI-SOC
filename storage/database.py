"""
storage/database.py
===================
All SQLite code lives here.

Two separate databases (one per laptop):
  * guardian.db        (Windows)  -> events, alerts, ground_truth
  * nemesis_memory.db  (Ubuntu)   -> attacks Nemesis has launched (its "memory")

SQLite is a single file, needs no server, and is perfect for a small lab.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from storage.models import row_to_dict

# SQLite allows only one writer at a time; this lock keeps our threads polite.
_write_lock = threading.Lock()


def connect(path: str | Path) -> sqlite3.Connection:
    """Open (and create if needed) a database file."""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# GUARDIAN DATABASE (Windows)
# ---------------------------------------------------------------------------
GUARDIAN_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,          -- when the event happened (UTC, ISO format)
    source      TEXT NOT NULL,          -- auth, email, endpoint, network, dns, web, cloud
    host        TEXT NOT NULL,
    user        TEXT NOT NULL,
    action      TEXT NOT NULL,          -- login_failed, process_start, ...
    details     TEXT NOT NULL,          -- JSON
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_code      TEXT,
    fingerprint     TEXT UNIQUE NOT NULL,   -- stops duplicate alerts
    rule_id         TEXT NOT NULL,
    title           TEXT NOT NULL,
    severity        TEXT NOT NULL,
    risk_score      INTEGER NOT NULL,
    category        TEXT NOT NULL,
    technique_id    TEXT,
    technique_name  TEXT,
    summary         TEXT NOT NULL,
    host            TEXT,
    user            TEXT,
    event_ids       TEXT NOT NULL,          -- JSON list
    first_event_ts  TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',
    analysis        TEXT NOT NULL,          -- JSON (the AI SOC analyst explanation)
    ai_briefing     TEXT                    -- optional text from the LLM
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at);

CREATE TABLE IF NOT EXISTS ground_truth (
    attack_id     TEXT PRIMARY KEY,
    scenario_id   TEXT NOT NULL,
    name          TEXT NOT NULL,
    category      TEXT NOT NULL,
    technique_id  TEXT,
    technique_name TEXT,
    difficulty    INTEGER,
    is_attack     INTEGER NOT NULL,         -- 1 = real simulated attack, 0 = harmless decoy
    planner       TEXT,
    reasoning     TEXT,
    started_at    TEXT NOT NULL,
    event_ids     TEXT NOT NULL,            -- JSON list
    received_at   TEXT NOT NULL
);
"""


def init_guardian_db(path: str | Path) -> None:
    conn = connect(path)
    try:
        conn.executescript(GUARDIAN_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def insert_events(conn: sqlite3.Connection, events: list[dict]) -> None:
    rows = [
        (e["event_id"], e["ts"], e["source"], e["host"], e["user"], e["action"],
         json.dumps(e["details"]), _now())
        for e in events
    ]
    with _write_lock, conn:
        conn.executemany(
            "INSERT OR IGNORE INTO events(event_id, ts, source, host, user, action, details, received_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            rows,
        )


def _event_row(row: sqlite3.Row) -> dict:
    return row_to_dict(row, ("details",))  # type: ignore[return-value]


def get_events_since(conn: sqlite3.Connection, since_ts: str) -> list[dict]:
    rows = conn.execute("SELECT * FROM events WHERE ts >= ? ORDER BY ts", (since_ts,)).fetchall()
    return [_event_row(r) for r in rows]


def get_events_by_ids(conn: sqlite3.Connection, ids: list[str]) -> list[dict]:
    if not ids:
        return []
    marks = ",".join("?" for _ in ids)
    rows = conn.execute(f"SELECT * FROM events WHERE event_id IN ({marks}) ORDER BY ts", ids).fetchall()
    return [_event_row(r) for r in rows]


def get_recent_events(conn: sqlite3.Connection, limit: int = 40, only_normal: bool = False) -> list[dict]:
    rows = conn.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
    return [_event_row(r) for r in rows]


def count_events(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]


_ALERT_JSON = ("event_ids", "analysis")


def insert_alert(conn: sqlite3.Connection, alert: dict) -> int | None:
    """Insert an alert. Returns its id, or None if an identical alert already exists."""
    with _write_lock, conn:
        try:
            cur = conn.execute(
                """INSERT INTO alerts(fingerprint, rule_id, title, severity, risk_score, category,
                       technique_id, technique_name, summary, host, user, event_ids, first_event_ts,
                       created_at, analysis)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (alert["fingerprint"], alert["rule_id"], alert["title"], alert["severity"],
                 alert["risk_score"], alert["category"], alert["technique_id"], alert["technique_name"],
                 alert["summary"], alert["host"], alert["user"], json.dumps(alert["event_ids"]),
                 alert["first_event_ts"], _now(), json.dumps(alert["analysis"])),
            )
        except sqlite3.IntegrityError:
            return None
        alert_id = cur.lastrowid
        year = datetime.now(timezone.utc).year
        conn.execute("UPDATE alerts SET alert_code=? WHERE id=?", (f"ALERT-{year}-{alert_id:04d}", alert_id))
        return alert_id


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM alerts WHERE id=?", (alert_id,)).fetchone()
    return row_to_dict(row, _ALERT_JSON)


def list_alerts(conn: sqlite3.Connection, limit: int = 100, status: str | None = None) -> list[dict]:
    if status:
        rows = conn.execute("SELECT * FROM alerts WHERE status=? ORDER BY id DESC LIMIT ?", (status, limit)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [row_to_dict(r, _ALERT_JSON) for r in rows]  # type: ignore[misc]


def update_alert_status(conn: sqlite3.Connection, alert_id: int, status: str) -> bool:
    with _write_lock, conn:
        cur = conn.execute("UPDATE alerts SET status=? WHERE id=?", (status, alert_id))
        return cur.rowcount > 0


def update_alert_briefing(conn: sqlite3.Connection, alert_id: int, text: str) -> None:
    with _write_lock, conn:
        conn.execute("UPDATE alerts SET ai_briefing=? WHERE id=?", (text, alert_id))


def insert_ground_truth(conn: sqlite3.Connection, gt: dict) -> None:
    with _write_lock, conn:
        conn.execute(
            """INSERT OR REPLACE INTO ground_truth(attack_id, scenario_id, name, category, technique_id,
                   technique_name, difficulty, is_attack, planner, reasoning, started_at, event_ids, received_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (gt["attack_id"], gt["scenario_id"], gt["name"], gt["category"], gt.get("technique_id"),
             gt.get("technique_name"), gt.get("difficulty"), 1 if gt.get("is_attack", True) else 0,
             gt.get("planner"), gt.get("reasoning"), gt["started_at"], json.dumps(gt["event_ids"]), _now()),
        )


def get_ground_truth(conn: sqlite3.Connection, attack_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM ground_truth WHERE attack_id=?", (attack_id,)).fetchone()
    return row_to_dict(row, ("event_ids",))


def list_ground_truth(conn: sqlite3.Connection, limit: int = 200) -> list[dict]:
    rows = conn.execute("SELECT * FROM ground_truth ORDER BY started_at DESC LIMIT ?", (limit,)).fetchall()
    return [row_to_dict(r, ("event_ids",)) for r in rows]  # type: ignore[misc]


# ---------------------------------------------------------------------------
# NEMESIS DATABASE (Ubuntu) - the attacker's memory
# ---------------------------------------------------------------------------
NEMESIS_SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    attack_id     TEXT PRIMARY KEY,
    ts            TEXT NOT NULL,
    scenario_id   TEXT NOT NULL,
    name          TEXT NOT NULL,
    category      TEXT NOT NULL,
    technique_id  TEXT,
    difficulty    INTEGER NOT NULL,
    is_attack     INTEGER NOT NULL,
    event_count   INTEGER NOT NULL,
    delivered     INTEGER NOT NULL DEFAULT 0,   -- 1 if Guardian received it
    detected      INTEGER,                      -- NULL = unknown, 1 = detected, 0 = missed
    planner       TEXT,                         -- 'ai' or 'rules'
    reasoning     TEXT
);
CREATE INDEX IF NOT EXISTS idx_attacks_ts ON attacks(ts);
"""


def init_nemesis_db(path: str | Path) -> None:
    conn = connect(path)
    try:
        conn.executescript(NEMESIS_SCHEMA)
        conn.commit()
    finally:
        conn.close()
