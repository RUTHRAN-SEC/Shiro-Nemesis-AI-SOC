"""
nemesis/attack_memory.py
========================
Nemesis' memory (a SQLite file). It remembers every attack it launched and whether
Guardian caught it. The planner reads this so Nemesis does NOT repeat itself and
learns which categories Guardian is weak against.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from storage.database import connect, init_nemesis_db


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class AttackMemory:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        init_nemesis_db(self.db_path)

    def record_attack(self, *, attack_id: str, scenario_id: str, name: str, category: str, technique_id: str,
                      difficulty: int, is_attack: bool, event_count: int, delivered: bool,
                      planner: str, reasoning: str) -> None:
        conn = connect(self.db_path)
        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO attacks(attack_id, ts, scenario_id, name, category, technique_id, "
                    "difficulty, is_attack, event_count, delivered, planner, reasoning) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (attack_id, _iso(datetime.now(timezone.utc)), scenario_id, name, category, technique_id,
                     difficulty, 1 if is_attack else 0, event_count, 1 if delivered else 0, planner, reasoning))
        finally:
            conn.close()

    def set_detected(self, attack_id: str, detected: bool) -> None:
        conn = connect(self.db_path)
        try:
            with conn:
                conn.execute("UPDATE attacks SET detected=? WHERE attack_id=?", (1 if detected else 0, attack_id))
        finally:
            conn.close()

    def recent(self, n: int = 10) -> list[dict]:
        conn = connect(self.db_path)
        try:
            rows = conn.execute("SELECT * FROM attacks ORDER BY ts DESC, rowid DESC LIMIT ?", (n,)).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def count_since(self, minutes: int) -> int:
        since = _iso(datetime.now(timezone.utc) - timedelta(minutes=minutes))
        conn = connect(self.db_path)
        try:
            return conn.execute("SELECT COUNT(*) FROM attacks WHERE ts >= ?", (since,)).fetchone()[0]
        finally:
            conn.close()

    def total(self) -> int:
        conn = connect(self.db_path)
        try:
            return conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        finally:
            conn.close()

    def category_stats(self) -> dict[str, dict]:
        """{category: {"total": n, "detected": n, "missed": n}} for real attacks only."""
        conn = connect(self.db_path)
        try:
            rows = conn.execute(
                "SELECT category, COUNT(*) AS total, "
                "SUM(CASE WHEN detected=1 THEN 1 ELSE 0 END) AS detected, "
                "SUM(CASE WHEN detected=0 THEN 1 ELSE 0 END) AS missed "
                "FROM attacks WHERE is_attack=1 GROUP BY category").fetchall()
            return {r["category"]: {"total": r["total"], "detected": r["detected"] or 0, "missed": r["missed"] or 0}
                    for r in rows}
        finally:
            conn.close()

    def scenario_counts(self) -> dict[str, int]:
        conn = connect(self.db_path)
        try:
            rows = conn.execute("SELECT scenario_id, COUNT(*) AS n FROM attacks GROUP BY scenario_id").fetchall()
            return {r["scenario_id"]: r["n"] for r in rows}
        finally:
            conn.close()

    def detection_rate(self, last_n: int = 10) -> float | None:
        """Share of the last n real attacks that Guardian detected (None if unknown)."""
        conn = connect(self.db_path)
        try:
            rows = conn.execute("SELECT detected FROM attacks WHERE is_attack=1 AND detected IS NOT NULL "
                                "ORDER BY ts DESC LIMIT ?", (last_n,)).fetchall()
        finally:
            conn.close()
        if not rows:
            return None
        return sum(r["detected"] for r in rows) / len(rows)

    def weaknesses(self) -> list[str]:
        """Categories where Guardian missed at least half of the attacks (min 2 tries)."""
        return [c for c, s in self.category_stats().items()
                if s["total"] >= 2 and s["missed"] / s["total"] >= 0.5]
