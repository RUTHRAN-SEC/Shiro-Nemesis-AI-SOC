"""
guardian/incident_manager.py
============================
The coordinator of Guardian. For every batch of events it receives:

   normalize -> store -> run detection rules -> make alerts (no duplicates)
   -> calculate severity -> write the analyst report -> pop up a Windows notification
   -> (optionally) ask the AI for an extra briefing in the background.

It also answers "did Guardian detect attack X?" and builds the detection scorecard.
"""
from __future__ import annotations

import hashlib
import logging
import threading
from datetime import datetime, timedelta

from guardian import ai_analyst, severity_engine
from guardian.detection_engine import LOOKBACK_MINUTES, run_rules
from guardian.event_normalizer import normalize_event
from storage import database as db
from storage.models import severity_rank

log = logging.getLogger("incident")


class IncidentManager:
    def __init__(self, settings, notifier=None):
        self.settings = settings
        self.db_path = settings.guardian_db_path
        self.notifier = notifier           # a function(title, message) or None
        db.init_guardian_db(self.db_path)

    # ------------------------------------------------------------------ ingest
    def ingest(self, raw_events: list[dict]) -> dict:
        accepted, rejected = [], []
        for raw in raw_events:
            try:
                accepted.append(normalize_event(raw))
            except ValueError as exc:
                rejected.append(str(exc))

        new_alerts: list[dict] = []
        conn = db.connect(self.db_path)
        try:
            db.insert_events(conn, accepted)
            if accepted:
                newest = max(e["ts"] for e in accepted)
                since_dt = datetime.fromisoformat(newest.replace("Z", "+00:00")) - timedelta(minutes=LOOKBACK_MINUTES)
                since = since_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                recent = db.get_events_since(conn, since)
                by_id = {e["event_id"]: e for e in recent}
                for det in run_rules(recent):
                    alert = self._make_alert(det, by_id)
                    alert_id = db.insert_alert(conn, alert)
                    if alert_id is None:      # we already raised this exact alert
                        continue
                    stored = db.get_alert(conn, alert_id)
                    new_alerts.append(stored)
        finally:
            conn.close()

        for alert in new_alerts:
            self._notify(alert)
            if self.settings.guardian_use_ai and self.settings.anthropic_api_key:
                threading.Thread(target=self._enrich, args=(alert["id"],), daemon=True).start()
        return {"accepted": len(accepted), "rejected": len(rejected), "rejected_reasons": rejected[:5],
                "new_alerts": [a["alert_code"] for a in new_alerts]}

    def _make_alert(self, det, by_id: dict) -> dict:
        rule, match = det.rule, det.match
        events = [by_id[i] for i in match.event_ids if i in by_id]
        first = events[0] if events else {"ts": "", "host": "unknown", "user": "unknown"}
        severity = severity_engine.final_severity(rule.severity, match.bump)
        fingerprint = hashlib.sha1(f"{rule.id}|{match.key}|{match.event_ids[0]}".encode()).hexdigest()
        return {
            "fingerprint": fingerprint, "rule_id": rule.id, "title": rule.title, "severity": severity,
            "risk_score": severity_engine.risk_score(severity, len(events)), "category": rule.category,
            "technique_id": rule.technique_id, "technique_name": rule.technique_name, "summary": match.summary,
            "host": first["host"], "user": first["user"], "event_ids": match.event_ids,
            "first_event_ts": first["ts"],
            "analysis": ai_analyst.build_analysis(rule, match.summary, first["host"], first["user"], events, severity),
        }

    # ------------------------------------------------------------------ notify / AI
    def _notify(self, alert: dict) -> None:
        if not self.notifier:
            return
        if severity_rank(alert["severity"]) < severity_rank(self.settings.min_toast_severity):
            return
        try:
            self.notifier(f"[{alert['severity']}] {alert['title']}",
                          f"{alert['alert_code']} - {alert['host']} / {alert['user']}")
        except Exception:
            log.exception("Notification failed (alert is still saved)")

    def _enrich(self, alert_id: int) -> None:
        """Background job: ask the LLM for an extra briefing."""
        from guardian.rules import RULES_BY_ID
        conn = db.connect(self.db_path)
        try:
            alert = db.get_alert(conn, alert_id)
            if not alert:
                return
            events = db.get_events_by_ids(conn, alert["event_ids"])
            text = ai_analyst.ask_llm_briefing(self.settings, RULES_BY_ID[alert["rule_id"]], alert["summary"], events)
            if text:
                db.update_alert_briefing(conn, alert_id, text)
        except Exception:
            log.exception("AI enrichment failed")
        finally:
            conn.close()

    # ------------------------------------------------------------------ scoring
    def attack_result(self, attack_id: str) -> dict | None:
        """Did Guardian raise an alert that contains evidence from this attack?"""
        conn = db.connect(self.db_path)
        try:
            gt = db.get_ground_truth(conn, attack_id)
            if gt is None:
                return None
            attack_events = set(gt["event_ids"])
            linked = [a for a in db.list_alerts(conn, 1000) if attack_events & set(a["event_ids"])]
            return {"attack_id": attack_id, "detected": bool(linked),
                    "alerts": [a["alert_code"] for a in linked]}
        finally:
            conn.close()

    def performance(self) -> dict:
        conn = db.connect(self.db_path)
        try:
            truths = db.list_ground_truth(conn, 1000)
            alerts = db.list_alerts(conn, 5000)
        finally:
            conn.close()
        owner: dict[str, dict] = {}
        for t in truths:
            for eid in t["event_ids"]:
                owner[eid] = t
        attacks = [t for t in truths if t["is_attack"]]
        detected_ids = set()
        tp = fp = 0
        for a in alerts:
            linked = next((owner[e] for e in a["event_ids"] if e in owner), None)
            if linked and linked["is_attack"]:
                tp += 1
                detected_ids.add(linked["attack_id"])
            else:
                fp += 1                                  # decoy, or no known attack behind it
        by_cat: dict[str, dict] = {}
        for t in attacks:
            c = by_cat.setdefault(t["category"], {"total": 0, "detected": 0})
            c["total"] += 1
            c["detected"] += 1 if t["attack_id"] in detected_ids else 0
        n = len(attacks)
        return {"attacks_total": n, "attacks_detected": len(detected_ids), "attacks_missed": n - len(detected_ids),
                "detection_rate": round(len(detected_ids) / n * 100) if n else None,
                "alerts_true_positive": tp, "alerts_false_positive": fp, "by_category": by_cat}
