"""
api/server.py
=============
Guardian's web server (FastAPI). It has two kinds of doors:

  DOOR 1 - for Nemesis (needs the secret token):
      POST /api/events                   receive log events
      POST /api/ground-truth             receive the attack "answer key"
      GET  /api/attacks/{id}/result      "did you catch this one?"
      POST /api/ping                     test message -> pops up a notification
  DOOR 2 - for YOU, the analyst (only from the ASUS laptop itself):
      GET  /                             the dashboard web page
      GET  /api/overview, /api/alerts, /api/alerts/{id}, /api/activity,
           /api/performance, /api/attack-log
      POST /api/alerts/{id}/status       mark an alert open / investigating / closed
  And one public door:  GET /api/health  (just says "ok")
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from api.authentication import make_local_only_checker, make_token_checker
from config.settings import PROJECT_ROOT, Settings, get_settings
from guardian.incident_manager import IncidentManager
from storage import database as db
from storage.models import ALERT_STATUSES, SEVERITIES

MAX_BATCH = 1000
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"


class EventBatch(BaseModel):
    events: list[dict]


class GroundTruthIn(BaseModel):
    attack: dict


class PingIn(BaseModel):
    message: str = "hello"


class StatusIn(BaseModel):
    status: str


def create_app(settings: Settings | None = None, notifier=None) -> FastAPI:
    settings = settings or get_settings()
    manager = IncidentManager(settings, notifier)
    app = FastAPI(title="Shiro Guardian SOC", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.manager = manager

    need_token = Depends(make_token_checker(settings.token))
    local_only = Depends(make_local_only_checker(settings.dashboard_allow_lan))

    # ---------------------------------------------------------------- public
    @app.get("/api/health")
    def health():
        return {"status": "ok"}

    # ---------------------------------------------------------------- door 1: Nemesis
    @app.post("/api/ping", dependencies=[need_token])
    def ping(body: PingIn):
        if notifier:
            notifier("Nemesis connected", body.message[:200])
        return {"ok": True, "reply": "pong", "message": body.message[:200]}

    @app.post("/api/events", dependencies=[need_token])
    def receive_events(batch: EventBatch):
        if len(batch.events) > MAX_BATCH:
            raise HTTPException(413, f"Too many events (max {MAX_BATCH} per request)")
        return manager.ingest(batch.events)

    @app.post("/api/ground-truth", dependencies=[need_token])
    def receive_ground_truth(body: GroundTruthIn):
        gt = body.attack
        missing = [k for k in ("attack_id", "scenario_id", "name", "category", "started_at", "event_ids")
                   if k not in gt]
        if missing:
            raise HTTPException(422, f"Missing fields: {missing}")
        conn = db.connect(settings.guardian_db_path)
        try:
            db.insert_ground_truth(conn, gt)
        finally:
            conn.close()
        return {"ok": True}

    @app.get("/api/attacks/{attack_id}/result", dependencies=[need_token])
    def attack_result(attack_id: str):
        result = manager.attack_result(attack_id)
        if result is None:
            raise HTTPException(404, "Unknown attack id")
        return result

    # ---------------------------------------------------------------- door 2: dashboard
    @app.get("/", dependencies=[local_only])
    def index():
        return FileResponse(DASHBOARD_DIR / "index.html")

    @app.get("/api/overview", dependencies=[local_only])
    def overview():
        conn = db.connect(settings.guardian_db_path)
        try:
            alerts = db.list_alerts(conn, 5000)
            total_events = db.count_events(conn)
        finally:
            conn.close()
        sev = Counter(a["severity"] for a in alerts)
        status = Counter(a["status"] for a in alerts)
        cats = Counter(a["category"] for a in alerts)
        techniques = Counter(f"{a['technique_id']} {a['technique_name']}" for a in alerts)
        timeline = Counter(a["first_event_ts"][:13] for a in alerts)   # per hour
        return {
            "total_alerts": len(alerts), "total_events": total_events,
            "open_alerts": status.get("open", 0) + status.get("investigating", 0),
            "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
            "by_status": dict(status), "by_category": dict(cats),
            "by_technique": dict(techniques.most_common(10)),
            "timeline": dict(sorted(timeline.items())[-24:]),
        }

    @app.get("/api/alerts", dependencies=[local_only])
    def alerts(limit: int = 100, status: str | None = None):
        conn = db.connect(settings.guardian_db_path)
        try:
            return db.list_alerts(conn, min(limit, 500), status)
        finally:
            conn.close()

    @app.get("/api/alerts/{alert_id}", dependencies=[local_only])
    def alert_detail(alert_id: int):
        conn = db.connect(settings.guardian_db_path)
        try:
            alert = db.get_alert(conn, alert_id)
            if not alert:
                raise HTTPException(404, "No such alert")
            alert["events"] = db.get_events_by_ids(conn, alert["event_ids"])
            return alert
        finally:
            conn.close()

    @app.post("/api/alerts/{alert_id}/status", dependencies=[local_only])
    def set_status(alert_id: int, body: StatusIn):
        if body.status not in ALERT_STATUSES:
            raise HTTPException(422, f"status must be one of {ALERT_STATUSES}")
        conn = db.connect(settings.guardian_db_path)
        try:
            if not db.update_alert_status(conn, alert_id, body.status):
                raise HTTPException(404, "No such alert")
        finally:
            conn.close()
        return {"ok": True}

    @app.get("/api/activity", dependencies=[local_only])
    def activity(limit: int = 40):
        conn = db.connect(settings.guardian_db_path)
        try:
            return db.get_recent_events(conn, min(limit, 200))
        finally:
            conn.close()

    @app.get("/api/performance", dependencies=[local_only])
    def performance():
        return manager.performance()

    @app.get("/api/attack-log", dependencies=[local_only])
    def attack_log():
        """The ANSWER KEY. The dashboard only asks for it when you press 'Reveal answers'."""
        conn = db.connect(settings.guardian_db_path)
        try:
            truths = db.list_ground_truth(conn, 200)
        finally:
            conn.close()
        for t in truths:
            res = manager.attack_result(t["attack_id"])
            t["detected"] = res["detected"] if res else None
            t["alerts"] = res["alerts"] if res else []
            t["event_count"] = len(t.pop("event_ids"))
        return truths

    app.mount("/static", StaticFiles(directory=str(Path(DASHBOARD_DIR))), name="static")
    return app
