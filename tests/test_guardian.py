"""
Tests for the defender side: every scenario is fed through Guardian and we check the result.

EXPECTATION TABLE (kept only in the tests - Guardian never sees it):
  * 26 attacks have a rule -> must be detected
  * 3 attacks have NO rule on purpose -> must be missed  (qr phishing, c2 beaconing, access key)
  * 3 decoys trigger a rule -> false positives (admin script, vuln scan, backup)
  * 1 decoy must stay silent (a few typo logins)
"""
import random
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from api.server import create_app
from attack_library import get_scenarios
from attack_library.base import ScenarioContext
from guardian.incident_manager import IncidentManager
from shiro.activity import normal_activity
from shiro.employee import load_employee
from tests.helpers import generate, make_settings

MISSED_ON_PURPOSE = {"qr_code_phishing", "c2_beaconing", "iam_access_key_created"}
FALSE_POSITIVE_DECOYS = {"benign_admin_script", "benign_vuln_scan", "benign_backup_transfer"}
SILENT_DECOYS = {"benign_typo_logins"}


@pytest.mark.parametrize("scenario_id", sorted(get_scenarios()))
@pytest.mark.parametrize("difficulty", [1, 2, 3])
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_detection_matrix(tmp_path, scenario_id, difficulty, seed):
    mgr = IncidentManager(make_settings(tmp_path))
    result = mgr.ingest(generate(scenario_id, difficulty, seed))
    assert result["rejected"] == 0
    if scenario_id in MISSED_ON_PURPOSE or scenario_id in SILENT_DECOYS:
        assert result["new_alerts"] == [], f"{scenario_id} should NOT raise an alert"
    else:
        assert result["new_alerts"], f"{scenario_id} (difficulty {difficulty}, seed {seed}) was not detected"


def test_normal_activity_never_alerts(tmp_path):
    mgr = IncidentManager(make_settings(tmp_path))
    emp = load_employee()
    for seed in range(30):
        ctx = ScenarioContext(emp, random.Random(seed), datetime.now(timezone.utc), 1)
        assert mgr.ingest(normal_activity(ctx))["new_alerts"] == []


def test_attack_hidden_inside_normal_noise_is_still_found(tmp_path):
    mgr = IncidentManager(make_settings(tmp_path))
    emp = load_employee()
    ctx = ScenarioContext(emp, random.Random(5), datetime.now(timezone.utc), 1)
    mgr.ingest(normal_activity(ctx))
    assert mgr.ingest(generate("password_spray"))["new_alerts"]


def test_duplicate_events_do_not_duplicate_alerts(tmp_path):
    mgr = IncidentManager(make_settings(tmp_path))
    events = generate("ransomware_behavior")
    first = mgr.ingest(events)
    second = mgr.ingest(events)               # same events sent twice (e.g. outbox retry)
    assert len(first["new_alerts"]) >= 1 and second["new_alerts"] == []


def test_bad_events_are_rejected_not_crashing(tmp_path):
    mgr = IncidentManager(make_settings(tmp_path))
    out = mgr.ingest([{"nonsense": 1}, {"source": "auth", "action": "x", "timestamp": "not-a-date"}, "text"])
    assert out["accepted"] == 0 and out["rejected"] == 3


def test_severity_goes_up_when_login_succeeds_after_brute_force(tmp_path):
    from storage import database as db
    mgr = IncidentManager(make_settings(tmp_path))
    ev = generate("brute_force_login", 1, 0)
    ev.append(ctx_success := {**ev[0], "event_id": "success-1", "action": "login_success",
                              "timestamp": (datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                              "details": {"src_ip": ev[0]["details"]["src_ip"], "method": "rdp", "country": "RO"}})
    mgr.ingest(ev)
    conn = db.connect(mgr.db_path)
    alert = [a for a in db.list_alerts(conn) if a["rule_id"] == "ID-001"][0]
    assert alert["severity"] == "CRITICAL" and "SUCCESSFUL" in alert["summary"]


# ----------------------------------------------------------------------------- API
@pytest.fixture
def api(tmp_path):
    settings = make_settings(tmp_path)
    sent = []
    app = create_app(settings, notifier=lambda t, m: sent.append((t, m)))
    return TestClient(app), {"Authorization": f"Bearer {settings.token}"}, sent


def test_api_requires_token(api):
    client, headers, _ = api
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/events", json={"events": []}).status_code == 401
    assert client.post("/api/events", json={"events": []}, headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/events", json={"events": []}, headers=headers).status_code == 200


def test_ping_shows_a_notification(api):
    client, headers, sent = api
    assert client.post("/api/ping", json={"message": "hello from ubuntu"}, headers=headers).json()["reply"] == "pong"
    assert sent and "hello from ubuntu" in sent[0][1]


def test_full_flow_events_truth_result_dashboard(api):
    client, headers, sent = api
    events = generate("dns_tunneling")
    assert client.post("/api/events", json={"events": events}, headers=headers).json()["new_alerts"]
    truth = {"attack_id": "ATK-1", "scenario_id": "dns_tunneling", "name": "DNS tunneling", "category": "network",
             "technique_id": "T1071.004", "difficulty": 1, "is_attack": True, "started_at": events[0]["timestamp"],
             "event_ids": [e["event_id"] for e in events]}
    assert client.post("/api/ground-truth", json={"attack": truth}, headers=headers).status_code == 200
    assert client.get("/api/attacks/ATK-1/result", headers=headers).json()["detected"] is True
    assert client.get("/api/attacks/NOPE/result", headers=headers).status_code == 404
    assert sent, "a toast notification should have been requested"

    overview = client.get("/api/overview").json()
    assert overview["total_alerts"] >= 1 and overview["by_severity"]["HIGH"] >= 1
    alert = client.get("/api/alerts").json()[0]
    detail = client.get(f"/api/alerts/{alert['id']}").json()
    assert detail["events"] and detail["analysis"]["investigate"]
    assert client.post(f"/api/alerts/{alert['id']}/status", json={"status": "closed_true_positive"}).status_code == 200
    assert client.post(f"/api/alerts/{alert['id']}/status", json={"status": "bogus"}).status_code == 422
    perf = client.get("/api/performance").json()
    assert perf["attacks_detected"] == 1 and perf["detection_rate"] == 100
    log = client.get("/api/attack-log").json()
    assert log[0]["scenario_id"] == "dns_tunneling" and log[0]["detected"] is True
    assert client.get("/").status_code == 200


def test_performance_counts_missed_attacks_and_false_positives(api):
    client, headers, _ = api
    for sid, is_attack in (("qr_code_phishing", True), ("benign_backup_transfer", False)):
        events = generate(sid)
        client.post("/api/events", json={"events": events}, headers=headers)
        client.post("/api/ground-truth", headers=headers, json={"attack": {
            "attack_id": f"ATK-{sid}", "scenario_id": sid, "name": sid, "category": "x", "is_attack": is_attack,
            "started_at": events[0]["timestamp"], "event_ids": [e["event_id"] for e in events]}})
    perf = client.get("/api/performance").json()
    assert perf["attacks_missed"] == 1 and perf["alerts_false_positive"] == 1


def test_dashboard_is_local_only(tmp_path):
    from fastapi import Request
    from api.authentication import make_local_only_checker
    from fastapi import HTTPException
    checker = make_local_only_checker(False)

    class Req:                    # a pretend request coming from another device on the Wi-Fi
        client = type("c", (), {"host": "192.168.1.9"})()

    with pytest.raises(HTTPException) as err:
        checker(Req())
    assert err.value.status_code == 403
    make_local_only_checker(True)(Req())      # allowed when SN_DASHBOARD_ALLOW_LAN=true
