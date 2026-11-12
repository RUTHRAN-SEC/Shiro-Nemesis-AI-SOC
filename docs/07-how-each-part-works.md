# 07 - How each part works (code tour)

Every code file has comments written for beginners. This page is the map.

## Life of one attack

```
nemesis/scheduler.py        every 20 minutes calls run_cycle()
   │  1. client.flush_outbox()            re-send anything saved while Guardian was offline
   │  2. executor.send_background_activity()   Shiro's normal events
   │  3. scenario_selector.select()       pick scenario (AI planner first, rules as backup)
   ▼
nemesis/executor.py         run_attack()
   │  4. scenario.generate(ctx)           attack_library/... makes fake events
   │  5. safety_validator.validate_events()   ANY problem -> nothing is sent
   │  6. client.send_events()             POST /api/events        (token protected)
   │  7. client.send_ground_truth()       POST /api/ground-truth  (hidden answer key)
   │  8. memory.record_attack()           remembered in SQLite
   │  9. client.get_attack_result()       "did you catch it?" -> memory.set_detected()
   ▼
api/server.py (Windows)     receive_events()
   ▼
guardian/incident_manager.py  ingest()
   │  normalize -> store -> load last 20 min of events -> run all rules
   │  -> severity -> analyst report -> save alert (duplicates ignored)
   │  -> windows_toast.notify()  -> optional AI briefing in background
   ▼
dashboard/app.js            shows it (refreshes every 4 seconds)
```

## Nemesis (Ubuntu)

| File | Job |
|---|---|
| `nemesis/scheduler.py` | The loop. Options: `--once --list --scenario --difficulty --dry-run --no-ai --interval --no-wait`. A lock file prevents two Nemesis running at once. A crash in one cycle never kills the loop. |
| `nemesis/scenario_selector.py` | Rule-based choice. Weights: never-used +1, Guardian-missed category up to +2, daily focus x1.8, same category as last x0.4. Excludes the last half-library. 15% chance of a decoy. |
| `nemesis/ai_planner.py` | Asks Claude for `{"scenario_id","difficulty","reasoning"}`. Rejects invented ids, decoys and repeats. |
| `nemesis/attack_memory.py` | SQLite memory: stats per category, detection rate, weaknesses. |
| `nemesis/safety_validator.py` | The safety officer (see [13](13-safety-rules.md)). |
| `nemesis/executor.py` | Runs one scenario end to end. |

## Shiro and the attack library

| File | Job |
|---|---|
| `config/shiro_profile.json` | The whole fictional company. Edit names/servers here. |
| `shiro/employee.py` | Loads the profile into an `Employee` object. |
| `shiro/activity.py` | Normal day events (must never alert). |
| `shiro/event_generator.py` | The one event format. |
| `attack_library/base.py` | `Scenario`, `ScenarioContext` (random fake IP, event counts by difficulty, timing) and the `@scenario` decorator. |
| `attack_library/<category>/scenarios.py` | The recipes. |

An event looks like this:

```json
{
  "event_id": "b4c1...", "timestamp": "2026-11-11T09:20:03.114Z",
  "source": "auth", "host": "DC01", "user": "shiro.user", "action": "login_failed",
  "details": {"src_ip": "203.0.113.45", "method": "rdp", "reason": "bad_password"},
  "simulated": true
}
```

## Guardian (Windows)

| File | Job |
|---|---|
| `api/server.py` | All web endpoints. Token door for Nemesis, local-only door for the dashboard. |
| `guardian/event_normalizer.py` | Cleans and validates incoming events. |
| `guardian/rules.py` | 27 rules + analyst texts. `find_burst()` = "N events within T seconds". |
| `guardian/detection_engine.py` | Runs all rules safely. |
| `guardian/severity_engine.py` | Final severity and 0-100 risk score. |
| `guardian/ai_analyst.py` | Built-in report + optional AI briefing. |
| `guardian/incident_manager.py` | Orchestration, dedupe (fingerprint = rule + key + first event), scoring. |
| `notifications/windows_toast.py` | Pop-ups. |
| `storage/database.py` | All SQL. Tables: `events`, `alerts`, `ground_truth`. |

## The scoring logic

* An attack is **detected** if at least one alert contains an event that belongs to it.
* An alert is a **true positive** if its events belong to a real attack; otherwise it is a **false positive**
  (decoy, or unknown cause).
* Nemesis learns detection results from `GET /api/attacks/<id>/result`.

## API cheat sheet

| Endpoint | Who | Purpose |
|---|---|---|
| `GET /api/health` | anyone | "ok" |
| `POST /api/ping` | Nemesis (token) | test message + pop-up |
| `POST /api/events` | Nemesis (token) | send events (max 1000 per request) |
| `POST /api/ground-truth` | Nemesis (token) | the answer key |
| `GET /api/attacks/{id}/result` | Nemesis (token) | was it detected? |
| `GET /`, `/api/overview`, `/api/alerts`, `/api/alerts/{id}`, `/api/activity`, `/api/performance`, `/api/attack-log` | dashboard (local only) | read data |
| `POST /api/alerts/{id}/status` | dashboard (local only) | open / investigating / closed_* |
