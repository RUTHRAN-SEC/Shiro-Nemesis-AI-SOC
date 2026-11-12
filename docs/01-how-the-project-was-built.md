# 01 - How this project was built, step by step

This is the full build story in the same order we built it. Use it to **understand** the project or to **rebuild it
from scratch** yourself. Each phase says: what we did, why, which files, and how to test it.
(The finished code is already in this repository.)

Rule we followed: **build one small piece, test it, then move on.**

---

## Phase 1 - Foundation (settings, storage, secure messaging)

**Goal:** both laptops can talk safely.

| Step | What we did | File |
|---|---|---|
| 1.1 | Created the folder structure (`config/ shiro/ nemesis/ guardian/ api/ ...`) | whole repo |
| 1.2 | Made one settings loader that reads `.env` (no extra packages) | `config/settings.py`, `.env.example` |
| 1.3 | Wrote the list of safety rules (allowed fake domains, max events...) | `config/safety_policy.json` |
| 1.4 | Created the SQLite storage layer (3 tables for Guardian, 1 for Nemesis) | `storage/database.py`, `storage/models.py` |
| 1.5 | Built the secret-token check and "dashboard is local-only" check | `api/authentication.py` |
| 1.6 | Built Guardian's web server (receives events) | `api/server.py` |
| 1.7 | Built Nemesis' HTTP client with timeouts and an **outbox** (saves data if Guardian is offline) | `api/client.py` |
| 1.8 | Wrote a connection test and setup scripts | `scripts/test_connection.py`, `scripts/setup_*` |

**Test:** Ubuntu runs `scripts/test_connection.py` -> Windows shows a pop-up "Nemesis connected". 
**Design choice:** the Ubuntu side uses only Python's standard library, so Python 3.14 never causes package problems.

---

## Phase 2 - Shiro, the fictional employee

**Goal:** a believable victim with a normal life.

| Step | What we did | File |
|---|---|---|
| 2.1 | Described ShiroTech: Shiro, 15 coworkers, servers, executives (all fictional, private 10.x IPs) | `config/shiro_profile.json` |
| 2.2 | Loaded that into a Python object | `shiro/employee.py` |
| 2.3 | One standard event format (no field says "attack") | `shiro/event_generator.py` |
| 2.4 | Normal daily activity: logins, files, apps, DNS, mail, browsing | `shiro/activity.py` |
| 2.5 | Fake mailbox saved as files; dummy documents | `shiro/email_simulator.py`, `shiro/file_simulator.py` |

**Test:** normal activity must **never** raise an alert (an automated test checks 30 random days).

---

## Phase 3 - The attack library (34 scenarios)

**Goal:** many different, varied attacks - all just log lines.

| Step | What we did | File |
|---|---|---|
| 3.1 | Made the scenario "recipe" format and the `@scenario` decorator | `attack_library/base.py` |
| 3.2 | Wrote 5 scenarios in each of 6 categories | `attack_library/<category>/scenarios.py` |
| 3.3 | Added 4 harmless decoys (cause false positives) | `attack_library/benign/scenarios.py` |
| 3.4 | Gave every scenario randomness (random fake IPs, counts, names) and a difficulty (1 loud ... 3 quiet) | `ScenarioContext` in `base.py` |

Fake attackers use only **reserved documentation IP ranges** (203.0.113.x, 198.51.100.x, 192.0.2.x) and
**reserved fake domains** (`.example`, `.invalid`, `.test`) that can never belong to a real machine.

**Test:** `tests/test_nemesis.py` checks 30 attacks, 5 per category, 4 decoys.

---

## Phase 4 - Nemesis, the AI attacker

**Goal:** choose a different attack each time, remember, adapt, stay safe.

| Step | What we did | File |
|---|---|---|
| 4.1 | **Attack memory** in SQLite: every attack + whether it was detected | `nemesis/attack_memory.py` |
| 4.2 | **Rule-based selector**: no repeats, prefer new things, prefer Guardian's weak spots, daily focus category, adaptive difficulty | `nemesis/scenario_selector.py` |
| 4.3 | **AI planner** (optional): Claude picks from a menu; answer is checked; falls back to rules | `nemesis/ai_planner.py`, `api/llm_client.py` |
| 4.4 | **Safety validator**: blocks public IPs, real domains, unknown users, too many events | `nemesis/safety_validator.py` |
| 4.5 | **Executor**: generate -> validate -> send -> send answer key -> ask result -> remember | `nemesis/executor.py` |
| 4.6 | **Scheduler**: the 20-minute loop with error handling, single-instance lock, `--once`, `--dry-run` | `nemesis/scheduler.py` |

**Test:** `tests/test_safety.py` (every scenario passes, every bad input is blocked) and selector tests.

---

## Phase 5 - Guardian, the detector

**Goal:** find attacks *without being told* what they are.

| Step | What we did | File |
|---|---|---|
| 5.1 | **Normalizer**: one clean format, rejects bad data | `guardian/event_normalizer.py` |
| 5.2 | **27 detection rules** (brute force, spray, impossible travel, PowerShell, ransomware, DNS tunnel, SQL injection, cloud admin policy...) | `guardian/rules.py` |
| 5.3 | **Detection engine**: runs all rules, one broken rule can't stop the rest | `guardian/detection_engine.py` |
| 5.4 | **Severity engine**: starting severity + clues (e.g. login *succeeded* after failures = worse) | `guardian/severity_engine.py` |
| 5.5 | **Incident manager**: store -> detect -> dedupe -> alert -> notify; also scoring | `guardian/incident_manager.py` |

We deliberately left **3 attacks without rules** and made **3 decoys trigger rules**.

**Test:** `tests/test_guardian.py` runs *every scenario x 3 difficulties x 3 random seeds* (306 runs) and checks the
expected result.

---

## Phase 6 - The AI SOC analyst

**Goal:** every alert explains itself.

| Step | What we did | File |
|---|---|---|
| 6.1 | Built-in report: what happened, why suspicious, who is affected, MITRE technique, what to investigate, how to fix | `guardian/ai_analyst.py` (`build_analysis`) |
| 6.2 | Optional Claude briefing that reads the actual evidence, added in the background | `guardian/ai_analyst.py` (`ask_llm_briefing`) |

---

## Phase 7 - Dashboard and notifications

| Step | What we did | File |
|---|---|---|
| 7.1 | Windows pop-ups: winotify -> PowerShell -> console fallback | `notifications/windows_toast.py` |
| 7.2 | Dashboard page: Alerts, Overview, Shiro activity, Detection score | `dashboard/index.html, style.css, app.js` |
| 7.3 | Analyst workflow: Investigating / Close as real / Close as false alarm | `api/server.py`, `app.js` |
| 7.4 | "Reveal answer key" button for the hidden truth | `app.js`, `/api/attack-log` |

The dashboard builds the page with `textContent` (never `innerHTML` with data), because attack evidence can contain
text like `<script>` and must never run in your browser.

---

## Phase 8 - Testing, hardening and polish

| Step | What we did |
|---|---|
| 8.1 | 433 automated tests (safety, selector, detection matrix, API, auth) |
| 8.2 | A live end-to-end run: Guardian server + several Nemesis cycles over HTTP |
| 8.3 | Browser check of the dashboard (no JavaScript errors) |
| 8.4 | GitHub Actions workflow runs the tests on every push (`.github/workflows/tests.yml`) |
| 8.5 | Documentation (these guides) |

---

## What to build next

See [14-roadmap.md](14-roadmap.md): more scenarios, multi-stage campaigns, a Guardian AI that learns, WebSocket live
updates, real log ingestion.
