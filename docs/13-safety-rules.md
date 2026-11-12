# 13 - Safety rules

This lab is a **simulation**. It is designed so that it cannot harm anything.

## What Nemesis does NOT do

* No port scanning, no packets to other computers, no real DoS traffic.
* No malware, no ransomware, no file changes (attack "files renamed" is only a log line; dummy files are never touched).
* No password guessing against any real account or service.
* No shell access for the AI. The AI picks an id from a menu; nothing it writes is executed.

## The Safety Validator (`nemesis/safety_validator.py`)

Every batch of events must pass **all** checks (rules in `config/safety_policy.json`) or **nothing is sent**:

| Check | Why |
|---|---|
| Scenario exists and is not in `blocked_scenarios` | Only known, reviewed scenarios run |
| Every `*_ip` value is private or in a reserved documentation range | A real public IP can never appear |
| Every domain, DNS name, URL and email domain ends in `.example .invalid .test .local .localhost` (or example.com/org/net) | Fake names only |
| Every user and host belongs to the fictional ShiroTech | Real people/systems can't be named |
| Every event says `"simulated": true`, is small, and there are <= 600 per attack | No floods |
| Max 6 attacks per hour | A bug can't spam the lab |

Automated tests (`tests/test_safety.py`) prove that all 34 scenarios x 3 difficulties pass, and that public IPs,
real domains, real emails, unknown users/hosts, un-simulated events and oversized batches are all rejected.

## Network safety

* Guardian listens on your home Wi-Fi only; **never port-forward** it or expose it to the internet.
* The Windows firewall rule allows **only the Ubuntu laptop's IP**.
* Every Nemesis request needs the secret token (compared in constant time).
* The dashboard answers only on the ASUS laptop (`127.0.0.1`) unless you set `SN_DASHBOARD_ALLOW_LAN=true`.
* The dashboard never inserts event text as HTML, so attack-style strings like `<script>` cannot run.
* Guardian refuses to start with a missing or short token.

## Keep it safe when you change things

1. Keep new scenarios inside the rules above (the validator will tell you if not).
2. Never loosen `allowed_domain_suffixes` to real domains.
3. Never feed **real** company logs into this lab; if you add AI, remember the data is sent to the AI provider.
4. Never commit `.env` (token, API key) to GitHub.
5. If you later add real log ingestion, keep it in a separate, clearly labelled component.

## Legal note

You are free to experiment on **your own** devices. Do not point any tool you learn about here at systems you do not own or
have written permission to test.
