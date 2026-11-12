# 14 - Roadmap: what is done and what to build next

## Done (version 1)

| Phase | Status |
|---|---|
| 1 Foundation (settings, storage, secure API, outbox) | Done |
| 2 Shiro employee (profile, normal activity, mailbox, dummy files) | Done |
| 3 Attack library (30 attacks + 4 decoys) | Done |
| 4 Nemesis (memory, selector, optional AI planner, safety validator, scheduler) | Done |
| 5 Guardian (normalizer, 27 rules, severity, dedupe, scoring) | Done |
| 6 AI SOC analyst (built-in report + optional AI briefing) | Done |
| 7 Dashboard + Windows notifications | Done |
| 8 Testing (433 tests, live end-to-end run, CI) | Done |

Known limits:
* Windows pop-up code was developed on Linux; verify it on your ASUS (see troubleshooting).
* Dashboard refreshes every 4 seconds (polling) instead of WebSocket push.
* Rules use fixed thresholds; they are readable on purpose rather than clever.
* Events are sent over plain HTTP on your home network, protected by a token, not encrypted.

## Ideas, easiest first

1. **More scenarios** - grow 30 -> 100 (docs 09). Ideas: USB malware, RDP from the internet, kerberoasting, phishing with MFA bypass page, S3 data download, insider copying files.
2. **More rules + fix a blind spot** - write rules for QR phishing, C2 beaconing (regular intervals) and CreateAccessKey. Re-run the tests.
3. **Analyst notes** - add a notes box per alert (new column in `alerts`).
4. **Multi-stage campaigns** - Nemesis plans a chain over several cycles (phish -> credential theft -> lateral movement -> exfiltration) and Guardian correlates alerts into one **incident**.
5. **WebSocket live updates** - replace polling with `/ws` so alerts appear instantly.
6. **Interactive analyst assistant** - a chat box on an alert: "why is this suspicious?" (send the alert + evidence to Claude).
7. **Guardian AI** - let AI suggest new rules from missed attacks (always human-reviewed). This completes the "AI vs AI" vision.
8. **Weekly report** - export a PDF/HTML summary of detection rate per category and per technique (MITRE heat map).
9. **Docker** - containers for each laptop if you want one-command installs.
10. **HTTPS** - put Guardian behind a reverse proxy with a self-signed certificate.
11. **Real log ingestion** - parse real Ubuntu auth logs into the same event format so Guardian can also watch real activity, shown clearly as "real", never mixed with simulations.

## Portfolio tips

* Pin the repository and add 2 dashboard screenshots to the README.
* Mention: detection engineering, MITRE ATT&CK mapping, false-positive handling, safe AI integration (menu-constrained planner with a rule-based fallback), automated tests, CI.
