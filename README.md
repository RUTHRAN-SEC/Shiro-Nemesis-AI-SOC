# SHIRO x NEMESIS - AI Adversary Simulation & SOC Training Lab

> A small, private cybersecurity training game that runs on two laptops.
> An **AI attacker (Nemesis)** keeps "attacking" a **fictional employee (Shiro)**. You work as the
> **SOC analyst** on a dashboard (**Guardian**) and investigate what happened.
> Every day brings new attacks, so you never repeat the same tutorial.

**100% simulation.** Nemesis only creates *fake log lines* about a *fictional company*. It never scans, attacks or
contacts any real computer, account, website or network. A built-in Safety Validator blocks anything else
(see [docs/13-safety-rules.md](docs/13-safety-rules.md)).

```
   HP UBUNTU LAPTOP  (192.168.1.9)                    ASUS WINDOWS LAPTOP  (192.168.1.5)
 ┌───────────────────────────────┐                  ┌──────────────────────────────────┐
 │  NEMESIS  (the attacker)      │                  │  GUARDIAN  (the defender / SOC)  │
 │   AI planner  + rule fallback │                  │   event receiver (FastAPI)       │
 │   attack memory (SQLite)      │   fake log       │   normalizer -> 27 detection     │
 │   safety validator            │   events over    │   rules -> severity -> AI analyst│
 │   34 scenarios (30 + 4 decoys)│ ───────────────► │   SQLite alert database          │
 │  SHIRO (fictional employee)   │  Wi-Fi + secret  │   Dashboard  +  Windows pop-ups  │
 │   normal daily activity       │      token       │   Detection score card           │
 └───────────────────────────────┘                  └──────────────────────────────────┘
        every 20 minutes: observe -> think -> simulate -> send -> learn from the result
```

## What you get

| Part | What it does |
|---|---|
| **Shiro** | Fictional IT Support Engineer at fictional ShiroTech with an account, PC, mailbox and normal daily activity |
| **Nemesis** | Picks a new attack every 20 min using memory (+ optional Claude AI). Never repeats recently. Gets sneakier when Guardian is strong |
| **34 scenarios** | 30 attacks (phishing, identity, malware, network incl. DoS, web, cloud) + 4 harmless decoys that cause false positives |
| **Guardian** | 27 detection rules with MITRE ATT&CK mapping, severity, analyst-style explanations |
| **Dashboard** | Alert queue, evidence, timeline, MITRE view, Shiro's activity, detection score, hidden "answer key" |
| **Windows pop-ups** | A notification for every new alert |
| **Honest scoring** | Some attacks have **no rule on purpose** (missed detections) and some rules **fire on harmless things** (false positives) |

## Quick start (about 30 minutes)

Follow the numbered guides in order. Each step is explained in simple English.

1. [Big picture](docs/00-big-picture.md) - understand the idea (5 min read)
2. [GitHub setup](docs/02-github-setup.md) - put the project in your own repository
3. [Ubuntu setup](docs/03-ubuntu-setup.md) - the attacker laptop
4. [Windows setup](docs/04-windows-setup.md) - the defender laptop
5. [Connect the two laptops](docs/05-connect-the-laptops.md) - token + firewall + first test message
6. [First run](docs/06-first-run.md) - your first attack and first investigation

Then explore: [how each part works](docs/07-how-each-part-works.md) ·
[add AI](docs/08-add-ai.md) · [add your own attack](docs/09-add-your-own-attack.md) ·
[add a detection rule](docs/10-add-a-detection-rule.md) · [run automatically](docs/11-run-automatically.md) ·
[troubleshooting](docs/12-troubleshooting.md) · [roadmap](docs/14-roadmap.md)

**Want to know how the project was built, step by step?** Read [docs/01-how-the-project-was-built.md](docs/01-how-the-project-was-built.md).

## Folder map

```
shiro-nemesis-ai-soc/
├── README.md                  this file
├── .env.example               settings template (copy to .env)
├── requirements-ubuntu.txt    Ubuntu needs NO extra packages
├── requirements-windows.txt   fastapi, uvicorn, winotify
├── requirements-dev.txt       + pytest for the tests
├── config/                    settings.py, shiro_profile.json (the fake company), safety_policy.json
├── shiro/                     the fictional employee: profile, normal activity, mailbox, dummy files
├── attack_library/            34 scenarios in 7 folders (phishing, identity, malware, network, web, cloud, benign)
├── nemesis/                   attacker: scheduler, selector, ai_planner, attack_memory, safety_validator, executor
├── guardian/                  defender: normalizer, rules, detection_engine, severity, ai_analyst, incident_manager
├── api/                       server.py (Guardian), client.py (Nemesis), authentication.py, llm_client.py
├── dashboard/                 index.html, style.css, app.js
├── notifications/             windows_toast.py
├── storage/                   database.py, models.py (SQLite)
├── scripts/                   setup + run scripts for both laptops, token generator, connection test
├── tests/                     433 automated tests
├── docs/                      the step-by-step guides
└── .github/workflows/         tests run automatically on GitHub
```

## Commands you will use most

| Where | Command | Meaning |
|---|---|---|
| Ubuntu | `.venv/bin/python -m nemesis.scheduler` | Start the attacker (one attack every 20 min) |
| Ubuntu | `.venv/bin/python -m nemesis.scheduler --once` | Run just one attack now |
| Ubuntu | `.venv/bin/python -m nemesis.scheduler --list` | Show all 34 scenarios |
| Ubuntu | `... --once --scenario port_scan --difficulty 2` | Force a specific attack |
| Windows | `scripts\run_guardian.ps1` | Start the defender + dashboard |
| Both | `python -m pytest` | Run the tests (needs `requirements-dev.txt`) |

## Status

Working and tested: phases 1-8 of the original plan at "version 1" level (see [roadmap](docs/14-roadmap.md)).
The Windows pop-up code could not be run on Windows during development (it was built and tested on Linux);
the dashboard and alert database are the source of truth, and pop-up problems are covered in the troubleshooting guide.

## License

MIT - see [LICENSE](LICENSE). Educational use. Everything in this lab is fictional.
