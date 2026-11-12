# 00 - The big picture

## The idea in one minute

Imagine a small company called **ShiroTech**. It has one employee we care about: **Shiro**, an IT Support Engineer.
Shiro is *fictional*: just a name, an account, a PC name and some fake files.

An attacker called **Nemesis** lives on your **HP Ubuntu laptop**. Every 20 minutes it:

1. **Observes** - reads its memory: what did I try before? What did the defender catch?
2. **Thinks** - chooses a *different* attack (phishing, password attack, malware, network scan, web attack, cloud attack ...)
3. **Simulates** - creates the *fake evidence* that attack would leave behind (log lines)
4. **Sends** the evidence over your Wi-Fi to your **ASUS Windows laptop**
5. **Learns** - asks "did Guardian catch that?" and remembers the answer

On the ASUS laptop, **Guardian** is the defender. It reads the evidence, looks for suspicious patterns using
detection rules, raises alerts, shows a Windows pop-up, and fills a dashboard. **You are the SOC analyst**: you open
the alerts, read the evidence, decide *real attack* or *false alarm*, and decide what to do.

## Why "fake log lines" and not real attacks?

* **Safe** - nothing can break, no real computer is touched, no law is at risk.
* **Realistic enough** - SOC analysts do not watch attackers; they read **logs**. Logs are exactly what we create.
* **Light** - runs on laptops with little RAM.

Nemesis is an **actor putting on a play**. It uses props (log lines), not weapons.

## The important rule: Guardian is never told the answer

Nemesis sends *only* the evidence. It does **not** say "this is a password-spray attack".
Guardian must work that out from the evidence, like a real SOC.

The "answer key" (what Nemesis really did) goes to a **separate hidden place**. The dashboard shows it only when you
press **Reveal answer key**. It is used to score Guardian: detected, missed, false alarm.

## Realistic imperfections (on purpose)

| Situation | Example | Why we included it |
|---|---|---|
| **Missed detection** | QR-code phishing, C2 beaconing, new cloud access key have **no rule** | Real defences have blind spots. Can *you* spot them in the raw activity feed? |
| **False positive** | An approved IT script, an approved scan, a planned backup **trigger rules** | Real alerts are often harmless. Learn to investigate and close them correctly. |
| **Silent decoy** | Shiro mistypes his password 3 times | Good detection must stay quiet here |
| **Noise** | Shiro's normal day (emails, files, browsing) | Real attacks hide inside normal activity |

## How the AI fits in

AI is **optional** and **never required**:

| Where | With AI | Without AI |
|---|---|---|
| Nemesis planner | Claude picks the next scenario by reading history | Built-in rule-based selector picks it |
| Guardian analyst | Claude writes an extra short briefing | Built-in report (what happened, why, what to check, how to fix) |

The AI can **only choose from a menu** of safe scenarios. It cannot run commands or invent attacks.
See [08-add-ai.md](08-add-ai.md).

## The two laptops

| Laptop | IP (from your setup) | Runs | Needs |
|---|---|---|---|
| HP Ubuntu | 192.168.1.9 | Nemesis + Shiro | Python 3 + Git. **No pip packages.** |
| ASUS Windows | 192.168.1.5 | Guardian + dashboard + pop-ups | Python 3 + Git + 3 small packages |

They talk over your home Wi-Fi using HTTP on port **8000**, protected by a **secret token**, and the Windows
firewall only lets the Ubuntu laptop in.

## Words you will see

| Word | Simple meaning |
|---|---|
| **SOC** | Security Operations Center - the team that watches for attacks |
| **Event / log** | One line saying "something happened" (a login, a file rename, a web request) |
| **Alert** | Guardian's warning: "these events look suspicious" |
| **Detection rule** | A pattern, e.g. "10 failed logins in 2 minutes" |
| **True positive** | A real attack that was correctly detected |
| **False positive** | A harmless activity that raised an alert |
| **False negative / missed** | A real attack that raised no alert |
| **MITRE ATT&CK** | A public catalogue of attacker techniques (e.g. T1110 = Brute Force) |
| **Severity** | LOW, MEDIUM, HIGH, CRITICAL |
| **Toast** | The little pop-up in the corner of Windows |
