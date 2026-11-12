# 09 - Add your own attack scenario

Example: add **"Suspicious scheduled task created"** (MITRE T1053.005) to the malware category.

## Step 1 - Open the category file

`attack_library/malware/scenarios.py`

## Step 2 - Add a recipe at the bottom

```python
@scenario(
    id="scheduled_task_persistence",                      # unique, lower case, no spaces
    name="Suspicious scheduled task created",
    category="malware",                                   # phishing|identity|malware|network|web|cloud|benign
    technique=("T1053.005", "Scheduled Task/Job: Scheduled Task"),
    severity="HIGH",
    description="A new task is created that runs a program from AppData every hour.",
    objective="Test whether Guardian detects new scheduled tasks in user folders.",
)
def scheduled_task_persistence(ctx):
    u = ctx.employee.username
    return [
        ctx.event("endpoint", "process_start",
                  {"image": "C:\\Windows\\System32\\schtasks.exe",
                   "parent_image": "C:\\Windows\\System32\\cmd.exe",
                   "cmdline": f"schtasks /create /tn Updater /tr C:\\Users\\{u}\\AppData\\Roaming\\up.exe /sc hourly"},
                  ago=ctx.rng.uniform(5, 60)),
    ]
```

Tools you have inside `ctx`:

| Helper | Meaning |
|---|---|
| `ctx.event(source, action, details, ago=seconds)` | One event that happened `ago` seconds before now. Sources: `auth email endpoint network dns web cloud` |
| `ctx.count(low, high)` | How many events. Harder difficulty -> closer to `low` |
| `ctx.spread(n, over_s, end_ago)` | n times spread over `over_s` seconds |
| `ctx.external_ip()` | A fake attacker IP (reserved documentation range) |
| `ctx.rng` | Random generator - use it so every run differs |
| `ctx.employee` | Shiro (username, workstation, workstation_ip, coworkers, servers) |

## Step 3 - Obey the safety rules

* Only fake IPs: `ctx.external_ip()` or the 10.10.10.x lab addresses.
* Only fake domains ending in `.example .invalid .test .local`.
* Only users/hosts from `config/shiro_profile.json` (or listed in `safety_policy.json`).
* Do not write words that name the attack in the event (Guardian must work it out).

## Step 4 - Check it

```bash
.venv/bin/python -m nemesis.scheduler --list | grep scheduled
.venv/bin/python -m nemesis.scheduler --once --dry-run --scenario scheduled_task_persistence
```

If the Safety Validator dislikes something it tells you exactly what.

## Step 5 - Decide: will Guardian catch it?

* **Yes** -> add a rule: [10-add-a-detection-rule.md](10-add-a-detection-rule.md).
* **No** -> leave it. You just created a new blind spot to hunt for.

## Step 6 - Update the tests

Run `python -m pytest`. Two things will fail on purpose, which tells you what to update:

1. `tests/test_nemesis.py::test_library_has_30_attacks...` - change the counts (31 attacks, 6 malware).
2. `tests/test_guardian.py` - if you left it undetected, add its id to `MISSED_ON_PURPOSE`.

Commit: `git add . && git commit -m "Add scheduled task scenario" && git push`.
