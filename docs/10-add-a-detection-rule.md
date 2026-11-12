# 10 - Add a detection rule to Guardian

Example: detect the **scheduled task** scenario from [09](09-add-your-own-attack.md). Everything is in `guardian/rules.py`.

## Step 1 - Write the check function

A check receives a list of recent events (newest 20 minutes) and returns a list of `Match` objects.

```python
def check_schtasks_user_folder(events):
    out = []
    for e in events:
        cmd = str(e["details"].get("cmdline", "")).lower()
        if (e["action"] == "process_start"
                and _base(e["details"].get("image")) == "schtasks.exe"
                and "/create" in cmd and "\\appdata\\" in cmd):
            out.append(Match(
                key=e["event_id"],                     # what the alert is about (used to avoid duplicates)
                event_ids=[e["event_id"]],             # the evidence
                summary="A scheduled task was created that runs a program from AppData",
            ))
    return out
```

Helpers already available: `_base(path)` (file name), `_group(events, predicate, keyfn)`,
`find_burst(events, window_seconds, threshold)` ("N events within T seconds").
`Match(..., bump=1)` makes the alert one severity level higher.

## Step 2 - Register the rule

Add to the `RULES` list at the bottom:

```python
Rule("EP-006", "Scheduled task in user folder", E, "T1053.005", "Scheduled Task/Job: Scheduled Task", "HIGH",
     "Malware creates scheduled tasks to keep running after reboots.",
     ["Inspect the program the task runs.", "Find which process created the task.", "Check for an approved change ticket."],
     ["Delete the task and the file.", "Scan the host."],
     check_schtasks_user_folder),
```

Arguments in order: id, title, category (`P I E N W C`), MITRE id, MITRE name, starting severity,
**why suspicious**, **what to investigate** (list), **how to fix** (list), the check function.

## Step 3 - Test it

```bash
python -m pytest -q
```

Remove `scheduled_task_persistence` from `MISSED_ON_PURPOSE` (if you added it there). The big detection-matrix test now
checks it across 3 difficulties and 3 random seeds.

## Tips for good rules

* **Think about false positives.** Ask: "what harmless thing looks like this?" Add conditions or an allow-list.
* **Use thresholds you can explain** (e.g. 10 failures in 120 seconds).
* **Rules only see event data**, never the scenario name or answer key.
* Keep analyst texts in plain English; the dashboard shows them to the investigator.
