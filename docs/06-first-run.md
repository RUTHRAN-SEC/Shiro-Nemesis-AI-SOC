# 06 - Your first attack and first investigation

## Step 1 - Launch ONE attack by hand

Guardian must be running on Windows and the dashboard open at http://127.0.0.1:8000.

On **Ubuntu**:

```bash
.venv/bin/python -m nemesis.scheduler --once
```

You will see something like:

```
PLAN  scenario=password_spray difficulty=2 planner=rules
WHY   Today's focus is 'identity'. Never used this scenario before.
DONE  ATK-20261111-112228-e6d6 | 24 events | delivered=True | result: DETECTED by Guardian
```

Reading it: **PLAN** = what Nemesis chose, **WHY** = its reason, **DONE** = how many fake events it sent and whether
Guardian caught it. (Do not peek at PLAN if you want to play the analyst honestly. Run it with `> /dev/null` or just
look at the dashboard.)

## Step 2 - Investigate as the SOC analyst

On the ASUS laptop, in the dashboard **Alerts** tab:

1. Click the alert in the queue.
2. Read **What happened** and **Why is it suspicious?**
3. Read the **Evidence** table: the raw events. Does it match the story?
4. Work through **What should you investigate?** (open the **Shiro activity** tab, look at events around the same time)
5. Click **Start investigating**.
6. Decide:
   * **Close: real attack** - the alert was correct.
   * **Close: false alarm** - the activity was harmless (check the clues: change tickets, approved scanner...).

## Step 3 - See the score

Go to **Detection score**. It shows attacks launched, detected, missed, and alerts that were real vs false alarms.
Press **Reveal answer key** to see exactly what Nemesis did, whether it was real or a decoy, why it chose it,
and which alerts matched.

**Challenge:** before revealing, look at **Shiro activity** and try to find attacks that raised *no alert*.

## Step 4 - Try specific attacks

```bash
.venv/bin/python -m nemesis.scheduler --list                              # see all scenarios
.venv/bin/python -m nemesis.scheduler --once --scenario dns_tunneling     # force one
.venv/bin/python -m nemesis.scheduler --once --scenario ransomware_behavior --difficulty 3
.venv/bin/python -m nemesis.scheduler --once --scenario qr_code_phishing  # Guardian has no rule: it will be missed
```

Difficulty: **1** = loud and obvious, **3** = quiet (fewer events, closer to the detection limit).

## Step 5 - Start the real 20-minute loop

```bash
.venv/bin/python -m nemesis.scheduler
```

Nemesis now sends Shiro's normal activity plus one new attack every 20 minutes. Press `Ctrl+C` to stop (it finishes
politely). To change the speed for testing: `... --interval 120` (every 2 minutes).

To start it automatically at boot, see [11-run-automatically.md](11-run-automatically.md).

## Step 6 - Watch Nemesis adapt

After 10+ attacks:

* It never repeats a scenario within a window of 15 attacks.
* Categories where Guardian missed attacks get picked more.
* If Guardian catches everything, difficulty drifts up; if it struggles, difficulty eases.
* Each day has a different "focus category".

Nemesis' memory is a file: `data/nemesis_memory.db` on Ubuntu. Delete it for a fresh start.
