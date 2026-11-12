"""
nemesis/scheduler.py
====================
The heartbeat of Nemesis (runs on the HP Ubuntu laptop).

    python -m nemesis.scheduler              # run forever, one attack every SN_INTERVAL_SECONDS (default 20 min)
    python -m nemesis.scheduler --once       # run a single cycle and stop (great for testing)
    python -m nemesis.scheduler --list       # show every scenario Nemesis knows
    python -m nemesis.scheduler --once --dry-run   # build + safety-check an attack but send nothing

Each cycle:  1) re-send anything saved in the outbox  2) send Shiro's normal activity
             3) check memory + pick an attack  4) safety check  5) deliver  6) learn the result.
"""
from __future__ import annotations

import argparse
import dataclasses
import logging
import random
import signal
import sys
import time

from api.client import GuardianClient
from attack_library import get_scenarios
from config.settings import get_settings, load_safety_policy
from nemesis import executor, safety_validator, scenario_selector
from nemesis.attack_memory import AttackMemory
from shiro.email_simulator import Mailbox
from shiro.employee import load_employee
from shiro.file_simulator import ensure_dummy_files

log = logging.getLogger("nemesis")
_stop = False


def _handle_signal(signum, _frame):
    global _stop
    log.info("Stop signal received - finishing the current step, then exiting.")
    _stop = True


def _acquire_lock(path):
    """Make sure only ONE Nemesis runs at a time (Linux/macOS)."""
    try:
        import fcntl
    except ImportError:  # Windows - not needed, Nemesis runs on Ubuntu
        return None
    handle = open(path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print("Another Nemesis is already running. Stop it first.")
        sys.exit(1)
    return handle  # keep a reference so the lock stays held


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Nemesis - the AI attacker (simulation only)")
    p.add_argument("--once", action="store_true", help="run one cycle, then exit")
    p.add_argument("--list", action="store_true", help="list all scenarios and exit")
    p.add_argument("--scenario", help="force a specific scenario id")
    p.add_argument("--difficulty", type=int, choices=[1, 2, 3], help="force a difficulty")
    p.add_argument("--dry-run", action="store_true", help="generate and validate, but do not send")
    p.add_argument("--no-ai", action="store_true", help="do not use the AI planner this run")
    p.add_argument("--interval", type=int, help="seconds between attacks (default from .env)")
    p.add_argument("--no-wait", action="store_true", help="do not wait for Guardian's detection result")
    return p


def run_cycle(settings, policy, employee, memory, client, mailbox, rng, args) -> None:
    scenarios = get_scenarios()
    client.flush_outbox()

    if args.scenario:
        if args.scenario not in scenarios:
            print(f"Unknown scenario '{args.scenario}'. Use --list to see them.")
            return
        choice = scenario_selector.Choice(scenarios[args.scenario], args.difficulty or 1, "manual", "Chosen by hand.")
    else:
        choice = scenario_selector.select(memory, rng, scenarios, settings, policy.get("blocked_scenarios", []))
        if args.difficulty:
            choice.difficulty = args.difficulty

    if not args.dry_run:
        sent = executor.send_background_activity(employee, client, rng, policy)
        log.info("Sent %d normal Shiro events.", sent)

    log.info("PLAN  scenario=%s difficulty=%d planner=%s", choice.scenario.id, choice.difficulty, choice.planner)
    log.info("WHY   %s", choice.reasoning)
    result = executor.run_attack(choice=choice, employee=employee, policy=policy, memory=memory, client=client,
                                 mailbox=mailbox, rng=rng, dry_run=args.dry_run,
                                 result_wait_s=-1 if args.no_wait else 4.0)
    if not result["ok"]:
        log.error("Attack NOT executed: %s", result["problems"])
        return
    if result["is_attack"]:
        verdict = {None: "unknown", True: "DETECTED by Guardian", False: "MISSED by Guardian"}[result["detected"]]
    else:  # harmless decoy: the GOOD outcome is "no alert"
        verdict = {None: "unknown", True: "decoy raised an alert (false positive)",
                   False: "decoy ignored (correct)"}[result["detected"]]
    log.info("DONE  %s | %d events | delivered=%s | result: %s", result["attack_id"], result["event_count"],
             result["delivered"], "(dry run)" if args.dry_run else verdict)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    settings = get_settings()
    policy = load_safety_policy()
    scenarios = get_scenarios()

    if args.list:
        print(f"{'ID':32} {'CATEGORY':10} {'MITRE':10} NAME")
        for s in sorted(scenarios.values(), key=lambda x: (x.category, x.id)):
            print(f"{s.id:32} {s.category:10} {s.technique_id:10} {s.name}")
        print(f"\n{len(scenarios)} scenarios.")
        return 0

    if args.no_ai:
        settings = dataclasses.replace(settings, nemesis_use_ai=False)
    interval = args.interval or settings.interval_seconds

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    if not args.dry_run and not settings.token:
        print("SN_TOKEN is empty. Run: python scripts/generate_token.py   (then paste it into .env)")
        return 1

    lock = _acquire_lock(settings.data_dir / "nemesis.lock")  # noqa: F841
    employee = load_employee()
    ensure_dummy_files(settings.files_dir)
    memory = AttackMemory(settings.nemesis_db_path)
    client = GuardianClient(settings.guardian_url, settings.token, settings.outbox_dir)
    mailbox = Mailbox(settings.mailbox_dir)
    rng = random.Random()

    if not args.dry_run:
        if client.health():
            log.info("Guardian is reachable at %s", settings.guardian_url)
        else:
            log.warning("Guardian is NOT reachable at %s. Events will wait in the outbox.", settings.guardian_url)
    log.info("AI planner: %s", "ON" if settings.nemesis_use_ai and settings.anthropic_api_key else "off (rules only)")

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if args.once or args.dry_run:
        run_cycle(settings, policy, employee, memory, client, mailbox, rng, args)
        return 0

    log.info("Nemesis started. One attack every %d seconds. Press Ctrl+C to stop.", interval)
    next_run = time.monotonic()
    while not _stop:
        if memory.count_since(60) >= policy["max_attacks_per_hour"]:
            log.warning("%s - skipping this cycle.", safety_validator.validate_rate(memory.count_since(60), policy)[0])
        else:
            try:
                run_cycle(settings, policy, employee, memory, client, mailbox, rng, args)
            except Exception:  # one bad cycle must never kill the attacker
                log.exception("Cycle failed - will try again next time.")
        next_run += interval
        if next_run < time.monotonic():
            next_run = time.monotonic() + interval
        while not _stop and time.monotonic() < next_run:
            time.sleep(1)
    log.info("Nemesis stopped.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
