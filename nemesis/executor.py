"""
nemesis/executor.py
===================
Runs ONE chosen scenario from start to finish:

   generate fake events -> safety check -> deliver -> tell Guardian the answer key
   -> ask Guardian whether it caught it -> remember the result.

"Simulation Executor" in the architecture diagram. It only ever builds log events;
it cannot run shell commands.
"""
from __future__ import annotations

import logging
import random
import time
import uuid
from datetime import datetime, timezone

from api.client import GuardianClient
from attack_library.base import ScenarioContext
from nemesis import safety_validator
from nemesis.attack_memory import AttackMemory
from nemesis.scenario_selector import Choice
from shiro.activity import normal_activity
from shiro.email_simulator import Mailbox
from shiro.employee import Employee

log = logging.getLogger("executor")


def send_background_activity(employee: Employee, client: GuardianClient, rng: random.Random, policy: dict) -> int:
    """Send a batch of Shiro's boring normal events (so attacks hide in noise)."""
    ctx = ScenarioContext(employee, rng, datetime.now(timezone.utc), 1)
    events = normal_activity(ctx)
    if safety_validator.validate_events(events, policy, employee):
        return 0
    client.send_events(events)
    return len(events)


def run_attack(*, choice: Choice, employee: Employee, policy: dict, memory: AttackMemory,
               client: GuardianClient, mailbox: Mailbox, rng: random.Random,
               dry_run: bool = False, result_wait_s: float = 4.0) -> dict:
    """Execute one scenario. Returns a summary dict (also used by tests)."""
    s = choice.scenario
    problems = safety_validator.validate_choice(s.id, policy)
    if problems:
        return {"ok": False, "stage": "choice", "problems": problems}

    now = datetime.now(timezone.utc)
    ctx = ScenarioContext(employee, rng, now, choice.difficulty)
    events = s.generate(ctx)

    problems = safety_validator.validate_events(events, policy, employee)
    if problems:
        log.error("SAFETY VALIDATOR REJECTED %s: %s", s.id, problems)
        return {"ok": False, "stage": "events", "problems": problems}

    attack_id = f"ATK-{now:%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:4]}"
    summary = {"ok": True, "attack_id": attack_id, "scenario_id": s.id, "name": s.name, "category": s.category,
               "difficulty": choice.difficulty, "event_count": len(events), "planner": choice.planner,
               "reasoning": choice.reasoning, "is_attack": s.is_attack, "events": events,
               "delivered": False, "detected": None}
    if dry_run:
        return summary

    mailbox.deliver_from_events(events)
    delivered = client.send_events(events)
    summary["delivered"] = delivered

    # The "answer key" goes to a separate endpoint. Guardian's detection rules never see it;
    # it is only used afterwards to score how well Guardian did.
    client.send_ground_truth({
        "attack_id": attack_id, "scenario_id": s.id, "name": s.name, "category": s.category,
        "technique_id": s.technique_id, "technique_name": s.technique_name, "difficulty": choice.difficulty,
        "is_attack": s.is_attack, "planner": choice.planner, "reasoning": choice.reasoning,
        "started_at": min(e["timestamp"] for e in events), "event_ids": [e["event_id"] for e in events],
    })

    memory.record_attack(attack_id=attack_id, scenario_id=s.id, name=s.name, category=s.category,
                         technique_id=s.technique_id, difficulty=choice.difficulty, is_attack=s.is_attack,
                         event_count=len(events), delivered=delivered, planner=choice.planner,
                         reasoning=choice.reasoning)

    # Evaluate: did Guardian notice? (Only meaningful for real attacks that were delivered.)
    if delivered and result_wait_s >= 0:
        time.sleep(result_wait_s)
        result = client.get_attack_result(attack_id)
        if result is not None:
            summary["detected"] = bool(result.get("detected"))
            memory.set_detected(attack_id, summary["detected"])
    return summary
