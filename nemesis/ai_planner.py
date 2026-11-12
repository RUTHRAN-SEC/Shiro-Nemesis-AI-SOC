"""
nemesis/ai_planner.py
=====================
The OPTIONAL AI part of Nemesis.

What the AI is allowed to do:   pick ONE scenario id from a menu + a difficulty (1-3)
                                + a one-sentence reason.
What the AI is NOT allowed to do: write commands, payloads, IP addresses, or run anything.

Even if the AI replies with nonsense, we check its answer against the real menu.
If it is wrong, or the API is unreachable, we return None and the rule-based selector takes over.
"""
from __future__ import annotations

import json
import logging
import random
import re
from datetime import date

from api.llm_client import ask_claude
from attack_library.base import Scenario
from nemesis.attack_memory import AttackMemory
from nemesis.scenario_selector import Choice, todays_focus

log = logging.getLogger("planner")

SYSTEM = (
    "You are Nemesis, the red-team PLANNER of a closed, fully simulated cybersecurity training lab. "
    "Nothing you choose touches a real system: scenarios only create fake log lines for a fictional employee. "
    "You may only choose a scenario_id from the menu you are given. Never write commands, payloads or addresses. "
    "Goal: give the blue-team trainee a varied, fresh experience: avoid repeats, vary categories, "
    "and favour areas where the defender has missed attacks before. "
    'Reply with ONLY a JSON object: {"scenario_id": "...", "difficulty": 1-3, "reasoning": "max 30 words"}'
)


def build_prompt(memory: AttackMemory, scenarios: dict[str, Scenario], today: date | None) -> str:
    attacks = [s for s in scenarios.values() if s.is_attack]
    menu = "\n".join(f"- {s.id} | {s.category} | {s.technique_id} | {s.name}" for s in attacks)
    recent = memory.recent(10)
    history = "\n".join(
        f"- {r['scenario_id']} (difficulty {r['difficulty']}, "
        f"{'detected' if r['detected'] == 1 else 'MISSED' if r['detected'] == 0 else 'unknown'})" for r in recent
    ) or "- (no attacks yet)"
    stats = memory.category_stats()
    stat_lines = "\n".join(f"- {c}: {s['total']} tried, {s['missed']} missed" for c, s in stats.items()) or "- (none)"
    focus = todays_focus(sorted({s.category for s in attacks}), today)
    return (
        f"MENU:\n{menu}\n\nLAST 10 ATTACKS (newest first):\n{history}\n\n"
        f"DEFENDER RESULTS BY CATEGORY:\n{stat_lines}\n\nTODAY'S FOCUS CATEGORY: {focus}\n\n"
        "Choose the next scenario."
    )


def parse_reply(text: str) -> dict | None:
    """Pull the first {...} JSON object out of the AI's text."""
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except json.JSONDecodeError:
        return None


def plan_with_ai(settings, memory: AttackMemory, scenarios: dict[str, Scenario],
                 rng: random.Random, today: date | None = None) -> Choice | None:
    text = ask_claude(api_key=settings.anthropic_api_key, model=settings.ai_model, system=SYSTEM,
                      prompt=build_prompt(memory, scenarios, today), max_tokens=200, timeout=20)
    if not text:
        return None
    data = parse_reply(text)
    if not data:
        log.warning("AI reply was not valid JSON - using rules instead.")
        return None
    scenario = scenarios.get(str(data.get("scenario_id", "")))
    if scenario is None or not scenario.is_attack:
        log.warning("AI chose an unknown scenario - using rules instead.")
        return None
    if scenario.id in {r["scenario_id"] for r in memory.recent(8)}:
        log.info("AI repeated a recent scenario - using rules instead.")
        return None
    try:
        difficulty = min(3, max(1, int(data.get("difficulty", 2))))
    except (TypeError, ValueError):
        difficulty = 2
    reasoning = str(data.get("reasoning", ""))[:300] or "Chosen by AI planner."
    return Choice(scenario, difficulty, "ai", reasoning)
