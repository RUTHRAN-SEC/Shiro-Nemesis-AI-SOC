"""
nemesis/scenario_selector.py
============================
The rule-based "brain" that decides WHICH attack to run next.
It works with no internet and no AI. (The AI planner, if enabled, is tried first
and this is the safety net.)

How it decides (in simple words):
  * Never repeat a scenario that was used recently.
  * Prefer scenarios it has never used.
  * Prefer categories where Guardian missed attacks before (attackers go where defence is weak).
  * Each day has a "focus category" (changes daily) that gets extra weight -> every day feels different.
  * Avoid using the same category twice in a row.
  * Pick a harder difficulty when Guardian has been catching everything.
  * Now and then (15%), send a harmless decoy that looks scary.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import date

from attack_library.base import Scenario
from nemesis.attack_memory import AttackMemory

DECOY_CHANCE = 0.15


@dataclass
class Choice:
    scenario: Scenario
    difficulty: int
    planner: str      # "rules" or "ai"
    reasoning: str


def todays_focus(categories: list[str], today: date | None = None) -> str:
    """A different category each day (rotates by calendar day)."""
    cats = sorted(categories)
    return cats[(today or date.today()).toordinal() % len(cats)]


def pick_difficulty(memory: AttackMemory, rng: random.Random) -> int:
    rate = memory.detection_rate(10)
    if rate is None:
        weights = [0.6, 0.3, 0.1]       # new game: start gentle
    elif rate > 0.8:
        weights = [0.1, 0.3, 0.6]       # Guardian is strong: be sneakier
    elif rate < 0.4:
        weights = [0.5, 0.4, 0.1]       # Guardian struggles: keep it fair
    else:
        weights = [0.3, 0.4, 0.3]
    return rng.choices([1, 2, 3], weights=weights)[0]


def choose_by_rules(memory: AttackMemory, rng: random.Random, scenarios: dict[str, Scenario],
                    include_decoys: bool = True, today: date | None = None) -> Choice:
    attacks = [s for s in scenarios.values() if s.is_attack]
    decoys = [s for s in scenarios.values() if not s.is_attack]

    # 1) sometimes pick a decoy instead of a real attack
    if include_decoys and decoys and rng.random() < DECOY_CHANCE:
        pool = decoys
        why = "Sending a harmless decoy that looks suspicious (practice for false positives)."
    else:
        pool = attacks
        why = ""

    # 2) never repeat what was used recently
    recent = memory.recent(max(1, len(pool) // 2))
    recent_ids = {r["scenario_id"] for r in recent}
    candidates = [s for s in pool if s.id not in recent_ids] or pool
    last_category = recent[0]["category"] if recent else None

    # 3) weigh the candidates
    stats = memory.category_stats()
    used = memory.scenario_counts()
    focus = todays_focus(sorted({s.category for s in attacks}), today)
    weights = []
    for s in candidates:
        w = 1.0
        if s.id not in used:
            w += 1.0                                  # never tried before
        st = stats.get(s.category)
        if st and st["total"] > 0:
            w += 2.0 * (st["missed"] / st["total"])   # Guardian was weak here
        if s.category == focus:
            w *= 1.8                                  # today's theme
        if s.category == last_category:
            w *= 0.4                                  # avoid the same category twice
        weights.append(w)

    scenario = rng.choices(candidates, weights=weights)[0]
    difficulty = pick_difficulty(memory, rng)
    if not why:
        bits = [f"Today's focus is '{focus}'."]
        if scenario.id not in used:
            bits.append("Never used this scenario before.")
        if stats.get(scenario.category, {}).get("missed"):
            bits.append(f"Guardian missed '{scenario.category}' attacks before.")
        why = " ".join(bits)
    return Choice(scenario, difficulty, "rules", why)


def select(memory: AttackMemory, rng: random.Random, scenarios: dict[str, Scenario], settings,
           blocked: list[str] | None = None, today: date | None = None) -> Choice:
    """Try the AI planner first (if enabled), otherwise use the rules."""
    allowed = {k: v for k, v in scenarios.items() if k not in (blocked or [])}
    # The decoy roll happens here so the AI only ever plans real attacks.
    decoy_roll = settings.include_decoys and rng.random() < DECOY_CHANCE
    if not decoy_roll and settings.nemesis_use_ai and settings.anthropic_api_key:
        from nemesis.ai_planner import plan_with_ai  # imported here to avoid a circular import
        choice = plan_with_ai(settings, memory, allowed, rng, today)
        if choice:
            return choice
    if decoy_roll:
        decoys = {k: v for k, v in allowed.items() if not v.is_attack}
        if decoys:
            pool = decoys
            scen = rng.choice(list(pool.values()))
            return Choice(scen, pick_difficulty(memory, rng), "rules",
                          "Sending a harmless decoy that looks suspicious (practice for false positives).")
    return choose_by_rules(memory, rng, allowed, include_decoys=False, today=today)
