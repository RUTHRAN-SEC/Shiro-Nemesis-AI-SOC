"""
attack_library/base.py
======================
The building blocks every attack scenario uses.

A SCENARIO is a small Python function that returns a list of fake log events.
It NEVER runs real attack tools and NEVER touches the network. It only makes up
log lines, like a movie prop. To add a scenario, see docs/09-add-your-own-attack.md.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable

from shiro.employee import Employee
from shiro.event_generator import make_event

# "Documentation" IP ranges. They are reserved by the internet standards (RFC 5737)
# for examples, so they can never belong to a real machine. Perfect fake attackers.
DOC_RANGES = ["203.0.113", "198.51.100", "192.0.2"]


@dataclass
class ScenarioContext:
    """Everything a scenario needs: who Shiro is, a random generator, and 'now'."""

    employee: Employee
    rng: random.Random
    now: datetime
    difficulty: int = 1  # 1 = noisy/obvious, 3 = quiet/stealthy

    def external_ip(self) -> str:
        """A fake attacker address from the reserved documentation ranges."""
        return f"{self.rng.choice(DOC_RANGES)}.{self.rng.randint(2, 250)}"

    def count(self, low: int, high: int) -> int:
        """How many events to make. Harder difficulty = quieter = closer to `low`."""
        frac = {1: 0.85, 2: 0.5, 3: 0.1}.get(self.difficulty, 0.5)
        frac = min(1.0, max(0.0, frac + self.rng.uniform(-0.1, 0.1)))
        return low + round((high - low) * frac)

    def event(self, source: str, action: str, details: dict, ago: float = 0.0,
              user: str | None = None, host: str | None = None) -> dict:
        """Make one event that happened `ago` seconds before now."""
        return make_event(
            source, action,
            host or self.employee.workstation,
            user or self.employee.username,
            details,
            self.now - timedelta(seconds=ago),
        )

    def spread(self, n: int, over_s: float, end_ago: float = 0.0) -> list[float]:
        """n random 'seconds ago' values spread over `over_s` seconds, earliest first."""
        offsets = sorted(self.rng.uniform(0, over_s) for _ in range(n))
        return [end_ago + over_s - t for t in offsets]


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    category: str          # phishing | identity | malware | network | web | cloud | benign
    technique_id: str      # MITRE ATT&CK id
    technique_name: str
    severity: str          # how bad the attacker thinks it is (for the attack log only)
    description: str
    objective: str         # "Test whether Guardian detects ..."
    is_attack: bool
    generate: Callable[[ScenarioContext], list[dict]]


# The big list of all scenarios. Filled automatically by the @scenario decorator.
SCENARIOS: dict[str, Scenario] = {}


def scenario(*, id: str, name: str, category: str, technique: tuple[str, str], severity: str = "MEDIUM",
             description: str, objective: str, is_attack: bool = True):
    """Decorator: put it above a function to register that function as a scenario."""

    def decorator(fn: Callable[[ScenarioContext], list[dict]]):
        if id in SCENARIOS:
            raise ValueError(f"Duplicate scenario id: {id}")
        SCENARIOS[id] = Scenario(id, name, category, technique[0], technique[1], severity,
                                 description, objective, is_attack, fn)
        return fn

    return decorator
