"""Tests for the attacker side: library, memory, selector, AI planner parsing."""
import random
from collections import Counter

from attack_library import get_scenarios
from nemesis import ai_planner, scenario_selector
from nemesis.attack_memory import AttackMemory


def test_library_has_30_attacks_5_per_category_and_4_decoys():
    scenarios = get_scenarios()
    attacks = [s for s in scenarios.values() if s.is_attack]
    assert len(attacks) == 30
    counts = Counter(s.category for s in attacks)
    assert set(counts) == {"phishing", "identity", "malware", "network", "web", "cloud"}
    assert all(n == 5 for n in counts.values())
    assert len([s for s in scenarios.values() if not s.is_attack]) == 4


def test_scenario_events_never_say_what_the_attack_is():
    """Guardian must work it out itself: no scenario name inside the events."""
    for sid, s in get_scenarios().items():
        from tests.helpers import generate
        text = str(generate(sid)).lower()
        assert sid not in text and s.technique_id.lower() not in text or s.technique_id == "-"


def test_events_are_different_each_run():
    from tests.helpers import generate
    a, b = generate("brute_force_login", seed=1), generate("brute_force_login", seed=2)
    assert [e["details"]["src_ip"] for e in a][:1] != [e["details"]["src_ip"] for e in b][:1] or len(a) != len(b)


def _record(mem, sid, cat, n, detected=None):
    mem.record_attack(attack_id=f"A{n}", scenario_id=sid, name=sid, category=cat, technique_id="T0",
                      difficulty=1, is_attack=True, event_count=1, delivered=True, planner="rules", reasoning="")
    if detected is not None:
        mem.set_detected(f"A{n}", detected)


def test_memory_stats_and_weaknesses(tmp_path):
    mem = AttackMemory(tmp_path / "m.db")
    _record(mem, "a", "web", 1, False)
    _record(mem, "b", "web", 2, False)
    _record(mem, "c", "cloud", 3, True)
    assert mem.category_stats()["web"] == {"total": 2, "detected": 0, "missed": 2}
    assert mem.weaknesses() == ["web"]
    assert mem.detection_rate() == 1 / 3
    assert mem.total() == 3


def test_selector_never_repeats_recently_and_varies(tmp_path):
    mem = AttackMemory(tmp_path / "m.db")
    rng = random.Random(7)
    scenarios = get_scenarios()
    picked = []
    for i in range(40):
        c = scenario_selector.choose_by_rules(mem, rng, scenarios, include_decoys=False)
        assert c.scenario.is_attack and 1 <= c.difficulty <= 3
        _record(mem, c.scenario.id, c.scenario.category, i, detected=bool(i % 2))
        picked.append(c.scenario.id)
    for i in range(len(picked) - 15):                    # no repeats inside a 15-attack window
        assert len(set(picked[i:i + 15])) == 15
    assert len(set(picked)) >= 25                        # wide variety overall


def test_selector_focus_changes_by_day():
    from datetime import date
    cats = ["a", "b", "c", "d", "e", "f"]
    focuses = {scenario_selector.todays_focus(cats, date(2026, 11, d)) for d in range(1, 7)}
    assert len(focuses) == 6


def test_ai_reply_parsing_and_validation(tmp_path, monkeypatch):
    mem = AttackMemory(tmp_path / "m.db")
    scenarios = get_scenarios()
    assert ai_planner.parse_reply('sure! {"scenario_id": "port_scan", "difficulty": 2, "reasoning": "x"}')["difficulty"] == 2
    assert ai_planner.parse_reply("no json here") is None

    class S:
        anthropic_api_key, ai_model = "k", "m"

    reply = {"text": '{"scenario_id": "port_scan", "difficulty": 9, "reasoning": "weak network"}'}
    monkeypatch.setattr(ai_planner, "ask_claude", lambda **kw: reply["text"])
    choice = ai_planner.plan_with_ai(S, mem, scenarios, random.Random(1))
    assert choice.scenario.id == "port_scan" and choice.difficulty == 3 and choice.planner == "ai"

    reply["text"] = '{"scenario_id": "delete_everything", "difficulty": 1}'      # invented id -> rejected
    assert ai_planner.plan_with_ai(S, mem, scenarios, random.Random(1)) is None
    reply["text"] = '{"scenario_id": "benign_admin_script", "difficulty": 1}'     # decoy -> rejected
    assert ai_planner.plan_with_ai(S, mem, scenarios, random.Random(1)) is None
    monkeypatch.setattr(ai_planner, "ask_claude", lambda **kw: None)              # API down -> fallback
    assert ai_planner.plan_with_ai(S, mem, scenarios, random.Random(1)) is None
