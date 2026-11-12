"""The safety validator must block anything outside the fake lab."""
import copy

import pytest

from attack_library import get_scenarios
from config.settings import load_safety_policy
from nemesis import safety_validator as sv
from shiro.employee import load_employee
from tests.helpers import generate

POLICY = load_safety_policy()
EMP = load_employee()


@pytest.mark.parametrize("scenario_id", sorted(get_scenarios()))
@pytest.mark.parametrize("difficulty", [1, 2, 3])
def test_every_scenario_passes_the_validator(scenario_id, difficulty):
    events = generate(scenario_id, difficulty, seed=difficulty)
    assert sv.validate_events(events, POLICY, EMP) == []


def _one_event():
    return copy.deepcopy(generate("brute_force_login")[0])


def test_rejects_public_ip():
    ev = _one_event()
    ev["details"]["src_ip"] = "8.8.8.8"
    assert any("public IP" in p for p in sv.validate_events([ev], POLICY, EMP))


def test_rejects_real_domain():
    ev = _one_event()
    ev["details"]["domain"] = "google.com"
    assert any("domain" in p for p in sv.validate_events([ev], POLICY, EMP))


def test_rejects_real_url_and_email():
    ev = _one_event()
    ev["details"]["url"] = "https://evil-bank.com/login"
    ev["details"]["from"] = "ceo@realcompany.com"
    problems = sv.validate_events([ev], POLICY, EMP)
    assert any("URL" in p for p in problems) and any("email" in p for p in problems)


def test_rejects_unknown_user_and_host():
    ev = _one_event()
    ev["user"], ev["host"] = "real.person", "REAL-PC"
    problems = sv.validate_events([ev], POLICY, EMP)
    assert any("user" in p for p in problems) and any("host" in p for p in problems)


def test_rejects_event_not_marked_simulated():
    ev = _one_event()
    ev["simulated"] = False
    assert sv.validate_events([ev], POLICY, EMP)


def test_rejects_too_many_events():
    events = [_one_event() for _ in range(POLICY["max_events_per_scenario"] + 1)]
    assert any("too many" in p for p in sv.validate_events(events, POLICY, EMP))


def test_rejects_unknown_and_blocked_scenarios():
    assert sv.validate_choice("rm_rf_everything", POLICY)
    assert sv.validate_choice("port_scan", {"blocked_scenarios": ["port_scan"]})


def test_rate_limit():
    assert sv.validate_rate(0, POLICY) == []
    assert sv.validate_rate(POLICY["max_attacks_per_hour"], POLICY)
