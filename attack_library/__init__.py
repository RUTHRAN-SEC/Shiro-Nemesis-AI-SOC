"""
attack_library
==============
Importing this package loads every scenario module, which registers the scenarios.

    from attack_library import get_scenarios
    scenarios = get_scenarios()       # {"brute_force_login": Scenario(...), ...}
"""
from attack_library.base import SCENARIOS, Scenario, ScenarioContext  # noqa: F401
from attack_library import phishing, identity, malware, network, web, cloud, benign  # noqa: F401


def get_scenarios() -> dict[str, Scenario]:
    return dict(SCENARIOS)
