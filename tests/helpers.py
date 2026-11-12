"""Shared helpers for the tests."""
import random
from datetime import datetime, timezone

from attack_library import get_scenarios
from attack_library.base import ScenarioContext
from config.settings import Settings
from shiro.employee import load_employee


def make_settings(tmp_path, token="test-token-1234567890abcdef") -> Settings:
    return Settings(
        token=token, guardian_host="127.0.0.1", guardian_port=8000, bind_host="127.0.0.1",
        dashboard_allow_lan=False, min_toast_severity="LOW", guardian_use_ai=False,
        interval_seconds=1200, nemesis_use_ai=False, include_decoys=True,
        anthropic_api_key="", ai_model="x", data_dir=tmp_path,
    )


def generate(scenario_id: str, difficulty: int = 1, seed: int = 0) -> list[dict]:
    ctx = ScenarioContext(load_employee(), random.Random(seed), datetime.now(timezone.utc), difficulty)
    return get_scenarios()[scenario_id].generate(ctx)
