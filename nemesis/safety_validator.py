"""
nemesis/safety_validator.py
===========================
The "safety officer". NOTHING leaves Nemesis unless this file says OK.

It checks (rules come from config/safety_policy.json):
  1. The scenario exists and is not blocked.
  2. Every IP address is private or a reserved documentation address (never a real public IP).
  3. Every domain/URL/email uses a reserved fake suffix (.example, .invalid, .test, .local ...).
  4. Every user and host belongs to the fake ShiroTech company.
  5. Every event is marked "simulated": true and is not too big.
  6. The scenario does not create too many events.
  7. Nemesis is not attacking more often than the hourly limit.
"""
from __future__ import annotations

import ipaddress
import json
from urllib.parse import urlparse

from attack_library.base import SCENARIOS
from shiro.employee import Employee

IP_KEYS_SUFFIX = ("_ip",)
DOMAIN_KEYS = {"domain", "from_domain", "reply_to_domain", "qr_url_domain", "partner_host"}
URL_KEYS = {"url", "qr_url"}
EMAIL_KEYS = {"from", "to", "reply_to"}
URL_LIST_KEYS = {"urls"}


def _domain_ok(host: str, suffixes: list[str]) -> bool:
    host = host.lower().strip(".")
    for s in suffixes:
        s = s.lower()
        if s.startswith("."):
            if host.endswith(s) or host == s[1:]:
                return True
        elif host == s or host.endswith("." + s):
            return True
    return False


def _walk(details, path=""):
    """Yield (key, value) for every item inside nested dicts/lists."""
    if isinstance(details, dict):
        for k, v in details.items():
            if isinstance(v, (dict, list)):
                yield from _walk(v, k)
            else:
                yield k, v
    elif isinstance(details, list):
        for item in details:
            if isinstance(item, (dict, list)):
                yield from _walk(item, path)
            else:
                yield path, item


def validate_choice(scenario_id: str, policy: dict) -> list[str]:
    problems = []
    if scenario_id not in SCENARIOS:
        problems.append(f"unknown scenario '{scenario_id}'")
    if scenario_id in policy.get("blocked_scenarios", []):
        problems.append(f"scenario '{scenario_id}' is blocked by policy")
    return problems


def validate_events(events: list[dict], policy: dict, employee: Employee) -> list[str]:
    """Return a list of problems. An empty list means the events are safe to send."""
    problems: list[str] = []
    suffixes = policy["allowed_domain_suffixes"]
    users = set(employee.all_usernames()) | set(policy.get("extra_accounts", []))
    hosts = set(employee.all_hosts()) | set(policy.get("extra_hosts", []))

    if not events:
        problems.append("scenario produced no events")
    if len(events) > policy["max_events_per_scenario"]:
        problems.append(f"too many events ({len(events)} > {policy['max_events_per_scenario']})")

    for ev in events:
        if ev.get("simulated") is not True:
            problems.append("event is not marked simulated")
        if len(json.dumps(ev)) > policy["max_event_bytes"]:
            problems.append("event is too large")
        if ev["user"] not in users:
            problems.append(f"user '{ev['user']}' is not part of the fake company")
        if ev["host"] not in hosts:
            problems.append(f"host '{ev['host']}' is not part of the fake company")

        for key, value in _walk(ev["details"]):
            if not isinstance(value, str) or not value:
                continue
            if key.endswith(IP_KEYS_SUFFIX):
                try:
                    if ipaddress.ip_address(value).is_global:
                        problems.append(f"public IP address {value} is forbidden")
                except ValueError:
                    problems.append(f"'{value}' is not a valid IP address")
            elif key in DOMAIN_KEYS and not _domain_ok(value, suffixes):
                problems.append(f"domain '{value}' is not on the allowed fake-domain list")
            elif key == "qname" and not _domain_ok(value, suffixes):
                problems.append(f"DNS name '{value}' is not on the allowed fake-domain list")
            elif key in URL_KEYS or key in URL_LIST_KEYS:
                host = urlparse(value).hostname or ""
                if not _domain_ok(host, suffixes):
                    problems.append(f"URL host '{host}' is not on the allowed fake-domain list")
            elif key in EMAIL_KEYS and "@" in value:
                if not _domain_ok(value.rsplit("@", 1)[1], suffixes):
                    problems.append(f"email domain in '{value}' is not allowed")
    # report each distinct problem once
    return sorted(set(problems))


def validate_rate(attacks_last_hour: int, policy: dict) -> list[str]:
    limit = policy["max_attacks_per_hour"]
    if attacks_last_hour >= limit:
        return [f"hourly attack limit reached ({attacks_last_hour}/{limit})"]
    return []
