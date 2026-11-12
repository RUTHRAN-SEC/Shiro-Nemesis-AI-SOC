"""
guardian/ai_analyst.py
======================
The "AI SOC Analyst": explains an alert in plain English.

Two layers:
  1. build_analysis()   - ALWAYS works. Fills a standard report from the rule's built-in knowledge
                          (what happened, why suspicious, who is affected, MITRE technique, what to investigate,
                          how to fix). No internet or AI needed.
  2. ask_llm_briefing() - OPTIONAL. If an API key is set, Claude writes a short extra briefing that
                          reads the actual evidence. If it fails, the report from step 1 is still there.
"""
from __future__ import annotations

import json
import logging

from api.llm_client import ask_claude
from guardian.rules import Rule

log = logging.getLogger("ai_analyst")


def build_analysis(rule: Rule, summary: str, host: str, user: str, events: list[dict], severity: str) -> dict:
    return {
        "what_happened": summary,
        "why_suspicious": rule.why,
        "affected": f"user '{user}' on host '{host}'",
        "mitre": f"{rule.technique_id} - {rule.technique_name}",
        "evidence_count": len(events),
        "severity_reason": f"Rule {rule.id} starts at {rule.severity}; final severity is {severity}.",
        "investigate": rule.investigate,
        "remediate": rule.remediate,
    }


SYSTEM = (
    "You are a senior SOC analyst mentoring a junior analyst in a closed, simulated training lab (all data is fake). "
    "Write a short briefing (max 150 words, plain English, no markdown headings): what probably happened, what the "
    "attacker may do next, and the 3 most useful next steps. Use only the evidence given. If the evidence could be "
    "normal activity (for example an approved IT script, scan or backup), say so and explain how to check."
)


def ask_llm_briefing(settings, rule: Rule, alert_summary: str, events: list[dict]) -> str | None:
    evidence = [{"time": e["ts"], "source": e["source"], "host": e["host"], "user": e["user"],
                 "action": e["action"], "details": e["details"]} for e in events[:12]]
    prompt = (f"ALERT: {rule.title}\nSUMMARY: {alert_summary}\nMITRE: {rule.technique_id} {rule.technique_name}\n"
              f"EVIDENCE (first {len(evidence)} events):\n{json.dumps(evidence, indent=1)[:6000]}")
    return ask_claude(api_key=settings.anthropic_api_key, model=settings.ai_model, system=SYSTEM,
                      prompt=prompt, max_tokens=400, timeout=25)
