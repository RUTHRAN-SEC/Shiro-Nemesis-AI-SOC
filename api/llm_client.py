"""
api/llm_client.py
=================
A tiny helper to ask Claude (Anthropic API) a question. Uses only the Python
standard library (urllib), so Ubuntu needs no extra packages.

IMPORTANT DESIGN RULE: AI is OPTIONAL.
If there is no API key, no internet, or the API fails, this returns None and the
caller uses its built-in rules instead. The project never depends on AI to work.
"""
from __future__ import annotations

import json
import logging
import urllib.request

log = logging.getLogger("llm")

API_URL = "https://api.anthropic.com/v1/messages"


def ask_claude(
    *,
    api_key: str,
    model: str,
    system: str,
    prompt: str,
    max_tokens: int = 600,
    timeout: float = 20.0,
) -> str | None:
    """Return Claude's text answer, or None if anything goes wrong."""
    if not api_key:
        return None
    body = json.dumps({
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }).encode("utf-8")
    req = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
        return text.strip() or None
    except Exception as exc:  # network down, bad key, rate limit ... all fine
        log.warning("LLM call failed (%s). Falling back to rules.", exc)
        return None
