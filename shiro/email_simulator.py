"""
shiro/email_simulator.py
========================
Shiro's fake mailbox. Every email event is also saved as a small .json file in
`data/shiro_mailbox/`, so you (the SOC analyst) can open the "real" email and
inspect its headers while investigating an alert.
"""
from __future__ import annotations

import json
from pathlib import Path


class Mailbox:
    def __init__(self, folder: str | Path):
        self.folder = Path(folder)

    def deliver_from_events(self, events: list[dict]) -> int:
        """Save every 'email_received' event as a file. Returns how many were saved."""
        saved = 0
        for ev in events:
            if ev["action"] != "email_received":
                continue
            self.folder.mkdir(parents=True, exist_ok=True)
            path = self.folder / f"{ev['timestamp'].replace(':', '-')}_{ev['event_id'][:8]}.json"
            path.write_text(json.dumps({"received": ev["timestamp"], **ev["details"]}, indent=2), encoding="utf-8")
            saved += 1
        return saved
