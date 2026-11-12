"""
api/client.py
=============
How Nemesis (Ubuntu) talks to Guardian (Windows).

Features:
  * Sends the secret token on every request.
  * Uses timeouts, so a dead laptop can never freeze Nemesis.
  * If Guardian is unreachable, saves the data to an "outbox" folder and
    re-sends it later (nothing is lost if the ASUS laptop is asleep).
  * Standard library only (urllib) -> no pip packages needed on Ubuntu.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

log = logging.getLogger("client")

CHUNK_SIZE = 200  # events per HTTP request


class GuardianUnreachable(Exception):
    """Raised when we could not connect at all (offline, wrong IP, firewall...)."""


class GuardianClient:
    def __init__(self, base_url: str, token: str, outbox_dir: str | Path, timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.outbox = Path(outbox_dir)
        self.timeout = timeout

    # ---- low level -------------------------------------------------------
    def _request(self, method: str, path: str, payload: dict | None = None, auth: bool = True):
        """Returns (status_code, parsed_json_or_None). Raises GuardianUnreachable on network failure."""
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(self.base_url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
                return resp.status, (json.loads(raw) if raw else None)
        except urllib.error.HTTPError as err:  # server answered with 4xx/5xx
            try:
                body = json.loads(err.read().decode("utf-8"))
            except Exception:
                body = None
            return err.code, body
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as err:
            raise GuardianUnreachable(str(err)) from err

    def _spool(self, kind: str, payload: dict) -> None:
        """Save a failed request to disk so we can retry it later."""
        self.outbox.mkdir(parents=True, exist_ok=True)
        name = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}-{kind}.json"
        (self.outbox / name).write_text(json.dumps({"kind": kind, "payload": payload}), encoding="utf-8")
        log.warning("Guardian unreachable - saved %s to outbox (%s)", kind, name)

    # ---- public API ------------------------------------------------------
    def health(self) -> bool:
        try:
            status, _ = self._request("GET", "/api/health", auth=False)
            return status == 200
        except GuardianUnreachable:
            return False

    def ping(self, message: str) -> tuple[int, dict | None]:
        """Authenticated test message (used by scripts/test_connection.py)."""
        return self._request("POST", "/api/ping", {"message": message})

    def send_events(self, events: list[dict]) -> bool:
        """Send events in chunks. Returns True if ALL chunks were delivered."""
        ok = True
        for i in range(0, len(events), CHUNK_SIZE):
            if not self._send("events", {"events": events[i : i + CHUNK_SIZE]}, "/api/events"):
                ok = False
        return ok

    def send_ground_truth(self, attack: dict) -> bool:
        return self._send("ground_truth", {"attack": attack}, "/api/ground-truth")

    def _send(self, kind: str, payload: dict, path: str) -> bool:
        try:
            status, _ = self._request("POST", path, payload)
        except GuardianUnreachable:
            self._spool(kind, payload)
            return False
        if status == 401:
            log.error("Guardian rejected our token (401). Check SN_TOKEN on both laptops.")
            return False  # do not spool: retrying will not help
        return status == 200

    def get_attack_result(self, attack_id: str) -> dict | None:
        """Ask Guardian whether it detected this attack (this is how Nemesis learns)."""
        try:
            status, body = self._request("GET", f"/api/attacks/{attack_id}/result")
            return body if status == 200 else None
        except GuardianUnreachable:
            return None

    def flush_outbox(self) -> int:
        """Try to re-send everything in the outbox. Returns how many files were delivered."""
        if not self.outbox.exists():
            return 0
        sent = 0
        for f in sorted(self.outbox.glob("*.json")):
            try:
                item = json.loads(f.read_text(encoding="utf-8"))
                path = "/api/events" if item["kind"] == "events" else "/api/ground-truth"
                status, _ = self._request("POST", path, item["payload"])
            except GuardianUnreachable:
                break  # Guardian still offline; try next cycle
            except (OSError, ValueError, KeyError):
                f.unlink(missing_ok=True)
                continue
            if status in (200, 401, 413, 422):
                f.unlink(missing_ok=True)  # delivered, or it can never succeed
                sent += 1 if status == 200 else 0
        return sent
