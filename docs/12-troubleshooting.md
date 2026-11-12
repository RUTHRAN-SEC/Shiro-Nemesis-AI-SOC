# 12 - Troubleshooting

Find your symptom, try the fixes in order.

## Connection problems

**`Can I reach Guardian? ... NO` (Ubuntu)**

1. Is Guardian running on Windows (the "Guardian SOC is starting" box)?
2. Is `SN_GUARDIAN_HOST` in the **Ubuntu** `.env` really the ASUS IP? On Windows run `ipconfig` and read the Wi-Fi *IPv4 Address*.
   Home routers can change it; consider a DHCP reservation in your router.
3. Did you run `open_firewall_windows.ps1` **as Administrator**, with `-UbuntuIp` = the Ubuntu IP (`hostname -I`)?
4. Test from Ubuntu: `curl http://192.168.1.5:8000/api/health` -> should print `{"status":"ok"}`.
   * Timeout -> firewall or router. Try on Windows: `Get-NetFirewallRule -DisplayName "Shiro Guardian*"`.
   * Connection refused -> Guardian is not running, or `SN_BIND_HOST` is `127.0.0.1` (must be `0.0.0.0` on Windows).
5. Some routers have **"AP/client isolation"** (often on guest Wi-Fi): devices cannot see each other. Use the main Wi-Fi
   for both laptops.
6. Are both laptops on the same network (`192.168.1.x`)?

**`Guardian rejected our token (401)`** - `SN_TOKEN` differs. Copy exactly, no quotes or spaces, then restart both sides.

**`SN_TOKEN is missing or too short` (Windows)** - run `scripts\generate_token.py` and paste into `.env` (min 16 characters).

## Windows

**`python` not recognized** - install Python from python.org; tick "Add python.exe to PATH"; reopen PowerShell.

**"running scripts is disabled"** - use `powershell -ExecutionPolicy Bypass -File ...` as in the guides.

**No pop-up but the console shows `[NOTIFY]`**

1. Settings -> System -> Notifications: notifications **On**; turn off **Do not disturb / Focus assist**.
2. `.\.venv\Scripts\python.exe -c "import winotify"` - if it errors, run
   `.\.venv\Scripts\python.exe -m pip install winotify`.
3. Lower `SN_MIN_TOAST_SEVERITY` (e.g. `low`).
4. Pop-ups are only a convenience: the alert is **always** on the dashboard.
5. If winotify is missing, Guardian automatically tries a built-in PowerShell pop-up instead; if both fail you still get the console line and the dashboard alert.

**Port 8000 already in use** - set `SN_GUARDIAN_PORT=8010` on **both** laptops (and re-run the firewall script with `-Port 8010`).

**Dashboard says "Dashboard is local-only"** - open `http://127.0.0.1:8000` **on the ASUS laptop**, not the 192.168 address.

## Ubuntu

**`python3-venv` missing** - `sudo apt install -y python3-venv`.

**`Another Nemesis is already running`** - a second copy holds the lock. `systemctl status nemesis` or `pkill -f nemesis.scheduler`.

**`Attack NOT executed: [...]`** - the Safety Validator blocked it; the list says why (e.g. a public IP in a scenario you edited).

**`hourly attack limit reached`** - safety limit (6 per hour). Raise `max_attacks_per_hour` in `config/safety_policy.json` only if you know why.

**Events pile up in `data/outbox/`** - Guardian was unreachable. They are re-sent automatically on the next cycle once it is back.

## Detection / dashboard

**No alerts appear** - 1) Check Guardian console for errors. 2) The scenario may be one of the 3 with **no rule** on purpose.
3) Look at **Shiro activity**: are events arriving?

**Alerts show wrong times** - both laptops need correct clocks. Ubuntu: `timedatectl`; Windows: Settings -> Time & language -> Sync now.
Timestamps are UTC.

**Dashboard blank / "cannot reach Guardian"** - Guardian stopped. Restart it.

**Tests fail on Python 3.14 install** - tests are optional; only `requirements-windows.txt` is needed to run the product.

## Still stuck?

Run `python -m pytest -q`. If tests pass, the code is fine and the problem is network, firewall or settings.
