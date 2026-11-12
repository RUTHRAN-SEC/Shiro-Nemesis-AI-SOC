# 11 - Start everything automatically

## Ubuntu: Nemesis starts at boot (systemd)

1. Edit the service file so the paths match your laptop:

   ```bash
   nano scripts/nemesis.service
   ```

   Change `User=babyboss` and the three `/home/babyboss/...` paths if yours differ.

2. Install and start it:

   ```bash
   sudo cp scripts/nemesis.service /etc/systemd/system/nemesis.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now nemesis
   ```

3. Useful commands:

   ```bash
   systemctl status nemesis        # is it running?
   journalctl -u nemesis -f        # live log (Ctrl+C to leave)
   sudo systemctl stop nemesis     # stop
   sudo systemctl restart nemesis  # after editing .env
   sudo systemctl disable nemesis  # do not start at boot
   ```

If the ASUS laptop is off, Nemesis keeps working and saves events in `data/outbox/`. When Guardian returns, the next
cycle re-sends them.

## Windows: Guardian starts when you log in (Task Scheduler)

1. Press the Windows key, type **Task Scheduler**, open it.
2. **Create Basic Task** -> Name: `Guardian SOC`.
3. Trigger: **When I log on**.
4. Action: **Start a program**.
   * Program: `C:\Users\<you>\shiro-nemesis-ai-soc\.venv\Scripts\python.exe`
   * Arguments: `-m guardian.main`
   * Start in: `C:\Users\<you>\shiro-nemesis-ai-soc`
5. Finish. Right-click the task -> **Run** to test.

Open http://127.0.0.1:8000 to confirm. (Start in **must** be the project folder, or Guardian cannot find `.env`.)

## Daily routine (the game loop)

1. Start the ASUS laptop (Guardian starts) and the HP laptop (Nemesis starts).
2. Work as the analyst: open the dashboard, investigate the new alerts.
3. At the end of the day look at **Detection score** and **Reveal answer key**.

## Housekeeping

| Want to... | Do this |
|---|---|
| Start fresh on Windows | Stop Guardian, delete `data\guardian.db*` |
| Start fresh on Ubuntu | Stop Nemesis, delete `data/nemesis_memory.db*` and `data/outbox/` |
| Change attack speed | `SN_INTERVAL_SECONDS` in Ubuntu `.env` (1200 = 20 min) |
| Fewer pop-ups | `SN_MIN_TOAST_SEVERITY=high` in Windows `.env` |
| No decoys | `SN_INCLUDE_DECOYS=false` in Ubuntu `.env` |
