"""
notifications/windows_toast.py
==============================
Shows a pop-up ("toast") in the bottom-right corner of Windows 11.

Tries, in order:
  1. winotify   (pip package, installed by requirements-windows.txt)  - nicest
  2. PowerShell (built into Windows, needs nothing)                    - fallback
  3. print()    (on Linux/mac, or if everything fails)                 - always works

The alert is ALWAYS saved in the database; the pop-up is only a convenience.
"""
from __future__ import annotations

import logging
import os
import subprocess
import sys

log = logging.getLogger("toast")

APP_ID = "Shiro Guardian SOC"

# The text is passed through environment variables, NOT pasted into the script,
# so odd characters in an alert can never be run as PowerShell code.
_PS_SCRIPT = r"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null
$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02)
$n = $t.GetElementsByTagName('text')
$n.Item(0).AppendChild($t.CreateTextNode($env:SG_TITLE)) > $null
$n.Item(1).AppendChild($t.CreateTextNode($env:SG_MESSAGE)) > $null
$toast = [Windows.UI.Notifications.ToastNotification]::new($t)
[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($env:SG_APPID).Show($toast)
"""


def notify(title: str, message: str) -> None:
    """Show a desktop notification. Never raises."""
    print(f"[NOTIFY] {title} | {message}", flush=True)       # always visible in the console too
    if sys.platform != "win32":
        return
    try:
        from winotify import Notification  # type: ignore

        Notification(app_id=APP_ID, title=title, msg=message, duration="short").show()
        return
    except Exception as exc:
        log.debug("winotify not available (%s) - using PowerShell", exc)
    try:
        env = {**os.environ, "SG_TITLE": title, "SG_MESSAGE": message, "SG_APPID": APP_ID}
        subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT],
                       env=env, timeout=15, check=False, capture_output=True,
                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception as exc:
        log.warning("Could not show toast: %s", exc)
