"""
Phase 1 milestone: Ubuntu sends a message -> Windows receives it -> Windows shows a pop-up.

Run on the UBUNTU laptop (Guardian must already be running on the ASUS laptop):

    python3 scripts/test_connection.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.client import GuardianClient  # noqa: E402
from config.settings import get_settings  # noqa: E402


def main() -> int:
    s = get_settings()
    print(f"Target: {s.guardian_url}")
    client = GuardianClient(s.guardian_url, s.token, s.outbox_dir, timeout=5)

    print("1) Can I reach Guardian? ...", end=" ")
    if not client.health():
        print("NO\n   -> Is Guardian running on the ASUS laptop? Is the firewall rule added? See docs/12-troubleshooting.md")
        return 1
    print("yes")

    print("2) Does Guardian accept my secret token? ...", end=" ")
    status, body = client.ping("Hello from the Ubuntu laptop - Nemesis is online!")
    if status == 401:
        print("NO\n   -> SN_TOKEN is different on the two laptops. Copy the same value to both .env files.")
        return 1
    if status != 200:
        print(f"unexpected answer {status}")
        return 1
    print(f"yes - Guardian replied: {body['reply']}")
    print("\nSUCCESS. Look at the ASUS laptop: a notification should have popped up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
