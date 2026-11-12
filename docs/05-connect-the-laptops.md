# 05 - Connect the two laptops (Phase 1 milestone)

Goal: **Ubuntu sends a message -> Windows receives it -> Windows shows a pop-up.**

## Step 1 - Check the laptops can see each other

On **Windows** (PowerShell):

```powershell
ping 192.168.1.9
```

On **Ubuntu**:

```bash
ping -c 4 192.168.1.5
```

Expected: replies and `0% packet loss`.
Note: Windows blocks ping by default, so Ubuntu -> Windows ping may fail even when everything is fine.
Ping from Windows to Ubuntu working is enough. Step 4 is the real test.

## Step 2 - Put the SAME token on Ubuntu

On Windows, show your token:

```powershell
findstr SN_TOKEN .env
```

On Ubuntu, edit `.env` and paste the **same** value:

```bash
nano .env
```

```
SN_GUARDIAN_HOST=192.168.1.5
SN_TOKEN=exactly-the-same-long-text-as-windows
```

## Step 3 - Make sure Guardian is running on Windows

You should see "Guardian SOC is starting" in the Windows PowerShell window. If not, run `scripts\run_guardian.ps1`.

## Step 4 - Send the first message

On **Ubuntu**:

```bash
.venv/bin/python scripts/test_connection.py
```

Expected:

```
1) Can I reach Guardian? ... yes
2) Does Guardian accept my secret token? ... yes - Guardian replied: pong
SUCCESS. Look at the ASUS laptop: a notification should have popped up.
```

On Windows you should see the message in PowerShell (`[NOTIFY] Nemesis connected ...`) and a pop-up in the corner.

## If something fails

| What you see | Meaning | Fix |
|---|---|---|
| `Can I reach Guardian? ... NO` | Network/firewall problem | Is Guardian running? Is the IP right? Did you run the firewall script as Administrator with the **Ubuntu IP**? See [12](12-troubleshooting.md) |
| `Does Guardian accept my token? ... NO` | Tokens differ | Copy the token again, no spaces or quotes |
| Message in PowerShell but no pop-up | Windows notification settings | See [12](12-troubleshooting.md) - alerts still appear on the dashboard |

## What just happened (simple explanation)

1. Ubuntu opened a connection to `192.168.1.5:8000`.
2. It sent `POST /api/ping` with the header `Authorization: Bearer <token>`.
3. Guardian compared the token. Correct -> it answered `pong` and asked Windows for a pop-up.
4. A wrong or missing token gets `401 Unauthorized`.

Next: [06-first-run.md](06-first-run.md).
