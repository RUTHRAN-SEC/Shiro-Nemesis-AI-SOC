# 04 - Set up the ASUS Windows laptop (Guardian)

Your system: Windows 11, Python 3.13, Git 2.55, IP **192.168.1.5**.

## Step 1 - Get the project

Open **PowerShell** (Start menu -> type PowerShell):

```powershell
cd $HOME
git clone https://github.com/YOUR-USERNAME/shiro-nemesis-ai-soc.git
cd shiro-nemesis-ai-soc
```

(Or unzip the project zip into `C:\Users\<you>\shiro-nemesis-ai-soc`.)

## Step 2 - Run the setup script

```powershell
powershell -ExecutionPolicy Bypass -File scripts\setup_windows.ps1
```

Why `-ExecutionPolicy Bypass`? Windows blocks scripts by default. This flag allows **only this one run**; it does not
change your computer's settings.

It will create `.venv`, install FastAPI, Uvicorn and winotify, and create `.env`.

> If it says `python` is not found, install Python from python.org and tick **"Add python.exe to PATH"**, then reopen PowerShell.

## Step 3 - Make the secret token

```powershell
.\.venv\Scripts\python.exe scripts\generate_token.py
```

It prints a long random text. **Copy it.** This is the shared password between the two laptops.

## Step 4 - Edit the settings

```powershell
notepad .env
```

Set:

```
SN_TOKEN=paste-the-long-text-here
```

Leave the rest as it is. Save and close Notepad.

## Step 5 - Allow ONLY the Ubuntu laptop through the firewall

Close PowerShell. Open it again **as Administrator** (Start -> type PowerShell -> right-click -> *Run as administrator*):

```powershell
cd $HOME\shiro-nemesis-ai-soc
powershell -ExecutionPolicy Bypass -File scripts\open_firewall_windows.ps1 -UbuntuIp 192.168.1.9
```

This adds one rule: *"allow port 8000 only from 192.168.1.9"*. Everyone else on your Wi-Fi stays blocked.

## Step 6 - Start Guardian

Normal (non-admin) PowerShell:

```powershell
cd $HOME\shiro-nemesis-ai-soc
powershell -ExecutionPolicy Bypass -File scripts\run_guardian.ps1
```

You should see a box saying **Guardian SOC is starting**. If Windows Defender Firewall asks for permission for Python,
click **Cancel** (we already added a safer rule).

## Step 7 - Open the dashboard

In your browser: **http://127.0.0.1:8000**

You will see an empty "Alert queue". That is correct. Leave Guardian running.

> The dashboard only opens **on this laptop**. If you try `http://192.168.1.5:8000` from another device you get
> "Dashboard is local-only". This is on purpose (change with `SN_DASHBOARD_ALLOW_LAN=true`).

Next: [05-connect-the-laptops.md](05-connect-the-laptops.md).
