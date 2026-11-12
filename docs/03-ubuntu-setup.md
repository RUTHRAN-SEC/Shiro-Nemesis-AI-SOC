# 03 - Set up the HP Ubuntu laptop (Nemesis + Shiro)

Your system (from your checks): Ubuntu 26.04.1, Python 3.14.4, Git 2.53, IP **192.168.1.9**.
This laptop needs **no pip packages**, so the new Python version is not a problem.

## Step 1 - Install what is missing

```bash
sudo apt update
sudo apt install -y python3-venv git
```

`python3-venv` lets us make a private Python box (a "virtual environment") for the project.

## Step 2 - Get the project

```bash
cd ~
git clone https://github.com/YOUR-USERNAME/shiro-nemesis-ai-soc.git
cd shiro-nemesis-ai-soc
```

(Or unzip the project zip into `~/shiro-nemesis-ai-soc`.)

## Step 3 - Run the setup script

```bash
bash scripts/setup_ubuntu.sh
```

It will: check Python, create `.venv`, and copy `.env.example` to `.env`.

## Step 4 - Edit the settings

```bash
nano .env
```

Change only these lines for now:

```
SN_GUARDIAN_HOST=192.168.1.5        # the ASUS laptop's IP (check with ipconfig on Windows)
SN_TOKEN=                           # leave empty until you do doc 05, then paste the token
```

Save in nano: `Ctrl+O`, `Enter`, then `Ctrl+X`.

## Step 5 - Check that Nemesis works (no network needed)

```bash
.venv/bin/python -m nemesis.scheduler --list
```

You should see a table of **34 scenarios**. Now do a **dry run**: it creates and safety-checks an attack but sends nothing.

```bash
.venv/bin/python -m nemesis.scheduler --once --dry-run --scenario password_spray
```

Look for a line ending in `delivered=False | result: (dry run)`. Nemesis is ready.

## Step 6 - (Optional) run the tests

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest -q
```

Expected: `433 passed`. If a package fails to install on Python 3.14, skip this step; the tests are optional.

## What Ubuntu will run later

* `python -m nemesis.scheduler` - the attacker loop.
* Nothing else. Guardian and the dashboard live on the ASUS laptop.

Next: [04-windows-setup.md](04-windows-setup.md).
