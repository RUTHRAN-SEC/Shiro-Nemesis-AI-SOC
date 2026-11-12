#!/usr/bin/env bash
# One-time setup for the HP Ubuntu laptop (Nemesis + Shiro).
# Run from the project folder:   bash scripts/setup_ubuntu.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> Checking Python"
python3 --version
if ! python3 -c "import venv, ensurepip" 2>/dev/null; then
  echo "python3-venv is missing. Install it with:  sudo apt install -y python3-venv"
  exit 1
fi

echo "==> Creating virtual environment (.venv)"
python3 -m venv .venv
# Ubuntu side needs no third-party packages, but keep the same step on both laptops.
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements-ubuntu.txt

if [ ! -f .env ]; then
  cp .env.example .env
  echo "==> Created .env from .env.example  (now edit it: nano .env)"
else
  echo "==> .env already exists - leaving it alone"
fi

mkdir -p data
echo
echo "Done. Next steps:"
echo "  1) nano .env            (set SN_GUARDIAN_HOST and SN_TOKEN)"
echo "  2) .venv/bin/python scripts/test_connection.py"
echo "  3) .venv/bin/python -m nemesis.scheduler --once"
