#!/usr/bin/env bash
# Start Nemesis (runs forever; Ctrl+C to stop).   bash scripts/run_nemesis.sh
cd "$(dirname "$0")/.."
exec .venv/bin/python -m nemesis.scheduler "$@"
