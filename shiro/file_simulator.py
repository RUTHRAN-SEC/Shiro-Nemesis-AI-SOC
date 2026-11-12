"""
shiro/file_simulator.py
=======================
Creates a small folder of DUMMY documents for Shiro (plain text files that only
say "dummy file"). They give the fake company some realistic-looking files to
look at. No attack ever modifies or deletes them - attacks only write log lines.
"""
from __future__ import annotations

from pathlib import Path

DUMMY_FILES = [
    "HR/employee_handbook.txt", "HR/payroll_2026.txt", "Finance/Q3_report.txt", "Finance/budget_draft.txt",
    "Projects/network_upgrade_plan.txt", "Projects/helpdesk_runbook.txt", "IT/asset_list.txt", "IT/vpn_guide.txt",
]


def ensure_dummy_files(folder: str | Path) -> int:
    """Create the dummy files if they do not exist. Returns how many were created."""
    root = Path(folder)
    created = 0
    for rel in DUMMY_FILES:
        path = root / rel
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(f"DUMMY FILE for ShiroTech lab: {rel}\nNot real company data.\n", encoding="utf-8")
            created += 1
    return created
