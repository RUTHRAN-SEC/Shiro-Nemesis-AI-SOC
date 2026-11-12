"""
shiro/employee.py
=================
Shiro - our fictional employee at the fictional company ShiroTech.

Shiro is just data: a name, an account, a workstation, a few coworkers and servers.
Nothing here touches the real computer. It is loaded from config/shiro_profile.json.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from config.settings import load_profile


@dataclass
class Employee:
    employee_id: str
    name: str
    department: str
    role: str
    username: str
    email: str
    workstation: str
    workstation_ip: str
    country: str
    status: str
    # Shiro's "security posture" - Nemesis can read this when planning.
    security_awareness: int = 60
    mfa_enabled: bool = True
    patch_level: str = "current"
    # The rest of the fake company
    company: str = "ShiroTech"
    coworkers: list[dict] = field(default_factory=list)
    servers: dict = field(default_factory=dict)
    executives: list[str] = field(default_factory=list)

    @property
    def domain(self) -> str:
        return self.email.split("@", 1)[1]

    def all_usernames(self) -> list[str]:
        return [self.username] + [c["username"] for c in self.coworkers]

    def all_hosts(self) -> list[str]:
        hosts = [self.workstation]
        for s in self.servers.values():
            hosts.append(s["host"])
        return hosts

    def to_dict(self) -> dict:
        return {
            "employee_id": self.employee_id, "name": self.name, "department": self.department,
            "role": self.role, "username": self.username, "workstation": self.workstation,
            "status": self.status, "security_awareness": self.security_awareness,
            "mfa_enabled": self.mfa_enabled, "patch_level": self.patch_level,
        }


def load_employee() -> Employee:
    p = load_profile()
    e = p["employee"]
    posture = p.get("posture", {})
    return Employee(
        employee_id=e["employee_id"], name=e["name"], department=e["department"], role=e["role"],
        username=e["username"], email=e["email"], workstation=e["workstation"],
        workstation_ip=e["workstation_ip"], country=e["country"], status=e["status"],
        security_awareness=posture.get("security_awareness", 60),
        mfa_enabled=posture.get("mfa_enabled", True),
        patch_level=posture.get("patch_level", "current"),
        company=p.get("company", "ShiroTech"),
        coworkers=p.get("coworkers", []),
        servers=p.get("servers", {}),
        executives=p.get("executives", []),
    )
