"""
shiro/activity.py
=================
Shiro's NORMAL day: logging in, opening files, reading email, browsing.

Why this matters: if every event were suspicious, detection would be too easy.
A real SOC drowns in normal noise, so we make some noise too. None of this
should ever trigger a Guardian alert (the tests check that).
"""
from __future__ import annotations

from attack_library.base import ScenarioContext

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"
SYS = "C:\\Windows\\System32\\"
APPS = ["chrome.exe", "outlook.exe", "teams.exe", "code.exe", "excel.exe", "winword.exe", "onenote.exe"]
SAFE_DOMAINS = ["intranet.shirotech.local", "mail.shirotech.local", "wiki.shirotech.local",
                "news.example.com", "docs.example.org", "tickets.shirotech.local"]
DOC_NAMES = ["Q3_report.xlsx", "Onboarding_guide.pdf", "Network_diagram.pptx", "Meeting_notes.docx",
             "Asset_list.xlsx", "Helpdesk_runbook.docx", "Budget_draft.xlsx"]


def normal_activity(ctx: ScenarioContext, n: int | None = None) -> list[dict]:
    """Return n harmless events from Shiro's ordinary working day."""
    e = ctx.employee
    n = n if n is not None else ctx.rng.randint(6, 14)
    events: list[dict] = []
    for ago in ctx.spread(n, 600, end_ago=ctx.rng.uniform(150, 300)):
        kind = ctx.rng.choice(["login", "file", "app", "dns", "mail", "web", "web"])
        if kind == "login":
            events.append(ctx.event("auth", "login_success",
                                    {"src_ip": e.workstation_ip, "method": "interactive", "country": e.country},
                                    ago=ago, host="DC01"))
        elif kind == "file":
            events.append(ctx.event("endpoint", "file_opened",
                                    {"path": f"\\\\fileserver-01\\shared\\{ctx.rng.choice(DOC_NAMES)}",
                                     "process": "explorer.exe"}, ago=ago))
        elif kind == "app":
            app = ctx.rng.choice(APPS)
            events.append(ctx.event("endpoint", "process_start",
                                    {"image": f"C:\\Program Files\\{app}", "parent_image": "C:\\Windows\\explorer.exe",
                                     "cmdline": app}, ago=ago))
        elif kind == "dns":
            events.append(ctx.event("dns", "dns_query",
                                    {"qname": ctx.rng.choice(SAFE_DOMAINS), "qtype": "A", "src_ip": e.workstation_ip},
                                    ago=ago, host="dns-resolver-01"))
        elif kind == "mail":
            colleague = ctx.rng.choice(e.coworkers)
            events.append(ctx.event("email", "email_received",
                                    {"from": f"{colleague['username']}@{e.domain}", "from_domain": e.domain,
                                     "display_name": colleague["name"], "to": e.email,
                                     "subject": ctx.rng.choice(["Lunch?", "Meeting notes", "Ticket update", "FYI"]),
                                     "body_preview": "Hi Shiro, quick note.", "spf": "pass", "dkim": "pass",
                                     "attachment_names": ctx.rng.choice([[], [], ["Meeting_notes.pdf"]])},
                                    ago=ago, host="mail-gateway"))
        else:
            events.append(ctx.event("web", "http_request",
                                    {"src_ip": e.workstation_ip, "method": "GET", "uri": "/tickets",
                                     "query": f"page={ctx.rng.randint(1, 5)}", "status": 200,
                                     "user_agent": BROWSER_UA, "response_bytes": ctx.rng.randint(800, 9000)},
                                    ago=ago, host=e.servers["web_app"]["host"]))
    return events
