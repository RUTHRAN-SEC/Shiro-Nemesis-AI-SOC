"""
guardian/rules.py
=================
Guardian's DETECTION RULES. Each rule looks at recent events and answers:
"Do these events add up to something suspicious?"

A rule is made of two parts:
  1. A `check` function  -> finds suspicious patterns and returns "matches".
  2. Information for the analyst -> why it is suspicious, what to investigate, how to fix it.

Real SOC rules are not perfect, and neither are these:
  * Some attacks have NO rule on purpose (missed detections: qr_code_phishing,
    c2_beaconing, iam_access_key_created). Can you spot them manually?
  * Some rules fire on harmless activity (false positives: admin scripts,
    approved scans, planned backups). Investigate, then close them as false positives.

To add a rule, see docs/10-add-a-detection-rule.md.
"""
from __future__ import annotations

import ntpath
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable
from urllib.parse import unquote_plus

from config.settings import load_profile

INTERNAL_DOMAIN = "shirotech.local"


# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------
@dataclass
class Match:
    key: str                    # what the alert is "about" (user, IP, host...) - used to avoid duplicates
    event_ids: list[str]        # the evidence
    summary: str                # one sentence for the alert list
    bump: int = 0               # +1 raises the severity one level


@dataclass
class Rule:
    id: str
    title: str
    category: str               # Phishing & Email | Identity | Endpoint | Network | Web | Cloud
    technique_id: str
    technique_name: str
    severity: str
    why: str                    # why this is suspicious (plain English)
    investigate: list[str]
    remediate: list[str]
    check: Callable[[list[dict]], list[Match]]


def _t(e: dict) -> datetime:
    return datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))


def _ids(events: list[dict]) -> list[str]:
    return [e["event_id"] for e in events]


def _base(path: str | None) -> str:
    """File name (lower case) from a Windows path, e.g. 'C:\\x\\Cmd.EXE' -> 'cmd.exe'."""
    return ntpath.basename(path or "").lower()


def find_burst(events: list[dict], window_s: int, threshold: int) -> list[dict] | None:
    """First group of >= `threshold` events that all happen within `window_s` seconds."""
    times = [_t(e) for e in events]
    j = 0
    for i in range(len(events)):
        end = times[i] + timedelta(seconds=window_s)
        j = max(j, i)
        while j < len(events) and times[j] <= end:
            j += 1
        if j - i >= threshold:
            return events[i:j]
    return None


def _group(events, predicate, keyfn) -> dict:
    groups: dict = defaultdict(list)
    for e in events:
        if predicate(e):
            groups[keyfn(e)].append(e)
    return groups


def _exec_names() -> set[str]:
    return {x.split(" (")[0].lower() for x in load_profile().get("executives", [])}


# ---------------------------------------------------------------------------
# IDENTITY
# ---------------------------------------------------------------------------
def check_brute_force(events):
    out = []
    groups = _group(events, lambda e: e["action"] == "login_failed",
                    lambda e: (e["user"], e["details"].get("src_ip")))
    for (user, ip), evs in groups.items():
        burst = find_burst(evs, 120, 10)
        if not burst:
            continue
        last = burst[-1]["ts"]
        wins = [x for x in events if x["action"] == "login_success" and x["user"] == user
                and x["details"].get("src_ip") == ip and x["ts"] >= last]
        text = f"{len(burst)} failed logins for '{user}' from {ip} within 2 minutes"
        if wins:
            text += " - followed by a SUCCESSFUL login from the same address"
        out.append(Match(f"{user}|{ip}", _ids(burst) + _ids(wins), text, 1 if wins else 0))
    return out


def check_password_spray(events):
    out = []
    groups = _group(events, lambda e: e["action"] == "login_failed", lambda e: e["details"].get("src_ip"))
    for ip, evs in groups.items():
        burst = find_burst(evs, 300, 10)
        if not burst:
            continue
        users = {e["user"] for e in burst}
        if len(users) >= 5:
            out.append(Match(str(ip), _ids(burst),
                             f"{len(burst)} failed logins across {len(users)} different accounts from {ip}"))
    return out


def check_impossible_travel(events):
    out = []
    groups = _group(events, lambda e: e["action"] == "login_success" and e["details"].get("country"),
                    lambda e: e["user"])
    for user, evs in groups.items():
        for a, b in zip(evs, evs[1:]):
            minutes = (_t(b) - _t(a)).total_seconds() / 60
            if a["details"]["country"] != b["details"]["country"] and minutes < 60:
                out.append(Match(user, _ids([a, b]),
                                 f"'{user}' logged in from {a['details']['country']} and {minutes:.0f} minutes later "
                                 f"from {b['details']['country']}"))
                break
    return out


def check_mfa_fatigue(events):
    out = []
    groups = _group(events, lambda e: e["action"] in ("mfa_denied", "mfa_timeout"), lambda e: e["user"])
    for user, evs in groups.items():
        burst = find_burst(evs, 600, 5)
        if not burst:
            continue
        ok = [x for x in events if x["action"] == "mfa_approved" and x["user"] == user and x["ts"] >= burst[-1]["ts"]]
        text = f"{len(burst)} MFA prompts were denied or ignored for '{user}' within 10 minutes"
        if ok:
            text += " - then one was APPROVED"
        out.append(Match(user, _ids(burst) + _ids(ok), text, 1 if ok else 0))
    return out


PRIVILEGED_GROUPS = {"domain admins", "enterprise admins", "administrators", "schema admins"}
APPROVED_ADMINS = {"it.admin", "svc.provisioning"}


def check_privilege_escalation(events):
    out = []
    for e in events:
        d = e["details"]
        if (e["action"] == "group_membership_change" and str(d.get("group", "")).lower() in PRIVILEGED_GROUPS
                and d.get("changed_by") not in APPROVED_ADMINS):
            out.append(Match(f"{d.get('member')}|{d.get('group')}", [e["event_id"]],
                             f"'{d.get('member')}' was added to '{d.get('group')}' by '{d.get('changed_by')}', "
                             f"who is not an approved admin"))
    return out


# ---------------------------------------------------------------------------
# PHISHING & EMAIL
# ---------------------------------------------------------------------------
RISKY_EXT = {".docm", ".xlsm", ".pptm", ".js", ".vbs", ".iso", ".img", ".lnk", ".hta", ".exe", ".scr",
             ".bat", ".cmd", ".jar", ".ps1"}
DOC_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".png", ".jpg"}


def _risky_attachment(name: str) -> bool:
    low = name.lower()
    parts = low.rsplit(".", 2)
    if f".{parts[-1]}" in RISKY_EXT:
        return True
    # double extension such as "invoice.pdf.exe"
    return len(parts) == 3 and f".{parts[-2]}" in DOC_EXT and f".{parts[-1]}" in RISKY_EXT


def check_malicious_attachment(events):
    out = []
    for e in events:
        if e["action"] != "email_received":
            continue
        d = e["details"]
        bad = [a for a in d.get("attachment_names", []) if _risky_attachment(a)]
        if bad:
            auth_failed = d.get("spf") == "fail" or d.get("dkim") == "fail"
            text = f"Email from {d.get('from')} has risky attachment '{bad[0]}'"
            if auth_failed:
                text += " and failed sender checks (SPF/DKIM)"
            out.append(Match(e["event_id"], [e["event_id"]], text, 1 if auth_failed else 0))
    return out


def check_phishing_click(events):
    out = []
    for e in events:
        d = e["details"]
        if e["action"] == "url_click" and (
                d.get("reputation") in ("newly_registered", "suspicious", "phishing")
                or (isinstance(d.get("domain_age_days"), int) and d["domain_age_days"] < 30)):
            out.append(Match(d.get("domain", e["event_id"]), [e["event_id"]],
                             f"'{e['user']}' clicked a link to {d.get('domain')} "
                             f"(domain only {d.get('domain_age_days', '?')} days old)"))
    return out


BEC_WORDS = ("wire transfer", "gift card", "urgent payment", "change of bank", "bank details")


def check_bec(events):
    execs = _exec_names()
    out = []
    for e in events:
        if e["action"] != "email_received":
            continue
        d = e["details"]
        text = f"{d.get('subject', '')} {d.get('body_preview', '')}".lower()
        spoof = d.get("display_name", "").lower() in execs and d.get("from_domain") != INTERNAL_DOMAIN
        mismatch = bool(d.get("reply_to_domain")) and d.get("reply_to_domain") != d.get("from_domain")
        words = any(w in text for w in BEC_WORDS)
        if (spoof and (mismatch or words)) or (mismatch and words):
            out.append(Match(e["event_id"], [e["event_id"]],
                             f"Email pretends to be '{d.get('display_name')}' but comes from {d.get('from_domain')}; "
                             f"asks for money or secrecy"))
    return out


RISKY_SCOPES = {"mail.readwrite", "mail.send", "files.readwrite.all", "offline_access"}


def check_oauth_consent(events):
    out = []
    for e in events:
        d = e["details"]
        scopes = {str(s).lower() for s in d.get("scopes", [])}
        if e["action"] == "oauth_consent_granted" and not d.get("publisher_verified") and scopes & RISKY_SCOPES:
            out.append(Match(str(d.get("app_name")), [e["event_id"]],
                             f"'{e['user']}' granted risky permissions to unverified app '{d.get('app_name')}'"))
    return out


# ---------------------------------------------------------------------------
# ENDPOINT
# ---------------------------------------------------------------------------
PS_STRONG = [r"-enc(odedcommand)?\b", r"downloadstring", r"downloadfile", r"invoke-expression", r"\biex\b",
             r"frombase64string", r"-w(indowstyle)?\s+hidden", r"net\.webclient"]
PS_WEAK = [r"-executionpolicy\s+bypass", r"-ep\s+bypass", r"-nop\b", r"-noprofile"]


def check_powershell(events):
    groups = _group(events, lambda e: e["action"] == "process_start" and _base(e["details"].get("image")) in
                    ("powershell.exe", "pwsh.exe"), lambda e: e["host"])
    out = []
    for host, evs in groups.items():
        hits, strong = [], False
        for e in evs:
            cmd = str(e["details"].get("cmdline", "")).lower()
            if any(re.search(p, cmd) for p in PS_STRONG):
                hits.append(e)
                strong = True
            elif any(re.search(p, cmd) for p in PS_WEAK):
                hits.append(e)
        if hits:
            kind = "hidden/encoded/download-style" if strong else "policy-bypass"
            out.append(Match(host, _ids(hits), f"{len(hits)} {kind} PowerShell run(s) on {host}", 1 if strong else 0))
    return out


OFFICE = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}


def check_office_shell(events):
    groups = _group(events, lambda e: e["action"] == "process_start"
                    and _base(e["details"].get("parent_image")) in OFFICE
                    and _base(e["details"].get("image")) in SHELLS, lambda e: e["host"])
    return [Match(host, _ids(evs), f"Office program started a command shell on {host} ({_base(evs[0]['details']['image'])})")
            for host, evs in groups.items()]


LOCKED_EXT = (".locked", ".encrypted", ".crypt", ".enc", ".shiro_locked")


def check_ransomware(events):
    groups = _group(events, lambda e: e["action"] == "file_renamed"
                    and str(e["details"].get("new_name", "")).lower().endswith(LOCKED_EXT), lambda e: e["host"])
    out = []
    for host, evs in groups.items():
        burst = find_burst(evs, 60, 30)
        if burst:
            notes = [e for e in events if e["action"] == "file_created" and e["host"] == host
                     and re.search(r"readme|decrypt|recover|ransom", str(e["details"].get("name", "")), re.I)]
            text = f"{len(burst)} files renamed with an 'encrypted' extension on {host} within one minute"
            if notes:
                text += f"; ransom note '{notes[0]['details'].get('name')}' appeared"
            out.append(Match(host, _ids(burst) + _ids(notes), text))
    return out


def check_run_key(events):
    out = []
    for e in events:
        d = e["details"]
        key, val = str(d.get("key", "")).lower(), str(d.get("value_data", "")).lower()
        if e["action"] == "registry_set" and "\\currentversion\\run" in key and any(
                p in val for p in ("\\appdata\\", "\\temp\\", "\\programdata\\", "\\users\\public\\")):
            out.append(Match(e["event_id"], [e["event_id"]],
                             f"New autostart entry points to a user-writable folder: {d.get('value_data')}"))
    return out


LSASS_ALLOWED = {"msmpeng.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "lsm.exe"}


def check_lsass(events):
    out = []
    for e in events:
        d = e["details"]
        if e["action"] == "process_access" and _base(d.get("target_image")) == "lsass.exe" \
                and _base(d.get("source_image")) not in LSASS_ALLOWED:
            cmd = str(d.get("source_cmdline", "")).lower()
            out.append(Match(e["event_id"], [e["event_id"]],
                             f"{_base(d.get('source_image'))} accessed the memory of lsass.exe (password store)",
                             1 if ("comsvcs" in cmd or "procdump" in cmd) else 0))
    return out


# ---------------------------------------------------------------------------
# NETWORK
# ---------------------------------------------------------------------------
def check_port_scan(events):
    out = []
    groups = _group(events, lambda e: e["action"] == "net_connection",
                    lambda e: (e["details"].get("src_ip"), e["details"].get("dst_ip")))
    for (src, dst), evs in groups.items():
        burst = find_burst(evs, 30, 15)
        if burst and len({e["details"].get("dst_port") for e in burst}) >= 15:
            out.append(Match(f"{src}|{dst}", _ids(burst),
                             f"{src} touched {len({e['details'].get('dst_port') for e in burst})} different ports "
                             f"on {dst} within 30 seconds"))
    return out


def check_dns_tunnel(events):
    def base_domain(q):
        return ".".join(q.lower().strip(".").split(".")[-2:])

    groups = _group(events, lambda e: e["action"] == "dns_query"
                    and len(str(e["details"].get("qname", "")).split(".")[0]) >= 30,
                    lambda e: base_domain(str(e["details"].get("qname", ""))))
    out = []
    for domain, evs in groups.items():
        burst = find_burst(evs, 120, 20)
        if burst:
            out.append(Match(domain, _ids(burst),
                             f"{len(burst)} DNS queries with very long random names to '{domain}' within 2 minutes"))
    return out


def check_dos(events):
    groups = _group(events, lambda e: e["action"] == "traffic_sample" and e["details"].get("rps", 0) >= 2000,
                    lambda e: e["details"].get("server"))
    out = []
    for server, evs in groups.items():
        burst = find_burst(evs, 120, 5)
        if burst:
            peak = max(e["details"]["rps"] for e in burst)
            out.append(Match(str(server), _ids(burst),
                             f"Traffic to {server} spiked to {peak} requests/second (normal is under 100)"))
    return out


def check_exfiltration(events):
    out = []
    for e in events:
        d = e["details"]
        size = d.get("bytes_out", 0)
        if (e["action"] == "net_transfer" and d.get("direction") == "outbound" and d.get("dst_zone") == "external"
                and size >= 200 * 1024 * 1024):
            out.append(Match(f"{d.get('src_ip')}|{d.get('dst_ip')}|{e['event_id'][:8]}", [e["event_id"]],
                             f"{size / 1024 / 1024:.0f} MB sent from {d.get('src_ip')} to external {d.get('dst_ip')}",
                             1 if size >= 1024 ** 3 else 0))
    return out


# ---------------------------------------------------------------------------
# WEB
# ---------------------------------------------------------------------------
def _request_text(e: dict) -> str:
    d = e["details"]
    text = f"{d.get('uri', '')}?{d.get('query', '')}"
    return unquote_plus(unquote_plus(text)).lower()   # decode twice: attackers double-encode


def _web_pattern_rule(patterns: list[str], label: str):
    regexes = [re.compile(p) for p in patterns]

    def check(events):
        groups = _group(events, lambda e: e["action"] == "http_request"
                        and any(r.search(_request_text(e)) for r in regexes), lambda e: e["details"].get("src_ip"))
        return [Match(str(ip), _ids(evs), f"{len(evs)} {label} request(s) from {ip}") for ip, evs in groups.items()]

    return check


check_sqli = _web_pattern_rule(
    [r"union\s+select", r"\bor\s+1\s*=\s*1", r"'\s*or\s*'", r"sleep\(\d+\)", r"information_schema",
     r"drop\s+table", r"xp_cmdshell"], "SQL-injection")
check_xss = _web_pattern_rule([r"<script", r"onerror\s*=", r"onload\s*=", r"javascript:", r"<svg"], "script-injection")
check_traversal = _web_pattern_rule([r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow", r"win\.ini"],
                                    "directory-traversal")


def check_login_stuffing(events):
    out = []
    groups = _group(events, lambda e: e["action"] == "http_request" and e["details"].get("uri") == "/login"
                    and e["details"].get("method") == "POST", lambda e: e["details"].get("src_ip"))
    for ip, evs in groups.items():
        fails = [e for e in evs if e["details"].get("status") == 401]
        burst = find_burst(fails, 120, 20)
        if burst:
            won = [e for e in evs if e["details"].get("status") in (200, 302) and e["ts"] >= burst[-1]["ts"]]
            text = f"{len(burst)} failed web logins from {ip} within 2 minutes"
            if won:
                text += " - then one SUCCEEDED"
            out.append(Match(str(ip), _ids(burst) + _ids(won), text, 1 if won else 0))
    return out


SCANNER_RE = re.compile(r"nikto|sqlmap|nmap|gobuster|dirbuster|wfuzz|masscan|nessus")


def check_scanner_ua(events):
    groups = _group(events, lambda e: e["action"] == "http_request"
                    and SCANNER_RE.search(str(e["details"].get("user_agent", "")).lower()),
                    lambda e: e["details"].get("src_ip"))
    return [Match(str(ip), _ids(evs), f"{len(evs)} request(s) from {ip} using a known hacking-tool User-Agent "
                                      f"('{evs[0]['details'].get('user_agent')}')") for ip, evs in groups.items()]


# ---------------------------------------------------------------------------
# CLOUD
# ---------------------------------------------------------------------------
def _cloud_rule(predicate, text):
    def check(events):
        return [Match(f"{e['details'].get('event_name')}|{e['event_id'][:8]}", [e["event_id"]], text(e))
                for e in events if e["action"] == "cloud_api_call" and predicate(e["details"])]

    return check


check_iam_admin = _cloud_rule(
    lambda d: d.get("event_name") in ("AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "CreatePolicyVersion")
    and str(d.get("policy_arn", "")).endswith("AdministratorAccess"),
    lambda e: f"Full admin policy attached to '{e['details'].get('target_user')}' by '{e['user']}'")
check_root_no_mfa = _cloud_rule(
    lambda d: d.get("event_name") == "ConsoleLogin" and d.get("user_type") == "Root" and not d.get("mfa_used"),
    lambda e: f"Root account signed in without MFA from {e['details'].get('src_ip')}")
check_s3_public = _cloud_rule(
    lambda d: d.get("event_name") in ("PutBucketAcl", "PutBucketPolicy") and d.get("public_access") is True,
    lambda e: f"Bucket '{e['details'].get('bucket')}' was opened to the public internet")
check_trail_stopped = _cloud_rule(
    lambda d: d.get("event_name") in ("StopLogging", "DeleteTrail"),
    lambda e: f"Audit logging '{e['details'].get('trail_name')}' was switched off by '{e['user']}'")


# ---------------------------------------------------------------------------
# THE RULE TABLE
# ---------------------------------------------------------------------------
P, I, E, N, W, C = "Phishing & Email", "Identity", "Endpoint", "Network", "Web", "Cloud"

RULES: list[Rule] = [
    Rule("ID-001", "Multiple failed logins (brute force)", I, "T1110.001", "Brute Force: Password Guessing", "HIGH",
         "Many failed logins for one account in a short time usually means someone is guessing passwords.",
         ["Identify the targeted account and the source IP.", "Check authentication logs for a SUCCESS after the failures.",
          "Look up the source IP: is it internal, a VPN, or an unknown external address?"],
         ["Lock or reset the targeted account if a success followed.", "Block the source IP at the firewall.",
          "Enforce MFA and account lockout limits."], check_brute_force),
    Rule("ID-002", "Password spraying", I, "T1110.003", "Brute Force: Password Spraying", "HIGH",
         "One source trying a few passwords against MANY accounts avoids lockouts and is a classic attacker trick.",
         ["List every account that was targeted.", "Check whether any targeted account later logged in successfully.",
          "Check if the source IP appears in other alerts."],
         ["Reset passwords for any account that succeeded.", "Block the source IP.", "Ban common passwords."],
         check_password_spray),
    Rule("ID-003", "Impossible travel", I, "T1078", "Valid Accounts", "HIGH",
         "A person cannot be in two far-apart countries within an hour. One of the logins is probably stolen credentials.",
         ["Compare the two source IPs and countries.", "Ask the user whether they were travelling or using a VPN.",
          "Review what the account did after the second login."],
         ["Force a password reset and sign the user out everywhere.", "Require MFA for the account."],
         check_impossible_travel),
    Rule("ID-004", "MFA fatigue (push bombing)", I, "T1621", "Multi-Factor Authentication Request Generation", "HIGH",
         "Repeated MFA prompts the user did not start mean someone already knows the password and is hoping the user taps 'Approve'.",
         ["Confirm with the user whether they started any of the prompts.", "Check for an approved prompt or a login right after.",
          "Look at the source IP of the login attempts."],
         ["Reset the password immediately.", "Switch to number-matching MFA.", "Revoke active sessions."],
         check_mfa_fatigue),
    Rule("ID-005", "Privileged group change by non-admin", I, "T1098", "Account Manipulation", "CRITICAL",
         "Ordinary users should never add themselves to powerful groups. This gives an attacker full control.",
         ["Who made the change and from which host?", "Review what the account did just before and after.",
          "Check the change against approved change tickets."],
         ["Remove the account from the group.", "Disable the account and investigate how it was compromised."],
         check_privilege_escalation),
    Rule("PH-001", "Risky email attachment", P, "T1566.001", "Phishing: Spearphishing Attachment", "MEDIUM",
         "Macro documents, scripts and disk images are favourite ways to deliver malware, especially from senders that fail SPF/DKIM.",
         ["Inspect the sender, headers and attachment name (open the .json in data/shiro_mailbox/).",
          "Did the user open the file? Look for process or file-open events afterwards.",
          "Search the mail system for the same sender or attachment."],
         ["Delete the email from all mailboxes.", "Block the sender domain.", "Scan the workstation if the file was opened."],
         check_malicious_attachment),
    Rule("PH-002", "Click on newly registered domain", P, "T1566.002", "Phishing: Spearphishing Link", "HIGH",
         "Phishing sites are usually brand-new look-alike domains. Clicking one often means credentials may be stolen.",
         ["Find the email that contained the link.", "Check whether the user entered credentials on the page.",
          "Check DNS and web logs for other users visiting the domain."],
         ["Reset the user's password.", "Block the domain.", "Remove the phishing email from all mailboxes."],
         check_phishing_click),
    Rule("PH-003", "Executive impersonation / BEC", P, "T1656", "Impersonation", "HIGH",
         "The sender name matches an executive, but the email comes from an outside domain and asks for money or secrecy.",
         ["Compare the display name, from-domain and reply-to domain.", "Verify the request with the real executive by phone.",
          "Check whether anyone replied or paid."],
         ["Report and delete the email.", "Warn finance and HR teams.", "Block the sending domain."], check_bec),
    Rule("PH-004", "Risky app consent granted", P, "T1528", "Steal Application Access Token", "HIGH",
         "Unverified apps with mailbox and file permissions can read everything without needing the password.",
         ["Find which app was approved and who published it.", "Check what mail or files the app accessed afterwards.",
          "Look for the email or link that led to the consent."],
         ["Revoke the app's access immediately.", "Block consent to unverified apps."], check_oauth_consent),
    Rule("EP-001", "Suspicious PowerShell", E, "T1059.001", "Command and Scripting Interpreter: PowerShell", "MEDIUM",
         "Attackers use PowerShell with hidden windows, encoded commands or downloads to run malware without files.",
         ["Decode the command line (Base64) and read what it does.", "Find the parent process: who started PowerShell?",
          "Check if an approved admin script or change ticket explains it."],
         ["Isolate the workstation if malicious.", "Block the download address.", "Enable PowerShell script-block logging."],
         check_powershell),
    Rule("EP-002", "Office app started a command shell", E, "T1204.002", "User Execution: Malicious File", "HIGH",
         "Word or Excel should almost never start cmd or PowerShell. This is a classic malicious macro pattern.",
         ["Which document was open? Check recent file-open events.", "Follow the child processes that were started.",
          "Check the email that delivered the document."],
         ["Isolate the workstation.", "Block macros from the internet by policy."], check_office_shell),
    Rule("EP-003", "Mass file renaming (ransomware)", E, "T1486", "Data Encrypted for Impact", "CRITICAL",
         "Hundreds of files renamed to an 'encrypted' extension in seconds, plus a ransom note, means ransomware is running.",
         ["Disconnect the machine from the network NOW.", "Find the process responsible and its parent.",
          "Check other hosts for the same file extension."],
         ["Isolate the host.", "Restore files from clean backups.", "Reset credentials used on the host."],
         check_ransomware),
    Rule("EP-004", "New autostart entry in user folder", E, "T1547.001", "Boot or Logon Autostart: Registry Run Keys", "HIGH",
         "Malware adds itself to the Run key so it comes back after every reboot.",
         ["Inspect the file the key points to.", "Find which process created the key.", "Check when the file first appeared."],
         ["Remove the Run entry and the file.", "Scan the host for related malware."], check_run_key),
    Rule("EP-005", "Access to LSASS memory", E, "T1003.001", "OS Credential Dumping: LSASS Memory", "HIGH",
         "lsass.exe stores passwords in memory. Tools such as procdump or rundll32+comsvcs read it to steal them.",
         ["Identify the process that read lsass.exe and its command line.", "Check which accounts were logged in on the host.",
          "Look for lateral movement using those accounts."],
         ["Isolate the host.", "Reset passwords of all accounts that were logged in.", "Enable LSASS protection."],
         check_lsass),
    Rule("NW-001", "Port scan", N, "T1046", "Network Service Discovery", "MEDIUM",
         "One address touching many ports in seconds is mapping the target to find weak services.",
         ["Is the source internal or external? Is it an approved scanner (check change tickets)?",
          "Check if any connection was allowed, and look for later access from the same IP."],
         ["Block the source if not approved.", "Close unneeded ports."], check_port_scan),
    Rule("NW-002", "DNS tunneling", N, "T1071.004", "Application Layer Protocol: DNS", "HIGH",
         "Long random DNS names to one domain can carry stolen data or commands hidden inside DNS traffic.",
         ["Look at the queried domain: who owns it, how old is it?", "Find which process on the host sends the queries.",
          "Estimate how much data could have been sent."],
         ["Block the domain at the DNS resolver.", "Isolate and scan the source host."], check_dns_tunnel),
    Rule("NW-003", "Traffic spike (possible DoS)", N, "T1499", "Endpoint Denial of Service", "HIGH",
         "Request rates far above normal can knock a server offline.",
         ["Check how many unique sources are involved.", "Check server health and response times.",
          "Compare with marketing events or planned load tests."],
         ["Enable rate limiting or a DoS-protection service.", "Block abusive sources."], check_dos),
    Rule("NW-004", "Large outbound transfer", N, "T1048", "Exfiltration Over Alternative Protocol", "HIGH",
         "Hundreds of megabytes leaving to an outside address can be stolen data.",
         ["Who owns the destination address? Is it a known partner or backup provider?",
          "Which files or databases were accessed just before?", "Check for an approved backup job or ticket."],
         ["Block the destination if unapproved.", "Isolate the source host.", "Start the data-breach process if data left."],
         check_exfiltration),
    Rule("WB-001", "SQL injection attempt", W, "T1190", "Exploit Public-Facing Application", "HIGH",
         "Database commands inside web requests mean someone is trying to read or damage the database.",
         ["Check response codes and sizes: did any request succeed (200 + big response)?", "Review database logs.",
          "Search for the same source IP elsewhere."],
         ["Block the source IP.", "Fix the vulnerable page with parameterised queries.", "Enable a web application firewall."],
         check_sqli),
    Rule("WB-002", "Cross-site scripting attempt", W, "T1059.007", "Command and Scripting Interpreter: JavaScript", "MEDIUM",
         "Script tags in form fields try to run attacker code in other users' browsers.",
         ["Check whether the input was stored and shown to other users.", "Review the page's output encoding."],
         ["Block the source IP.", "Encode output and add a Content-Security-Policy."], check_xss),
    Rule("WB-003", "Directory traversal attempt", W, "T1083", "File and Directory Discovery", "MEDIUM",
         "'../' sequences try to escape the web folder and read system files.",
         ["Check for status 200 responses (file was served).", "Review which files were requested."],
         ["Block the source IP.", "Validate file paths on the server."], check_traversal),
    Rule("WB-004", "Web login flood (credential stuffing)", W, "T1110.004", "Brute Force: Credential Stuffing", "MEDIUM",
         "Many failed web logins from one source suggests a bot using leaked passwords.",
         ["Check for a successful login after the failures.", "Which accounts were targeted?"],
         ["Rate-limit the login page.", "Force resets for any compromised account.", "Add CAPTCHA or MFA."],
         check_login_stuffing),
    Rule("WB-005", "Hacking-tool User-Agent", W, "T1595.002", "Active Scanning: Vulnerability Scanning", "LOW",
         "Tools like Nikto and gobuster announce themselves. Someone is probing the site for weaknesses.",
         ["Which paths were requested?", "Did any return 200? Check for follow-up attacks from the same IP."],
         ["Block the source IP.", "Remove exposed admin or backup pages."], check_scanner_ua),
    Rule("CL-001", "Admin policy attached in cloud", C, "T1098.003", "Account Manipulation: Additional Cloud Roles", "HIGH",
         "Giving a user full AdministratorAccess lets them do anything in the cloud account.",
         ["Who attached the policy and from which IP?", "Check for an approved change ticket.", "Review what the user did afterwards."],
         ["Detach the policy.", "Rotate the keys of the acting user."], check_iam_admin),
    Rule("CL-002", "Root login without MFA", C, "T1078.004", "Valid Accounts: Cloud Accounts", "CRITICAL",
         "The root account is all-powerful and should be protected with MFA and almost never used.",
         ["Where did the login come from?", "Review every action taken in the session."],
         ["Reset the root password and enable MFA.", "Remove any root access keys."], check_root_no_mfa),
    Rule("CL-003", "Storage bucket made public", C, "T1530", "Data from Cloud Storage", "HIGH",
         "A public bucket exposes its files to the whole internet.",
         ["Which files are inside the bucket?", "Were they accessed by anonymous users?"],
         ["Block public access on the bucket.", "Review the change with the owner."], check_s3_public),
    Rule("CL-004", "Cloud audit logging stopped", C, "T1562.008", "Impair Defenses: Disable Cloud Logs", "CRITICAL",
         "Attackers switch logging off to hide what they do next.",
         ["Who stopped logging and from where?", "Review activity right after this event."],
         ["Turn logging back on immediately.", "Rotate credentials of the acting user."], check_trail_stopped),
]

RULES_BY_ID = {r.id: r for r in RULES}
