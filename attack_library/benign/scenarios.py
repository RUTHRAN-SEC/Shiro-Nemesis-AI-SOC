"""
Benign DECOYS (4).
These are NOT attacks. They are normal-but-noisy things IT people really do.
Some of them look scary to a simple detection rule, so they create FALSE POSITIVES -
good practice for a SOC analyst: investigate, then close as 'false positive'.
"""
from attack_library.base import scenario


@scenario(
    id="benign_admin_script", name="[Decoy] IT automation script", category="benign",
    technique=("-", "Not an attack"), severity="LOW", is_attack=False,
    description="A scheduled IT clean-up script runs PowerShell with ExecutionPolicy Bypass.",
    objective="Check how Guardian handles legitimate admin automation (expect a false positive).",
)
def benign_admin_script(ctx):
    return [ctx.event("endpoint", "process_start",
                      {"image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       "parent_image": "C:\\Windows\\System32\\taskeng.exe",
                       "cmdline": "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\Scripts\\Cleanup-TempFiles.ps1",
                       "change_ticket": "CHG-1041"}, ago=ctx.rng.uniform(5, 60), user="svc.itautomation")]


@scenario(
    id="benign_typo_logins", name="[Decoy] Shiro mistypes his password", category="benign",
    technique=("-", "Not an attack"), severity="LOW", is_attack=False,
    description="Shiro fails to log in three times, then succeeds. Totally normal.",
    objective="Check that Guardian does NOT raise an alert for a few normal failures.",
)
def benign_typo_logins(ctx):
    ip = ctx.employee.workstation_ip
    events = [ctx.event("auth", "login_failed", {"src_ip": ip, "method": "interactive", "reason": "bad_password"},
                        ago=ago, host="DC01") for ago in ctx.spread(3, 40, end_ago=30)]
    events.append(ctx.event("auth", "login_success", {"src_ip": ip, "method": "interactive", "country": "IN"},
                            ago=10, host="DC01"))
    return events


@scenario(
    id="benign_vuln_scan", name="[Decoy] Approved internal vulnerability scan", category="benign",
    technique=("-", "Not an attack"), severity="LOW", is_attack=False,
    description="IT's own scanner (ITSCAN-01) checks the web server's ports during a planned maintenance window.",
    objective="Check how Guardian handles approved scans (expect a false positive).",
)
def benign_vuln_scan(ctx):
    scanner = ctx.employee.servers["scanner"]
    web = ctx.employee.servers["web_app"]
    ports = ctx.rng.sample(range(20, 9000), ctx.rng.randint(25, 60))
    return [ctx.event("network", "net_connection",
                      {"src_ip": scanner["ip"], "src_host": scanner["host"], "dst_ip": web["ip"], "dst_port": p,
                       "protocol": "tcp", "result": "allowed", "change_ticket": "CHG-1042"},
                      ago=ago, host="firewall-01", user="svc.itautomation")
            for p, ago in zip(ports, ctx.spread(len(ports), 20, end_ago=5))]


@scenario(
    id="benign_backup_transfer", name="[Decoy] Nightly backup to partner", category="benign",
    technique=("-", "Not an attack"), severity="LOW", is_attack=False,
    description="A big, planned backup upload to the company's external backup provider.",
    objective="Check how Guardian handles large but legitimate transfers (expect a false positive).",
)
def benign_backup_transfer(ctx):
    return [ctx.event("network", "net_transfer",
                      {"src_ip": ctx.employee.servers["file_server"]["ip"], "dst_ip": "198.51.100.77",
                       "dst_zone": "external", "direction": "outbound", "protocol": "sftp",
                       "bytes_out": ctx.rng.randint(400, 900) * 1024 * 1024, "job": "nightly-backup",
                       "partner_host": "backup.partner-backup.example"},
                      ago=ctx.rng.uniform(10, 60), host="firewall-01", user="svc.itautomation")]
