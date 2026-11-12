"""
Authentication & identity scenarios (5).
Evidence produced: Windows-style authentication and MFA logs.
"""
from attack_library.base import scenario


def _fail(ctx, user, ip, ago, method="rdp"):
    return ctx.event("auth", "login_failed",
                     {"src_ip": ip, "method": method, "reason": "bad_password"},
                     ago=ago, user=user, host="DC01")


@scenario(
    id="brute_force_login", name="Brute-force login attempts", category="identity",
    technique=("T1110.001", "Brute Force: Password Guessing"), severity="HIGH",
    description="An attacker guesses many passwords for Shiro's account. Sometimes one finally works.",
    objective="Test whether Guardian detects repeated failed logins (and a success after them).",
)
def brute_force_login(ctx):
    ip = ctx.external_ip()
    n = ctx.count(12, 40)
    events = [_fail(ctx, ctx.employee.username, ip, ago) for ago in ctx.spread(n, 90, end_ago=20)]
    if ctx.rng.random() < 0.4:  # sometimes the attacker gets lucky -> much worse
        events.append(ctx.event("auth", "login_success",
                                {"src_ip": ip, "method": "rdp", "country": "RO"}, ago=5, host="DC01"))
    return events


@scenario(
    id="password_spray", name="Password spraying", category="identity",
    technique=("T1110.003", "Brute Force: Password Spraying"), severity="HIGH",
    description="One attacker tries a common password against many different accounts, slowly.",
    objective="Test whether Guardian links failures across many users from one source.",
)
def password_spray(ctx):
    ip = ctx.external_ip()
    n_users = ctx.count(8, 15)
    users = ctx.rng.sample(ctx.employee.all_usernames(), min(n_users, len(ctx.employee.all_usernames())))
    if ctx.employee.username not in users:
        users[0] = ctx.employee.username
    events = []
    for user in users:
        for ago in ctx.spread(2, 20, end_ago=ctx.rng.uniform(5, 220)):
            events.append(_fail(ctx, user, ip, ago, method="vpn"))
    return events


@scenario(
    id="impossible_travel", name="Impossible travel login", category="identity",
    technique=("T1078", "Valid Accounts"), severity="HIGH",
    description="Shiro logs in from India, then minutes later 'he' logs in from another country.",
    objective="Test whether Guardian notices two far-apart logins that cannot both be real.",
)
def impossible_travel(ctx):
    country = ctx.rng.choice(["RO", "BR", "NG", "VN"])
    return [
        ctx.event("auth", "login_success",
                  {"src_ip": ctx.employee.workstation_ip, "method": "interactive", "country": "IN"},
                  ago=ctx.rng.uniform(600, 800), host="DC01"),
        ctx.event("auth", "login_success",
                  {"src_ip": ctx.external_ip(), "method": "vpn", "country": country},
                  ago=ctx.rng.uniform(10, 60), host="DC01"),
    ]


@scenario(
    id="mfa_fatigue", name="MFA fatigue (push bombing)", category="identity",
    technique=("T1621", "Multi-Factor Authentication Request Generation"), severity="HIGH",
    description="The attacker has Shiro's password and spams MFA prompts until he taps 'Approve'.",
    objective="Test whether Guardian detects floods of MFA prompts.",
)
def mfa_fatigue(ctx):
    ip = ctx.external_ip()
    n = ctx.count(6, 18)
    u = ctx.employee.username
    events = [
        ctx.event("auth", ctx.rng.choice(["mfa_denied", "mfa_timeout"]),
                  {"src_ip": ip, "method": "push"}, ago=ago, host="DC01")
        for ago in ctx.spread(n, 240, end_ago=40)
    ]
    if ctx.rng.random() < 0.6:
        events.append(ctx.event("auth", "mfa_approved", {"src_ip": ip, "method": "push"}, ago=15, host="DC01"))
        events.append(ctx.event("auth", "login_success",
                                {"src_ip": ip, "method": "vpn", "country": "NG"}, ago=10, host="DC01", user=u))
    return events


@scenario(
    id="privilege_escalation", name="Unexpected privilege escalation", category="identity",
    technique=("T1098", "Account Manipulation"), severity="CRITICAL",
    description="Shiro's normal account is suddenly added to the Domain Admins group by itself.",
    objective="Test whether Guardian notices privileged-group changes by non-admins.",
)
def privilege_escalation(ctx):
    u = ctx.employee.username
    return [
        ctx.event("endpoint", "process_start",
                  {"image": "C:\\Windows\\System32\\net.exe", "parent_image": "C:\\Windows\\System32\\cmd.exe",
                   "cmdline": "net group \"Domain Admins\" /domain"}, ago=ctx.rng.uniform(60, 120)),
        ctx.event("auth", "group_membership_change",
                  {"group": ctx.rng.choice(["Domain Admins", "Enterprise Admins", "Administrators"]),
                   "member": u, "changed_by": u, "change": "added"},
                  ago=ctx.rng.uniform(5, 40), host="DC01"),
    ]
