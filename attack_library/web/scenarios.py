"""
Web application scenarios (5).
Evidence produced: web-server access logs for the company app (web-app-01).
IMPORTANT: these are fake log lines. No real web request is ever made.
"""
from attack_library.base import scenario

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"


def _req(ctx, ago, ip, method, path, query="", status=200, ua=BROWSER_UA, size=1200):
    host = ctx.employee.servers["web_app"]["host"]
    return ctx.event("web", "http_request",
                     {"src_ip": ip, "method": method, "uri": path, "query": query, "status": status,
                      "user_agent": ua, "response_bytes": size}, ago=ago, host=host, user="anonymous")


@scenario(
    id="sql_injection", name="SQL injection attempts", category="web",
    technique=("T1190", "Exploit Public-Facing Application"), severity="HIGH",
    description="Someone adds database commands to the product-search URL to try to read the database.",
    objective="Test whether Guardian detects SQL-injection patterns in web requests.",
)
def sql_injection(ctx):
    ip = ctx.external_ip()
    payloads = ["1' OR 1=1--", "1 UNION SELECT username,password FROM users--", "1'; DROP TABLE users;--",
                "1 AND SLEEP(5)--", "' OR '1'='1", "1 UNION SELECT table_name FROM information_schema.tables--"]
    n = ctx.count(5, 14)
    return [_req(ctx, ago, ip, "GET", "/products", f"id={ctx.rng.choice(payloads)}",
                 status=ctx.rng.choice([200, 500]), size=ctx.rng.randint(300, 90000))
            for ago in ctx.spread(n, 80, end_ago=10)]


@scenario(
    id="xss_attempt", name="Cross-site scripting (XSS) attempts", category="web",
    technique=("T1059.007", "Command and Scripting Interpreter: JavaScript"), severity="MEDIUM",
    description="Script tags are pushed into the comment form of the company site.",
    objective="Test whether Guardian detects script injection in web requests.",
)
def xss_attempt(ctx):
    ip = ctx.external_ip()
    payloads = ["<script>alert(1)</script>", "\"><img src=x onerror=alert(1)>", "<svg onload=alert(document.domain)>",
                "javascript:alert(1)"]
    n = ctx.count(3, 9)
    return [_req(ctx, ago, ip, "POST", "/comments", f"text={ctx.rng.choice(payloads)}", status=200)
            for ago in ctx.spread(n, 60, end_ago=10)]


@scenario(
    id="directory_traversal", name="Directory traversal", category="web",
    technique=("T1083", "File and Directory Discovery"), severity="MEDIUM",
    description="The attacker asks the download page for files outside its folder, such as /etc/passwd.",
    objective="Test whether Guardian detects '../' path tricks.",
)
def directory_traversal(ctx):
    ip = ctx.external_ip()
    paths = ["../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "..\\..\\windows\\win.ini",
             "../../../etc/shadow"]
    n = ctx.count(3, 8)
    return [_req(ctx, ago, ip, "GET", "/download", f"file={ctx.rng.choice(paths)}",
                 status=ctx.rng.choice([200, 403, 404])) for ago in ctx.spread(n, 50, end_ago=10)]


@scenario(
    id="credential_stuffing_web", name="Credential stuffing on the login page", category="web",
    technique=("T1110.004", "Brute Force: Credential Stuffing"), severity="HIGH",
    description="A bot tries many leaked username/password pairs against the company web login.",
    objective="Test whether Guardian detects floods of failed web logins.",
)
def credential_stuffing_web(ctx):
    ip = ctx.external_ip()
    n = ctx.count(25, 90)
    events = [_req(ctx, ago, ip, "POST", "/login", status=401, size=300) for ago in ctx.spread(n, 100, end_ago=15)]
    if ctx.rng.random() < 0.4:
        events.append(_req(ctx, 5, ip, "POST", "/login", status=302, size=0))
    return events


@scenario(
    id="automated_scanner_probe", name="Automated vulnerability scanner", category="web",
    technique=("T1595.002", "Active Scanning: Vulnerability Scanning"), severity="LOW",
    description="A scanning tool (named in its User-Agent) hunts for hidden admin pages and backup files.",
    objective="Test whether Guardian recognises well-known hacking tool signatures.",
)
def automated_scanner_probe(ctx):
    ip = ctx.external_ip()
    ua = ctx.rng.choice(["Nikto/2.5.0", "gobuster/3.6", "Mozilla/5.00 (Nikto/2.1.6)"])
    paths = ["/admin", "/backup.zip", "/.git/config", "/phpmyadmin", "/wp-login.php", "/.env", "/server-status"]
    n = ctx.count(15, 50)
    return [_req(ctx, ago, ip, "GET", ctx.rng.choice(paths), status=404, ua=ua, size=150)
            for ago in ctx.spread(n, 60, end_ago=10)]
