"""
Phishing & email scenarios (5).
Evidence produced: email-gateway logs, URL-click logs, cloud app-consent logs.
Everything uses reserved fake domains (.example / .invalid / .test).
"""
from attack_library.base import scenario


def _email(ctx, from_name, from_addr, subject, preview="", attachments=None, spf="pass", dkim="pass",
           reply_to=None, ago=200.0, **extra):
    """Helper: build one 'email_received' event."""
    from_domain = from_addr.split("@", 1)[1]
    details = {
        "from": from_addr, "from_domain": from_domain, "display_name": from_name,
        "to": ctx.employee.email, "subject": subject, "body_preview": preview,
        "attachment_names": attachments or [], "spf": spf, "dkim": dkim,
    }
    if reply_to:
        details["reply_to"] = reply_to
        details["reply_to_domain"] = reply_to.split("@", 1)[1]
    details.update(extra)
    return ctx.event("email", "email_received", details, ago=ago, host="mail-gateway")


@scenario(
    id="phish_malicious_attachment", name="Phishing email with macro attachment", category="phishing",
    technique=("T1566.001", "Phishing: Spearphishing Attachment"), severity="HIGH",
    description="Shiro gets an 'invoice' email with a risky attachment type and opens it.",
    objective="Test whether Guardian flags risky attachments from senders that fail SPF/DKIM.",
)
def phish_malicious_attachment(ctx):
    domain = ctx.rng.choice(["invoice-portal.example", "accounts-payable.test", "shirotech-hr.invalid"])
    n = ctx.rng.randint(1000, 9999)
    fname = ctx.rng.choice([f"Invoice_{n}.docm", f"Payroll_Update_{n}.xlsm", f"Scan_{n}.iso", f"Shipping_{n}.js"])
    subject = ctx.rng.choice(["Your invoice is attached", "Updated payroll sheet", "Your shipment is on hold"])
    return [
        _email(ctx, "Billing Team", f"billing@{domain}", subject, "Please open the attachment.",
               [fname], spf="fail", dkim="fail", ago=ctx.rng.uniform(150, 240)),
        ctx.event("endpoint", "file_opened",
                  {"path": f"C:\\Users\\{ctx.employee.username}\\Downloads\\{fname}",
                   "process": "explorer.exe"}, ago=ctx.rng.uniform(40, 100)),
    ]


@scenario(
    id="phish_credential_link", name="Credential-harvesting link", category="phishing",
    technique=("T1566.002", "Phishing: Spearphishing Link"), severity="HIGH",
    description="Shiro receives a 'password expires' email and clicks a link to a brand-new look-alike domain.",
    objective="Test whether Guardian notices clicks on newly registered domains.",
)
def phish_credential_link(ctx):
    domain = ctx.rng.choice(["shirotech-login.example", "m365-secure-signin.test", "sso-shirotech.invalid"])
    url = f"https://{domain}/signin?session={ctx.rng.randint(100000, 999999)}"
    return [
        _email(ctx, "IT Helpdesk", f"helpdesk@{domain}", "Your password expires today",
               "Click here to keep your password.", urls=[url], ago=ctx.rng.uniform(200, 300)),
        ctx.event("dns", "dns_query", {"qname": domain, "qtype": "A", "src_ip": ctx.employee.workstation_ip},
                  ago=ctx.rng.uniform(60, 90), host="dns-resolver-01"),
        ctx.event("web", "url_click",
                  {"url": url, "domain": domain, "domain_age_days": ctx.rng.randint(0, 5),
                   "reputation": "newly_registered", "referrer": "mail"}, ago=ctx.rng.uniform(30, 55)),
    ]


@scenario(
    id="bec_ceo_fraud", name="CEO impersonation (business email compromise)", category="phishing",
    technique=("T1656", "Impersonation"), severity="HIGH",
    description="An email pretending to be the CEO urgently asks Shiro to arrange a payment.",
    objective="Test whether Guardian spots spoofed executive names and reply-to mismatches.",
)
def bec_ceo_fraud(ctx):
    exec_name = ctx.rng.choice(ctx.employee.executives).split(" (")[0]
    domain = ctx.rng.choice(["shirotech-ceo.example", "shiro-tech-mail.test"])
    return [
        _email(ctx, exec_name, f"ceo@{domain}", "Urgent payment needed today",
               "I need a wire transfer to a new supplier. Keep this confidential. Buy gift cards if the bank is closed.",
               reply_to="ceo.private@mail-reply.invalid", ago=ctx.rng.uniform(100, 200)),
    ]


@scenario(
    id="qr_code_phishing", name="QR-code phishing (quishing)", category="phishing",
    technique=("T1566", "Phishing"), severity="MEDIUM",
    description="An image-only email contains a QR code that points to a fake login page. No links, no attachment risk.",
    objective="Test whether Guardian can see threats hidden inside images (a known blind spot).",
)
def qr_code_phishing(ctx):
    domain = ctx.rng.choice(["secure-docs.example", "hr-benefits.test"])
    return [
        _email(ctx, "Benefits Portal", f"no-reply@{domain}", "Action needed: re-enable your sign-in",
               "(image only)", attachments=["scan_me.png"], images_only=True,
               qr_url_domain="qr-login-shirotech.invalid", ago=ctx.rng.uniform(100, 200)),
    ]


@scenario(
    id="oauth_consent_phish", name="Malicious app consent request", category="phishing",
    technique=("T1528", "Steal Application Access Token"), severity="HIGH",
    description="Shiro is tricked into granting a look-alike 'document viewer' app access to his mailbox and files.",
    objective="Test whether Guardian notices risky consent grants to unverified apps.",
)
def oauth_consent_phish(ctx):
    domain = "sharepoint-share.example"
    return [
        _email(ctx, "SharePoint Share", f"share@{domain}", "A document was shared with you",
               "Open the shared document.", ago=ctx.rng.uniform(120, 200)),
        ctx.event("cloud", "oauth_consent_granted",
                  {"app_name": ctx.rng.choice(["DocViewer Pro", "SecureShare Reader", "FastPDF Sign"]),
                   "publisher_verified": False,
                   "scopes": ["Mail.ReadWrite", "Files.ReadWrite.All", "offline_access"],
                   "src_ip": ctx.employee.workstation_ip}, ago=ctx.rng.uniform(20, 60),
                  host="aws-lab-account"),
    ]
