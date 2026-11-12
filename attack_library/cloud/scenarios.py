"""
Cloud security scenarios (5).
Evidence produced: synthetic CloudTrail-style audit logs for a FAKE cloud account.
IMPORTANT: no real cloud account or API is ever contacted.
"""
from attack_library.base import scenario


def _cloud(ctx, event_name, ago, user="shiro.iam", user_type="IAMUser", ip=None, **extra):
    details = {"event_name": event_name, "user_type": user_type, "user_name": user,
               "src_ip": ip or ctx.external_ip(), "mfa_used": False, "region": "eu-north-1"}
    details.update(extra)
    return ctx.event("cloud", "cloud_api_call", details, ago=ago, user=user, host="aws-lab-account")


@scenario(
    id="iam_admin_policy_attached", name="Admin policy attached to a user", category="cloud",
    technique=("T1098.003", "Account Manipulation: Additional Cloud Roles"), severity="HIGH",
    description="Someone gives the IAM user 'shiro.iam' full AdministratorAccess.",
    objective="Test whether Guardian detects dangerous IAM permission changes.",
)
def iam_admin_policy_attached(ctx):
    return [_cloud(ctx, "AttachUserPolicy", ctx.rng.uniform(10, 60),
                   policy_arn="arn:aws:iam::aws:policy/AdministratorAccess", target_user="shiro.iam")]


@scenario(
    id="root_login_without_mfa", name="Root account login without MFA", category="cloud",
    technique=("T1078.004", "Valid Accounts: Cloud Accounts"), severity="CRITICAL",
    description="The all-powerful cloud root account signs in from an unknown address with no MFA.",
    objective="Test whether Guardian detects root logins without MFA.",
)
def root_login_without_mfa(ctx):
    return [_cloud(ctx, "ConsoleLogin", ctx.rng.uniform(10, 60), user="root", user_type="Root", mfa_used=False)]


@scenario(
    id="iam_access_key_created", name="New access key created for another user", category="cloud",
    technique=("T1098.001", "Account Manipulation: Additional Cloud Credentials"), severity="HIGH",
    description="A new long-lived access key is quietly created for a different IAM user (backdoor).",
    objective="Test whether Guardian detects new credentials created for other users (a known blind spot).",
)
def iam_access_key_created(ctx):
    return [_cloud(ctx, "CreateAccessKey", ctx.rng.uniform(10, 60), target_user="alice.iam")]


@scenario(
    id="s3_bucket_made_public", name="Storage bucket made public", category="cloud",
    technique=("T1530", "Data from Cloud Storage"), severity="HIGH",
    description="The 'shirotech-reports-lab' bucket is changed so that anyone on the internet can read it.",
    objective="Test whether Guardian detects buckets being opened to the public.",
)
def s3_bucket_made_public(ctx):
    return [_cloud(ctx, ctx.rng.choice(["PutBucketAcl", "PutBucketPolicy"]), ctx.rng.uniform(10, 60),
                   bucket="shirotech-reports-lab", public_access=True)]


@scenario(
    id="cloudtrail_logging_stopped", name="Audit logging switched off", category="cloud",
    technique=("T1562.008", "Impair Defenses: Disable Cloud Logs"), severity="CRITICAL",
    description="Someone turns off the audit trail - usually done right before doing something bad.",
    objective="Test whether Guardian detects attempts to blind the logs.",
)
def cloudtrail_logging_stopped(ctx):
    return [_cloud(ctx, ctx.rng.choice(["StopLogging", "DeleteTrail"]), ctx.rng.uniform(10, 60),
                   trail_name="shirotech-main-trail")]
