from datetime import datetime, timedelta, timezone

from src.aws.iam import scan_iam_users
from src.security.finding import SecurityFinding


HIGH_PRIVILEGE_POLICIES = {
    "AdministratorAccess",
    "PowerUserAccess",
}


def scan_iam_security():
    """Analyze IAM user security details and return findings."""
    users = scan_iam_users()
    findings = []

    for user in users:
        username = user["username"]

        # 1. Check MFA status.
        if not user["mfa_enabled"]:
            findings.append(
                SecurityFinding(
                    resource_id=username,
                    issue="MFA_NOT_ENABLED",
                    severity="HIGH",
                    description=(
                        f"IAM user '{username}' does not have MFA enabled."
                    ),
                )
            )

        # 2. Check directly attached managed policies.
        for policy in user["attached_policies"]:
            policy_name = policy.get("PolicyName", "")

            if policy_name in HIGH_PRIVILEGE_POLICIES:
                findings.append(
                    SecurityFinding(
                        resource_id=username,
                        issue="HIGH_PRIVILEGE_POLICY_ATTACHED",
                        severity="CRITICAL",
                        description=(
                            f"IAM user '{username}' has the high-privilege "
                            f"managed policy '{policy_name}' attached."
                        ),
                    )
                )
            elif policy_name:
                findings.append(
                    SecurityFinding(
                        resource_id=username,
                        issue="DIRECT_POLICY_ATTACHED",
                        severity="MEDIUM",
                        description=(
                            f"IAM user '{username}' has directly attached "
                            f"managed policy '{policy_name}'. Review whether "
                            "the permissions are required."
                        ),
                    )
                )

        # 3. Report inline policies for manual permission review.
        for policy_name in user.get("inline_policies", []):
            findings.append(
                SecurityFinding(
                    resource_id=username,
                    issue="INLINE_POLICY_REQUIRES_REVIEW",
                    severity="MEDIUM",
                    description=(
                        f"IAM user '{username}' has inline policy "
                        f"'{policy_name}'. Review its statements for "
                        "overly broad permissions."
                    ),
                )
            )

        # 4. Check active access keys older than 90 days.
        now = datetime.now(timezone.utc)
        key_age_limit = timedelta(days=90)

        for access_key in user["access_keys"]:
            if access_key.get("Status") != "Active":
                continue

            create_date = access_key.get("CreateDate")

            if create_date is None:
                continue

            if create_date.tzinfo is None:
                create_date = create_date.replace(
                    tzinfo=timezone.utc
                )

            if now - create_date > key_age_limit:
                key_id = access_key.get("AccessKeyId", "Unknown")

                findings.append(
                    SecurityFinding(
                        resource_id=username,
                        issue="OLD_ACCESS_KEY",
                        severity="HIGH",
                        description=(
                            f"IAM user '{username}' has an active access "
                            f"key older than 90 days: {key_id}."
                        ),
                    )
                )

    return findings
