
from datetime import datetime, timedelta, timezone

from src.aws.iam import scan_iam_users
from src.security.finding import SecurityFinding


def scan_iam_security():
    users = scan_iam_users()
    findings = []

    for user in users:
        username = user["username"]

        # 1. Check MFA status
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

        # 2. Check attached policies
        for policy in user["attached_policies"]:
            policy_name = policy.get("PolicyName", "")

            if policy_name == "AdministratorAccess":
                findings.append(
                    SecurityFinding(
                        resource_id=username,
                        issue="ADMINISTRATOR_ACCESS",
                        severity="CRITICAL",
                        description=(
                            f"IAM user '{username}' has "
                            "AdministratorAccess policy attached."
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
                            f"IAM user '{username}' has directly "
                            f"attached policy '{policy_name}'."
                        ),
                    )
                )

        # 3. Check access key age
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
                key_id = access_key.get(
                    "AccessKeyId",
                    "Unknown",
                )

                findings.append(
                    SecurityFinding(
                        resource_id=username,
                        issue="OLD_ACCESS_KEY",
                        severity="HIGH",
                        description=(
                            f"IAM user '{username}' has an active "
                            f"access key older than 90 days: {key_id}."
                        ),
                    )
                )

    return findings
