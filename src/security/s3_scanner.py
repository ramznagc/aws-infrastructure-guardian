from src.security.finding import SecurityFinding


def scan_s3_buckets(buckets):
    findings = []

    for bucket in buckets:
        bucket_name = bucket.get("Name", "unknown")

        public_access_block = bucket.get(
            "PublicAccessBlock", {}
        )

        policy_status = bucket.get("PolicyStatus", {})
        bucket_policy = bucket.get("Policy", {})

        # 1. Detect publicly accessible buckets
        if policy_status.get("IsPublic", False):
            findings.append(
                SecurityFinding(
                    resource_id=bucket_name,
                    issue="Public S3 bucket",
                    severity="CRITICAL",
                    description=(
                        "S3 bucket is publicly accessible. "
                        "Review its access policy and permissions."
                    ),
                )
            )

        # 2. Detect disabled or missing public access protections
        protection_settings = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]

        protection_disabled = any(
            public_access_block.get(setting) is not True
            for setting in protection_settings
        )

        if protection_disabled:
            findings.append(
                SecurityFinding(
                    resource_id=bucket_name,
                    issue="S3 public access block disabled",
                    severity="HIGH",
                    description=(
                        "One or more S3 Public Access Block "
                        "settings are disabled or missing."
                    ),
                )
            )

        # 3. Detect risky bucket policies
        for statement in bucket_policy.get("Statement", []):
            principal = statement.get("Principal")
            effect = statement.get("Effect")

            if effect == "Allow" and principal == "*":
                findings.append(
                    SecurityFinding(
                        resource_id=bucket_name,
                        issue="Risky S3 bucket policy",
                        severity="HIGH",
                        description=(
                            "Bucket policy grants access to all "
                            "principals. Review the policy."
                        ),
                    )
                )
                break

        # 4. Detect missing encryption
        if bucket.get("Encryption") is not True:
            findings.append(
                SecurityFinding(
                    resource_id=bucket_name,
                    issue="S3 bucket encryption disabled",
                    severity="HIGH",
                    description=(
                        "S3 bucket does not have default encryption "
                        "enabled."
                    ),
                )
            )

    return findings