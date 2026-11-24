from src.security.finding import SecurityFinding


def scan_ec2_instances(instances):
    findings = []

    for instance in instances:
        if instance.get("public_ip"):
            findings.append(
                SecurityFinding(
                    resource_id=instance["id"],
                    issue="Public IP assigned",
                    severity="MEDIUM",
                    description=(
                        "EC2 instance has a public IP address. "
                        "Review its network access rules."
                    ),
                )
            )

    return findings


def scan_ec2_metadata_options(instances):
    """Flag instances that explicitly allow IMDSv1 instead of requiring IMDSv2."""
    findings = []

    for instance in instances:
        http_tokens = instance.get("metadata_http_tokens")

        # Missing metadata is treated as unknown, not as a confirmed failure.
        if http_tokens == "optional":
            findings.append(
                SecurityFinding(
                    resource_id=instance["id"],
                    issue="IMDSv2 not enforced",
                    severity="HIGH",
                    description=(
                        "The instance metadata endpoint allows IMDSv1. "
                        "Require IMDSv2 by setting HttpTokens to required."
                    ),
                )
            )

    return findings
