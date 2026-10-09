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