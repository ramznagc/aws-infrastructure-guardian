from src.security.finding import SecurityFinding


def scan_rds_instances(instances):
    """Return security findings for RDS DB instance configuration."""
    findings = []

    for instance in instances:
        db_id = instance.get("DBInstanceIdentifier", "unknown")

        if instance.get("PubliclyAccessible") is True:
            findings.append(
                SecurityFinding(
                    resource_id=db_id,
                    issue="RDS instance publicly accessible",
                    severity="CRITICAL",
                    description=(
                        f"RDS instance '{db_id}' is publicly accessible. "
                        "Restrict network access to trusted application "
                        "networks and private connectivity."
                    ),
                )
            )

        if instance.get("StorageEncrypted") is not True:
            findings.append(
                SecurityFinding(
                    resource_id=db_id,
                    issue="RDS storage encryption disabled",
                    severity="HIGH",
                    description=(
                        f"RDS instance '{db_id}' does not have storage "
                        "encryption enabled. Enable encryption at rest."
                    ),
                )
            )

        retention = instance.get("BackupRetentionPeriod", 0)
        if retention < 7:
            findings.append(
                SecurityFinding(
                    resource_id=db_id,
                    issue="RDS backup retention below 7 days",
                    severity="MEDIUM",
                    description=(
                        f"RDS instance '{db_id}' retains automated backups "
                        f"for {retention} day(s). Set retention to at least "
                        "7 days according to the baseline."
                    ),
                )
            )

        if instance.get("DeletionProtection") is not True:
            findings.append(
                SecurityFinding(
                    resource_id=db_id,
                    issue="RDS deletion protection disabled",
                    severity="MEDIUM",
                    description=(
                        f"RDS instance '{db_id}' has deletion protection "
                        "disabled. Enable it for production databases."
                    ),
                )
            )

    return findings
