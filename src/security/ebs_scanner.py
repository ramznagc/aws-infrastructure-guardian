from src.security.finding import SecurityFinding


def scan_ebs_resources(ebs_resources):
    """Create security findings for EBS volumes and snapshots."""
    findings = []

    for volume in ebs_resources.get("Volumes", []):
        volume_id = volume.get("VolumeId", "unknown")

        if volume.get("Encrypted") is not True:
            findings.append(
                SecurityFinding(
                    resource_id=volume_id,
                    issue="EBS volume encryption disabled",
                    severity="HIGH",
                    description=(
                        f"EBS volume '{volume_id}' is not encrypted. "
                        "Enable encryption for data at rest."
                    ),
                )
            )

    for snapshot in ebs_resources.get("Snapshots", []):
        snapshot_id = snapshot.get("SnapshotId", "unknown")

        if snapshot.get("Encrypted") is not True:
            findings.append(
                SecurityFinding(
                    resource_id=snapshot_id,
                    issue="EBS snapshot encryption disabled",
                    severity="HIGH",
                    description=(
                        f"EBS snapshot '{snapshot_id}' is not encrypted. "
                        "Review the data-at-rest protection requirements."
                    ),
                )
            )

        if snapshot.get("Public") is True:
            findings.append(
                SecurityFinding(
                    resource_id=snapshot_id,
                    issue="Public EBS snapshot",
                    severity="CRITICAL",
                    description=(
                        f"EBS snapshot '{snapshot_id}' grants create-volume "
                        "permission to everyone. Remove public sharing unless "
                        "it is explicitly intended."
                    ),
                )
            )
        elif snapshot.get("Public") is None:
            findings.append(
                SecurityFinding(
                    resource_id=snapshot_id,
                    issue="EBS snapshot permissions not verified",
                    severity="MEDIUM",
                    description=(
                        f"Public-sharing permissions for EBS snapshot "
                        f"'{snapshot_id}' could not be verified. Check IAM "
                        "permissions and inspect the snapshot manually."
                    ),
                )
            )

    return findings
