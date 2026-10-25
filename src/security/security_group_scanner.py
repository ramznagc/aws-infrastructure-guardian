
from src.security.finding import SecurityFinding


def scan_security_groups(security_groups):
    findings = []

    for security_group in security_groups:
        group_id = security_group.get("GroupId", "unknown")

        for permission in security_group.get("IpPermissions", []):
            protocol = permission.get("IpProtocol")
            from_port = permission.get("FromPort")
            to_port = permission.get("ToPort")

            if protocol == "tcp":
                if from_port is None or to_port is None:
                    continue

                if not (from_port <= 22 <= to_port):
                    continue
            elif protocol != "-1":
                continue

            ipv4_open = any(
                ip_range.get("CidrIp") == "0.0.0.0/0"
                for ip_range in permission.get("IpRanges", [])
            )

            ipv6_open = any(
                ip_range.get("CidrIpv6") == "::/0"
                for ip_range in permission.get("Ipv6Ranges", [])
            )

            if ipv4_open or ipv6_open:
                findings.append(
                    SecurityFinding(
                        resource_id=group_id,
                        issue="SSH open to the internet",
                        severity="HIGH",
                        description=(
                            "Security group allows SSH or unrestricted "
                            "protocol access from all IPv4 or IPv6 addresses. "
                            "Review and restrict inbound access."
                        ),
                    )
                )

    return findings
