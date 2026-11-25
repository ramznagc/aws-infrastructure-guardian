from src.security.finding import SecurityFinding


def scan_vpc_flow_logs(resources):
    """Flag VPCs without an active flow log delivering records successfully."""
    findings = []
    flow_logs_by_vpc = {}

    for flow_log in resources.get("FlowLogs", []):
        resource_id = flow_log.get("ResourceId")
        if resource_id:
            flow_logs_by_vpc.setdefault(resource_id, []).append(flow_log)

    for vpc in resources.get("Vpcs", []):
        vpc_id = vpc.get("VpcId")
        if not vpc_id:
            continue

        vpc_flow_logs = flow_logs_by_vpc.get(vpc_id, [])
        has_healthy_flow_log = any(
            flow_log.get("FlowLogStatus") == "ACTIVE"
            and flow_log.get("DeliverLogsStatus") == "SUCCESS"
            for flow_log in vpc_flow_logs
        )

        if not has_healthy_flow_log:
            findings.append(
                SecurityFinding(
                    resource_id=vpc_id,
                    issue="VPC Flow Logs missing or unhealthy",
                    severity="MEDIUM",
                    description=(
                        "The VPC has no Flow Log with ACTIVE status and "
                        "successful log delivery. Enable or repair VPC Flow "
                        "Logs to improve network visibility."
                    ),
                )
            )

    return findings
