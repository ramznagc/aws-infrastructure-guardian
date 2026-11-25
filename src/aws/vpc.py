from .session import get_session


def scan_vpc_flow_logs(region_name=None):
    """Discover VPCs and their flow-log delivery status without changing AWS."""
    session = get_session(region_name)
    ec2 = session.client("ec2")

    vpc_paginator = ec2.get_paginator("describe_vpcs")
    flow_log_paginator = ec2.get_paginator("describe_flow_logs")

    vpcs = []
    for page in vpc_paginator.paginate():
        vpcs.extend(page.get("Vpcs", []))

    flow_logs = []
    for page in flow_log_paginator.paginate():
        flow_logs.extend(page.get("FlowLogs", []))

    return {"Vpcs": vpcs, "FlowLogs": flow_logs}
