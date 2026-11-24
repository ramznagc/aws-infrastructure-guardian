from .session import get_session


def list_instances(region_name=None):
    """Discover EC2 instances and selected security metadata across all pages."""
    session = get_session(region_name)
    ec2 = session.client("ec2")
    paginator = ec2.get_paginator("describe_instances")

    instances = []
    for page in paginator.paginate():
        for reservation in page.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                metadata_options = instance.get("MetadataOptions") or {}
                instances.append(
                    {
                        "id": instance["InstanceId"],
                        "state": instance["State"]["Name"],
                        "type": instance["InstanceType"],
                        "public_ip": instance.get("PublicIpAddress"),
                        "metadata_http_tokens": metadata_options.get("HttpTokens"),
                    }
                )

    return instances


def list_security_groups(region_name=None):
    """Return EC2 security groups using paginated, read-only discovery."""
    session = get_session(region_name)
    ec2 = session.client("ec2")
    paginator = ec2.get_paginator("describe_security_groups")

    security_groups = []
    for page in paginator.paginate():
        security_groups.extend(page.get("SecurityGroups", []))

    return security_groups
