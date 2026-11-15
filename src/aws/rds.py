from src.aws.session import get_session


def list_rds_instances(rds_client):
    """List RDS DB instances, following all pages."""
    paginator = rds_client.get_paginator("describe_db_instances")
    instances = []

    for page in paginator.paginate():
        instances.extend(page.get("DBInstances", []))

    return instances


def scan_rds_security(region_name=None):
    """Collect read-only security metadata for RDS DB instances."""
    session = get_session(region_name)
    rds_client = session.client("rds")
    return list_rds_instances(rds_client)
