from botocore.exceptions import ClientError

from src.aws.session import get_session


def _error_code(error):
    return error.response.get("Error", {}).get("Code", "Unknown")


def list_ebs_volumes(ec2_client):
    """List EBS volumes across all pages."""
    paginator = ec2_client.get_paginator("describe_volumes")
    volumes = []

    for page in paginator.paginate():
        volumes.extend(page.get("Volumes", []))

    return volumes


def list_ebs_snapshots(ec2_client, owner_ids=None):
    """List snapshots owned by the current account across all pages."""
    paginator = ec2_client.get_paginator("describe_snapshots")
    pages = paginator.paginate(OwnerIds=owner_ids or ["self"])
    snapshots = []

    for page in pages:
        snapshots.extend(page.get("Snapshots", []))

    return snapshots


def get_snapshot_public_status(snapshot_id, ec2_client):
    """Check whether a snapshot grants create-volume permission to everyone."""
    try:
        response = ec2_client.describe_snapshot_attribute(
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
        )
    except ClientError as error:
        if _error_code(error) == "AccessDenied":
            return None
        raise

    return any(
        permission.get("Group") == "all"
        for permission in response.get("CreateVolumePermissions", [])
    )


def get_ebs_security_details(ec2_client):
    """Collect volume encryption and snapshot exposure metadata."""
    volumes = list_ebs_volumes(ec2_client)
    snapshots = list_ebs_snapshots(ec2_client)
    snapshot_details = []

    for snapshot in snapshots:
        snapshot_id = snapshot["SnapshotId"]
        snapshot_details.append({
            **snapshot,
            "Public": get_snapshot_public_status(
                snapshot_id,
                ec2_client,
            ),
        })

    return {
        "Volumes": volumes,
        "Snapshots": snapshot_details,
    }


def scan_ebs_security(region_name=None):
    """Discover EBS resources and collect their security details."""
    session = get_session(region_name)
    ec2_client = session.client("ec2")
    return get_ebs_security_details(ec2_client)
