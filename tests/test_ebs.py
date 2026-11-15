from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from src.aws.ebs import (
    get_ebs_security_details,
    get_snapshot_public_status,
    list_ebs_snapshots,
    list_ebs_volumes,
    scan_ebs_security,
)


def test_list_ebs_volumes_uses_paginator():
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"Volumes": [{"VolumeId": "vol-1"}]},
        {"Volumes": [{"VolumeId": "vol-2"}]},
    ]

    volumes = list_ebs_volumes(ec2)

    assert [volume["VolumeId"] for volume in volumes] == [
        "vol-1",
        "vol-2",
    ]
    ec2.get_paginator.assert_called_once_with("describe_volumes")


def test_list_ebs_snapshots_uses_self_owner_and_paginator():
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"Snapshots": [{"SnapshotId": "snap-1"}]},
        {"Snapshots": [{"SnapshotId": "snap-2"}]},
    ]

    snapshots = list_ebs_snapshots(ec2)

    assert [item["SnapshotId"] for item in snapshots] == [
        "snap-1",
        "snap-2",
    ]
    paginator.paginate.assert_called_once_with(OwnerIds=["self"])


def test_snapshot_is_public_when_group_all_is_present():
    ec2 = MagicMock()
    ec2.describe_snapshot_attribute.return_value = {
        "CreateVolumePermissions": [
            {"Group": "all"},
        ]
    }

    assert get_snapshot_public_status("snap-public", ec2) is True
    ec2.describe_snapshot_attribute.assert_called_once_with(
        SnapshotId="snap-public",
        Attribute="createVolumePermission",
    )


def test_snapshot_is_not_public_for_account_specific_permission():
    ec2 = MagicMock()
    ec2.describe_snapshot_attribute.return_value = {
        "CreateVolumePermissions": [
            {"UserId": "123456789012"},
        ]
    }

    assert get_snapshot_public_status("snap-private", ec2) is False


def test_snapshot_public_status_returns_none_on_access_denied():
    ec2 = MagicMock()
    ec2.describe_snapshot_attribute.side_effect = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access denied",
            }
        },
        "DescribeSnapshotAttribute",
    )

    assert get_snapshot_public_status("snap-unknown", ec2) is None


def test_get_ebs_security_details_collects_volumes_and_snapshots():
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.side_effect = [
        [{"Volumes": [{"VolumeId": "vol-1", "Encrypted": True}]}],
        [{"Snapshots": [{"SnapshotId": "snap-1", "Encrypted": True}]}],
    ]
    ec2.describe_snapshot_attribute.return_value = {
        "CreateVolumePermissions": []
    }

    details = get_ebs_security_details(ec2)

    assert details["Volumes"][0]["VolumeId"] == "vol-1"
    assert details["Snapshots"][0]["SnapshotId"] == "snap-1"
    assert details["Snapshots"][0]["Public"] is False


@patch("src.aws.ebs.get_session")
def test_scan_ebs_security_uses_ec2_client(mock_get_session):
    ec2 = MagicMock()
    session = MagicMock()
    session.client.return_value = ec2
    mock_get_session.return_value = session

    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.side_effect = [
        [{"Volumes": []}],
        [{"Snapshots": []}],
    ]

    result = scan_ebs_security("eu-central-1")

    assert result == {"Volumes": [], "Snapshots": []}
    mock_get_session.assert_called_once_with("eu-central-1")
    session.client.assert_called_once_with("ec2")
