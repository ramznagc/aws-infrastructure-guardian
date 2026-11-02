
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from src.aws.iam import (
    list_iam_users,
    get_user_mfa_status,
    get_user_attached_policies,
    get_user_access_keys,
    get_user_security_details,
    scan_iam_users,
)


@patch("src.aws.iam.get_session")
def test_list_iam_users(mock_get_session):
    mock_iam = MagicMock()
    mock_session = MagicMock()

    mock_get_session.return_value = mock_session
    mock_session.client.return_value = mock_iam

    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator

    mock_paginator.paginate.return_value = [
        {
            "Users": [
                {"UserName": "alice"},
                {"UserName": "bob"},
            ]
        }
    ]

    users = list_iam_users()

    assert len(users) == 2
    assert users[0]["UserName"] == "alice"
    assert users[1]["UserName"] == "bob"

    mock_iam.get_paginator.assert_called_once_with("list_users")
    mock_paginator.paginate.assert_called_once_with()


def test_get_user_mfa_status_enabled():
    mock_iam = MagicMock()
    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": [
            {"SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}
        ]
    }

    result = get_user_mfa_status("alice", mock_iam)

    assert result is True


def test_get_user_mfa_status_disabled():
    mock_iam = MagicMock()
    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": []
    }

    result = get_user_mfa_status("bob", mock_iam)

    assert result is False


def test_get_user_attached_policies():
    mock_iam = MagicMock()

    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator

    mock_paginator.paginate.return_value = [
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": (
                        "arn:aws:iam::aws:policy/AdministratorAccess"
                    ),
                },
                {
                    "PolicyName": "ReadOnlyAccess",
                    "PolicyArn": (
                        "arn:aws:iam::aws:policy/ReadOnlyAccess"
                    ),
                },
            ]
        }
    ]

    policies = get_user_attached_policies("alice", mock_iam)

    assert len(policies) == 2
    assert policies[0]["PolicyName"] == "AdministratorAccess"
    assert policies[1]["PolicyName"] == "ReadOnlyAccess"

    mock_iam.get_paginator.assert_called_once_with(
        "list_attached_user_policies"
    )

    mock_paginator.paginate.assert_called_once_with(
        UserName="alice"
    )


def test_get_user_access_keys():
    mock_iam = MagicMock()

    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAEXAMPLE123",
                "Status": "Active",
                "CreateDate": (
                    datetime.now(timezone.utc) - timedelta(days=120)
                ),
            },
            {
                "AccessKeyId": "AKIAEXAMPLE456",
                "Status": "Active",
                "CreateDate": (
                    datetime.now(timezone.utc) - timedelta(days=30)
                ),
            },
        ]
    }

    keys = get_user_access_keys("alice", mock_iam)

    assert len(keys) == 2
    assert keys[0]["AccessKeyId"] == "AKIAEXAMPLE123"
    assert keys[1]["AccessKeyId"] == "AKIAEXAMPLE456"

    mock_iam.list_access_keys.assert_called_once_with(
        UserName="alice"
    )


def test_get_user_security_details():
    mock_iam = MagicMock()

    mock_iam.list_mfa_devices.return_value = {
        "MFADevices": [
            {"SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}
        ]
    }

    mock_paginator = MagicMock()

    mock_iam.get_paginator.return_value = mock_paginator

    mock_paginator.paginate.return_value = [
        {
            "AttachedPolicies": [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": (
                        "arn:aws:iam::aws:policy/AdministratorAccess"
                    ),
                }
            ]
        }
    ]

    mock_iam.list_access_keys.return_value = {
        "AccessKeyMetadata": [
            {
                "AccessKeyId": "AKIAEXAMPLE123",
                "Status": "Active",
                "CreateDate": (
                    datetime.now(timezone.utc) - timedelta(days=120)
                ),
            }
        ]
    }

    details = get_user_security_details("alice", mock_iam)

    assert details["mfa_enabled"] is True

    assert len(details["attached_policies"]) == 1

    assert details["attached_policies"][0]["PolicyName"] == (
        "AdministratorAccess"
    )

    assert len(details["access_keys"]) == 1


@patch("src.aws.iam.get_user_security_details")
@patch("src.aws.iam.list_iam_users")
def test_scan_iam_users_multiple_users(
    mock_list_users,
    mock_security_details,
):
    mock_list_users.return_value = [
        {"UserName": "alice"},
        {"UserName": "bob"},
    ]

    mock_security_details.side_effect = [
        {
            "mfa_enabled": True,
            "attached_policies": [],
            "access_keys": [],
        },
        {
            "mfa_enabled": False,
            "attached_policies": [
                {"PolicyName": "AdministratorAccess"}
            ],
            "access_keys": [],
        },
    ]

    result = scan_iam_users()

    assert len(result) == 2
    assert result[0]["username"] == "alice"
    assert result[1]["username"] == "bob"

    assert mock_security_details.call_count == 2


@patch("src.aws.iam.get_session")
def test_scan_iam_users_empty_list(mock_get_session):
    mock_iam = MagicMock()
    mock_session = MagicMock()

    mock_get_session.return_value = mock_session
    mock_session.client.return_value = mock_iam

    mock_paginator = MagicMock()
    mock_iam.get_paginator.return_value = mock_paginator
    mock_paginator.paginate.return_value = [
        {"Users": []}
    ]

    result = scan_iam_users()

    assert result == []
