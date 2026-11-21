from unittest.mock import MagicMock, patch

from src.aws.ec2 import list_security_groups


def test_list_security_groups_collects_all_pages():
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"SecurityGroups": [{"GroupId": "sg-1"}]},
        {"SecurityGroups": [{"GroupId": "sg-2"}]},
    ]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.ec2.get_session", return_value=session) as get_session:
        groups = list_security_groups("eu-central-1")

    assert groups == [{"GroupId": "sg-1"}, {"GroupId": "sg-2"}]
    get_session.assert_called_once_with("eu-central-1")
    session.client.assert_called_once_with("ec2")
    client.get_paginator.assert_called_once_with("describe_security_groups")


def test_list_security_groups_returns_empty_inventory():
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"SecurityGroups": []}]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.ec2.get_session", return_value=session):
        assert list_security_groups() == []


def test_list_security_groups_handles_missing_response_key():
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{}, {"SecurityGroups": [{"GroupId": "sg-3"}]}]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.ec2.get_session", return_value=session):
        assert list_security_groups() == [{"GroupId": "sg-3"}]
