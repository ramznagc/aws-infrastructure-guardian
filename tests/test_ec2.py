from unittest.mock import MagicMock, patch

from src.aws.ec2 import list_instances


def test_list_instances_collects_all_pages_and_metadata_options():
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-1234567890",
                            "State": {"Name": "running"},
                            "InstanceType": "t3.micro",
                            "PublicIpAddress": "203.0.113.10",
                            "MetadataOptions": {"HttpTokens": "required"},
                        }
                    ]
                }
            ]
        },
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-0987654321",
                            "State": {"Name": "stopped"},
                            "InstanceType": "t3.small",
                            "MetadataOptions": {"HttpTokens": "optional"},
                        }
                    ]
                }
            ]
        },
    ]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.ec2.get_session", return_value=session) as get_session:
        instances = list_instances(region_name="eu-central-1")

    assert instances == [
        {
            "id": "i-1234567890",
            "state": "running",
            "type": "t3.micro",
            "public_ip": "203.0.113.10",
            "metadata_http_tokens": "required",
        },
        {
            "id": "i-0987654321",
            "state": "stopped",
            "type": "t3.small",
            "public_ip": None,
            "metadata_http_tokens": "optional",
        },
    ]
    get_session.assert_called_once_with("eu-central-1")
    session.client.assert_called_once_with("ec2")
    client.get_paginator.assert_called_once_with("describe_instances")


def test_list_instances_handles_empty_pages_and_missing_metadata_options():
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"Reservations": []},
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-no-metadata",
                            "State": {"Name": "running"},
                            "InstanceType": "t3.micro",
                        }
                    ]
                }
            ]
        },
    ]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.ec2.get_session", return_value=session):
        instances = list_instances()

    assert instances == [
        {
            "id": "i-no-metadata",
            "state": "running",
            "type": "t3.micro",
            "public_ip": None,
            "metadata_http_tokens": None,
        }
    ]
