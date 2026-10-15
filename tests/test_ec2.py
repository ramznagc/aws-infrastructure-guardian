
from unittest.mock import patch

from src.aws.ec2 import list_instances


def test_list_instances():
    mock_response = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "InstanceId": "i-1234567890",
                        "State": {"Name": "running"},
                        "InstanceType": "t3.micro",
                        "PublicIpAddress": "203.0.113.10",
                    }
                ]
            }
        ]
    }

    with patch("src.aws.ec2.get_session") as mock_get_session:
        mock_ec2 = mock_get_session.return_value.client.return_value
        mock_ec2.describe_instances.return_value = mock_response

        instances = list_instances(region_name="eu-central-1")

    assert instances == [
        {
            "id": "i-1234567890",
            "state": "running",
            "type": "t3.micro",
            "public_ip": "203.0.113.10",
        }
    ]

    mock_ec2.describe_instances.assert_called_once_with()
