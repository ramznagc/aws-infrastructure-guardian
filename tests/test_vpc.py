from unittest.mock import MagicMock, patch

from src.aws.vpc import scan_vpc_flow_logs


def test_discovers_vpcs_and_flow_logs_across_all_pages():
    client = MagicMock()
    vpc_paginator = MagicMock()
    flow_log_paginator = MagicMock()
    client.get_paginator.side_effect = [vpc_paginator, flow_log_paginator]
    vpc_paginator.paginate.return_value = [
        {"Vpcs": [{"VpcId": "vpc-1"}]},
        {"Vpcs": [{"VpcId": "vpc-2"}]},
    ]
    flow_log_paginator.paginate.return_value = [
        {"FlowLogs": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}]},
        {"FlowLogs": [{"ResourceId": "vpc-2", "FlowLogStatus": "ACTIVE"}]},
    ]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.vpc.get_session", return_value=session) as get_session:
        result = scan_vpc_flow_logs(region_name="eu-central-1")

    assert result == {
        "Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}],
        "FlowLogs": [
            {"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"},
            {"ResourceId": "vpc-2", "FlowLogStatus": "ACTIVE"},
        ],
    }
    get_session.assert_called_once_with("eu-central-1")
    session.client.assert_called_once_with("ec2")
    assert client.get_paginator.call_args_list[0].args == ("describe_vpcs",)
    assert client.get_paginator.call_args_list[1].args == ("describe_flow_logs",)


def test_handles_empty_discovery_pages():
    client = MagicMock()
    vpc_paginator = MagicMock()
    flow_log_paginator = MagicMock()
    client.get_paginator.side_effect = [vpc_paginator, flow_log_paginator]
    vpc_paginator.paginate.return_value = [{"Vpcs": []}, {}]
    flow_log_paginator.paginate.return_value = [{"FlowLogs": []}, {}]
    session = MagicMock()
    session.client.return_value = client

    with patch("src.aws.vpc.get_session", return_value=session):
        assert scan_vpc_flow_logs() == {"Vpcs": [], "FlowLogs": []}
