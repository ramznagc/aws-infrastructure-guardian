from src.security.vpc_scanner import scan_vpc_flow_logs


def test_flags_vpc_without_flow_logs():
    findings = scan_vpc_flow_logs(
        {"Vpcs": [{"VpcId": "vpc-no-logs"}], "FlowLogs": []}
    )

    assert len(findings) == 1
    assert findings[0].resource_id == "vpc-no-logs"
    assert findings[0].issue == "VPC Flow Logs missing or unhealthy"
    assert findings[0].severity == "MEDIUM"


def test_active_flow_log_with_successful_delivery_is_compliant():
    resources = {
        "Vpcs": [{"VpcId": "vpc-healthy"}],
        "FlowLogs": [
            {
                "ResourceId": "vpc-healthy",
                "FlowLogStatus": "ACTIVE",
                "DeliverLogsStatus": "SUCCESS",
            }
        ],
    }

    assert scan_vpc_flow_logs(resources) == []


def test_failed_delivery_is_reported():
    resources = {
        "Vpcs": [{"VpcId": "vpc-failed-delivery"}],
        "FlowLogs": [
            {
                "ResourceId": "vpc-failed-delivery",
                "FlowLogStatus": "ACTIVE",
                "DeliverLogsStatus": "FAILED",
            }
        ],
    }

    findings = scan_vpc_flow_logs(resources)

    assert len(findings) == 1
    assert findings[0].resource_id == "vpc-failed-delivery"


def test_inactive_flow_log_is_reported():
    resources = {
        "Vpcs": [{"VpcId": "vpc-inactive"}],
        "FlowLogs": [
            {
                "ResourceId": "vpc-inactive",
                "FlowLogStatus": "FAILED",
                "DeliverLogsStatus": "SUCCESS",
            }
        ],
    }

    assert len(scan_vpc_flow_logs(resources)) == 1


def test_unrelated_vpc_flow_log_does_not_satisfy_coverage():
    resources = {
        "Vpcs": [{"VpcId": "vpc-a"}],
        "FlowLogs": [
            {
                "ResourceId": "vpc-b",
                "FlowLogStatus": "ACTIVE",
                "DeliverLogsStatus": "SUCCESS",
            }
        ],
    }

    findings = scan_vpc_flow_logs(resources)

    assert [finding.resource_id for finding in findings] == ["vpc-a"]


def test_empty_inventory_has_no_findings():
    assert scan_vpc_flow_logs({"Vpcs": [], "FlowLogs": []}) == []


def test_missing_response_keys_are_handled_safely():
    assert scan_vpc_flow_logs({}) == []
