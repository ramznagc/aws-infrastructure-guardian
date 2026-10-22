
import pytest

from src.security.finding import SecurityFinding
from src.security.scanner import scan_ec2_instances


def test_public_ip_creates_security_finding():
    instances = [
        {
            "id": "i-1234567890",
            "public_ip": "203.0.113.10",
        }
    ]

    findings = scan_ec2_instances(instances)

    assert len(findings) == 1
    assert findings[0].resource_id == "i-1234567890"
    assert findings[0].issue == "Public IP assigned"
    assert findings[0].severity == "MEDIUM"


def test_instance_without_public_ip_has_no_finding():
    instances = [
        {
            "id": "i-0987654321",
            "public_ip": None,
        }
    ]

    findings = scan_ec2_instances(instances)

    assert findings == []


def test_instance_without_public_ip_key_has_no_finding():
    instances = [
        {
            "id": "i-1122334455",
        }
    ]

    findings = scan_ec2_instances(instances)

    assert findings == []


def test_multiple_instances_are_scanned_independently():
    instances = [
        {
            "id": "i-public",
            "public_ip": "203.0.113.10",
        },
        {
            "id": "i-private",
            "public_ip": None,
        },
        {
            "id": "i-public-2",
            "public_ip": "203.0.113.20",
        },
    ]

    findings = scan_ec2_instances(instances)

    assert len(findings) == 2
    assert [finding.resource_id for finding in findings] == [
        "i-public",
        "i-public-2",
    ]


def test_severity_is_normalized_to_uppercase():
    finding = SecurityFinding(
        resource_id="i-123",
        issue="Public IP assigned",
        severity="medium",
        description="Test finding",
    )

    assert finding.severity == "MEDIUM"


def test_invalid_severity_raises_value_error():
    with pytest.raises(ValueError, match="Invalid severity"):
        SecurityFinding(
            resource_id="i-123",
            issue="Public IP assigned",
            severity="URGENT",
            description="Test finding",
        )


def test_empty_resource_id_raises_value_error():
    with pytest.raises(ValueError, match="resource_id cannot be empty"):
        SecurityFinding(
            resource_id=" ",
            issue="Public IP assigned",
            severity="MEDIUM",
            description="Test finding",
        )


def test_empty_issue_raises_value_error():
    with pytest.raises(ValueError, match="issue cannot be empty"):
        SecurityFinding(
            resource_id="i-123",
            issue=" ",
            severity="MEDIUM",
            description="Test finding",
        )
