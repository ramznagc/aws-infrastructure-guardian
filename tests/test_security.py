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