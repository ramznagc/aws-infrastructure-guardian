from src.security.scanner import scan_ec2_instances


def test_detects_instance_with_public_ip():
    findings = scan_ec2_instances(
        [
            {
                "id": "i-public",
                "state": "running",
                "type": "t3.micro",
                "public_ip": "203.0.113.10",
            }
        ]
    )

    assert len(findings) == 1
    assert findings[0].resource_id == "i-public"
    assert findings[0].issue == "Public IP assigned"
    assert findings[0].severity == "MEDIUM"


def test_private_instance_has_no_public_ip_finding():
    instances = [
        {
            "id": "i-private",
            "state": "running",
            "type": "t3.micro",
            "public_ip": None,
        }
    ]

    assert scan_ec2_instances(instances) == []


def test_empty_instance_inventory_has_no_findings():
    assert scan_ec2_instances([]) == []


def test_reports_each_public_instance():
    instances = [
        {"id": "i-one", "public_ip": "203.0.113.10"},
        {"id": "i-two", "public_ip": "203.0.113.11"},
    ]

    findings = scan_ec2_instances(instances)

    assert [finding.resource_id for finding in findings] == ["i-one", "i-two"]
