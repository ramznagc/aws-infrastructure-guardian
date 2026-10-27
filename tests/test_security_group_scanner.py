from src.security.security_group_scanner import scan_security_groups


def test_detects_ssh_open_to_internet():
    security_groups = [
        {
            "GroupId": "sg-12345",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]

    findings = scan_security_groups(security_groups)

    assert len(findings) == 1
    assert findings[0].resource_id == "sg-12345"
    assert findings[0].issue == "SSH open to the internet"
    assert findings[0].severity == "HIGH"


def test_ignores_ssh_restricted_to_trusted_ip():
    security_groups = [
        {
            "GroupId": "sg-67890",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "203.0.113.10/32"}],
                }
            ],
        }
    ]

    assert scan_security_groups(security_groups) == []


def test_ignores_unrelated_open_port():
    security_groups = [
        {
            "GroupId": "sg-54321",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]

    assert scan_security_groups(security_groups) == []


def test_empty_security_groups_return_no_findings():
    assert scan_security_groups([]) == []


def test_ignores_tcp_rule_with_missing_port_information():
    security_groups = [
        {
            "GroupId": "sg-missing-port",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]

    assert scan_security_groups(security_groups) == []


def test_detects_all_protocols_open_to_internet():
    security_groups = [
        {
            "GroupId": "sg-all-protocols",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
    ]

    findings = scan_security_groups(security_groups)

    assert len(findings) == 1
    assert findings[0].resource_id == "sg-all-protocols"
    assert findings[0].severity == "HIGH"


def test_detects_ssh_open_to_all_ipv6_addresses():
    security_groups = [
        {
            "GroupId": "sg-ipv6-ssh",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        }
    ]

    findings = scan_security_groups(security_groups)

    assert len(findings) == 1
    assert findings[0].resource_id == "sg-ipv6-ssh"
    assert findings[0].severity == "HIGH"


def test_ignores_ssh_restricted_to_specific_ipv6_range():
    security_groups = [
        {
            "GroupId": "sg-restricted-ipv6",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "2001:db8::/64"}],
                }
            ],
        }
    ]

    assert scan_security_groups(security_groups) == []


def test_reports_only_one_finding_per_security_group():
    security_groups = [
        {
            "GroupId": "sg-duplicate",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
        }
    ]

    findings = scan_security_groups(security_groups)

    assert len(findings) == 1
    assert findings[0].resource_id == "sg-duplicate"
