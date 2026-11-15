from src.security.ebs_scanner import scan_ebs_resources


def test_detects_unencrypted_volume():
    findings = scan_ebs_resources({
        "Volumes": [
            {"VolumeId": "vol-plain", "Encrypted": False}
        ],
        "Snapshots": [],
    })

    assert len(findings) == 1
    assert findings[0].resource_id == "vol-plain"
    assert findings[0].issue == "EBS volume encryption disabled"
    assert findings[0].severity == "HIGH"


def test_detects_unencrypted_snapshot():
    findings = scan_ebs_resources({
        "Volumes": [],
        "Snapshots": [
            {
                "SnapshotId": "snap-plain",
                "Encrypted": False,
                "Public": False,
            }
        ],
    })

    assert len(findings) == 1
    assert findings[0].resource_id == "snap-plain"
    assert findings[0].issue == "EBS snapshot encryption disabled"
    assert findings[0].severity == "HIGH"


def test_detects_public_snapshot_as_critical():
    findings = scan_ebs_resources({
        "Volumes": [],
        "Snapshots": [
            {
                "SnapshotId": "snap-public",
                "Encrypted": True,
                "Public": True,
            }
        ],
    })

    assert len(findings) == 1
    assert findings[0].issue == "Public EBS snapshot"
    assert findings[0].severity == "CRITICAL"


def test_reports_snapshot_permissions_that_cannot_be_verified():
    findings = scan_ebs_resources({
        "Volumes": [],
        "Snapshots": [
            {
                "SnapshotId": "snap-unknown",
                "Encrypted": True,
                "Public": None,
            }
        ],
    })

    assert len(findings) == 1
    assert findings[0].issue == "EBS snapshot permissions not verified"
    assert findings[0].severity == "MEDIUM"


def test_detects_multiple_ebs_findings():
    findings = scan_ebs_resources({
        "Volumes": [
            {"VolumeId": "vol-plain", "Encrypted": False},
            {"VolumeId": "vol-encrypted", "Encrypted": True},
        ],
        "Snapshots": [
            {
                "SnapshotId": "snap-public",
                "Encrypted": False,
                "Public": True,
            }
        ],
    })

    assert len(findings) == 3
    assert {finding.severity for finding in findings} == {
        "HIGH",
        "CRITICAL",
    }


def test_no_findings_for_secure_ebs_resources():
    findings = scan_ebs_resources({
        "Volumes": [
            {"VolumeId": "vol-secure", "Encrypted": True}
        ],
        "Snapshots": [
            {
                "SnapshotId": "snap-secure",
                "Encrypted": True,
                "Public": False,
            }
        ],
    })

    assert findings == []


def test_empty_ebs_inventory_returns_no_findings():
    assert scan_ebs_resources({}) == []
