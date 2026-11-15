from unittest.mock import MagicMock, patch

from src.aws.rds import list_rds_instances, scan_rds_security
from src.security.rds_scanner import scan_rds_instances


def _instance(**overrides):
    instance = {
        "DBInstanceIdentifier": "guardian-db",
        "PubliclyAccessible": False,
        "StorageEncrypted": True,
        "BackupRetentionPeriod": 7,
        "DeletionProtection": True,
    }
    instance.update(overrides)
    return instance


def test_list_rds_instances_uses_paginator():
    client = MagicMock()
    paginator = MagicMock()
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"DBInstances": [{"DBInstanceIdentifier": "db-1"}]},
        {"DBInstances": [{"DBInstanceIdentifier": "db-2"}]},
    ]

    instances = list_rds_instances(client)

    assert [item["DBInstanceIdentifier"] for item in instances] == [
        "db-1", "db-2"
    ]
    client.get_paginator.assert_called_once_with("describe_db_instances")


@patch("src.aws.rds.get_session")
def test_scan_rds_security_uses_rds_client(mock_get_session):
    session = MagicMock()
    client = MagicMock()
    paginator = MagicMock()
    session.client.return_value = client
    client.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"DBInstances": []}]
    mock_get_session.return_value = session

    assert scan_rds_security("eu-central-1") == []
    mock_get_session.assert_called_once_with("eu-central-1")
    session.client.assert_called_once_with("rds")


def test_detects_public_rds_instance_as_critical():
    findings = scan_rds_instances([_instance(PubliclyAccessible=True)])

    assert len(findings) == 1
    assert findings[0].issue == "RDS instance publicly accessible"
    assert findings[0].severity == "CRITICAL"


def test_detects_unencrypted_rds_storage():
    findings = scan_rds_instances([_instance(StorageEncrypted=False)])

    assert len(findings) == 1
    assert findings[0].issue == "RDS storage encryption disabled"
    assert findings[0].severity == "HIGH"


def test_detects_short_backup_retention():
    findings = scan_rds_instances([_instance(BackupRetentionPeriod=3)])

    assert len(findings) == 1
    assert findings[0].issue == "RDS backup retention below 7 days"
    assert findings[0].severity == "MEDIUM"


def test_detects_zero_backup_retention():
    findings = scan_rds_instances([_instance(BackupRetentionPeriod=0)])

    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_detects_disabled_deletion_protection():
    findings = scan_rds_instances([_instance(DeletionProtection=False)])

    assert len(findings) == 1
    assert findings[0].issue == "RDS deletion protection disabled"
    assert findings[0].severity == "MEDIUM"


def test_detects_multiple_rds_misconfigurations():
    findings = scan_rds_instances([
        _instance(
            PubliclyAccessible=True,
            StorageEncrypted=False,
            BackupRetentionPeriod=0,
            DeletionProtection=False,
        )
    ])

    assert len(findings) == 4
    assert {finding.severity for finding in findings} == {
        "CRITICAL", "HIGH", "MEDIUM"
    }


def test_secure_rds_instance_has_no_findings():
    assert scan_rds_instances([_instance()]) == []


def test_empty_rds_inventory_has_no_findings():
    assert scan_rds_instances([]) == []
