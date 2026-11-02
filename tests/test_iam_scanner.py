
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.security.iam_scanner import scan_iam_security


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_user_without_mfa(mock_scan):
    mock_scan.return_value = [
        {
            "username": "alice",
            "mfa_enabled": False,
            "attached_policies": [],
            "access_keys": [],
        }
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].resource_id == "alice"
    assert findings[0].issue == "MFA_NOT_ENABLED"
    assert findings[0].severity == "HIGH"


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_administrator_access(mock_scan):
    mock_scan.return_value = [
        {
            "username": "alice",
            "mfa_enabled": True,
            "attached_policies": [
                {"PolicyName": "AdministratorAccess"}
            ],
            "access_keys": [],
        }
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].issue == "ADMINISTRATOR_ACCESS"
    assert findings[0].severity == "CRITICAL"


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_old_active_access_key(mock_scan):
    mock_scan.return_value = [
        {
            "username": "alice",
            "mfa_enabled": True,
            "attached_policies": [],
            "access_keys": [
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Active",
                    "CreateDate": (
                        datetime.now(timezone.utc)
                        - timedelta(days=120)
                    ),
                }
            ],
        }
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].issue == "OLD_ACCESS_KEY"
    assert findings[0].severity == "HIGH"


@patch("src.security.iam_scanner.scan_iam_users")
def test_ignore_inactive_old_access_key(mock_scan):
    mock_scan.return_value = [
        {
            "username": "alice",
            "mfa_enabled": True,
            "attached_policies": [],
            "access_keys": [
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Inactive",
                    "CreateDate": (
                        datetime.now(timezone.utc)
                        - timedelta(days=120)
                    ),
                }
            ],
        }
    ]

    findings = scan_iam_security()

    assert findings == []


@patch("src.security.iam_scanner.scan_iam_users")
def test_no_findings_for_secure_user(mock_scan):
    mock_scan.return_value = [
        {
            "username": "alice",
            "mfa_enabled": True,
            "attached_policies": [],
            "access_keys": [
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Active",
                    "CreateDate": (
                        datetime.now(timezone.utc)
                        - timedelta(days=30)
                    ),
                }
            ],
        }
    ]

    findings = scan_iam_security()

    assert findings == []


@patch("src.security.iam_scanner.scan_iam_users")
def test_scan_multiple_users(mock_scan):
    mock_scan.return_value = [
        {
            "username": "alice",
            "mfa_enabled": False,
            "attached_policies": [],
            "access_keys": [],
        },
        {
            "username": "bob",
            "mfa_enabled": True,
            "attached_policies": [
                {"PolicyName": "AdministratorAccess"}
            ],
            "access_keys": [],
        },
    ]

    findings = scan_iam_security()

    assert len(findings) == 2
    assert findings[0].resource_id == "alice"
    assert findings[1].resource_id == "bob"


@patch("src.security.iam_scanner.scan_iam_users")
def test_scan_empty_user_list(mock_scan):
    mock_scan.return_value = []

    findings = scan_iam_security()

    assert findings == []
