from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from src.security.iam_scanner import scan_iam_security


def _user(
    username="alice",
    mfa_enabled=True,
    attached_policies=None,
    inline_policies=None,
    access_keys=None,
):
    return {
        "username": username,
        "mfa_enabled": mfa_enabled,
        "attached_policies": attached_policies or [],
        "inline_policies": inline_policies or [],
        "access_keys": access_keys or [],
    }


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_user_without_mfa(mock_scan):
    mock_scan.return_value = [_user(mfa_enabled=False)]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].resource_id == "alice"
    assert findings[0].issue == "MFA_NOT_ENABLED"
    assert findings[0].severity == "HIGH"


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_administrator_access(mock_scan):
    mock_scan.return_value = [
        _user(attached_policies=[{"PolicyName": "AdministratorAccess"}])
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].issue == "HIGH_PRIVILEGE_POLICY_ATTACHED"
    assert findings[0].severity == "CRITICAL"


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_power_user_access(mock_scan):
    mock_scan.return_value = [
        _user(attached_policies=[{"PolicyName": "PowerUserAccess"}])
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].issue == "HIGH_PRIVILEGE_POLICY_ATTACHED"
    assert findings[0].severity == "CRITICAL"
    assert "PowerUserAccess" in findings[0].description


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_inline_policy_for_review(mock_scan):
    mock_scan.return_value = [
        _user(inline_policies=["CustomBillingAccess"])
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].issue == "INLINE_POLICY_REQUIRES_REVIEW"
    assert findings[0].severity == "MEDIUM"
    assert "CustomBillingAccess" in findings[0].description


@patch("src.security.iam_scanner.scan_iam_users")
def test_detect_old_active_access_key(mock_scan):
    mock_scan.return_value = [
        _user(
            access_keys=[
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Active",
                    "CreateDate": (
                        datetime.now(timezone.utc) - timedelta(days=120)
                    ),
                }
            ]
        )
    ]

    findings = scan_iam_security()

    assert len(findings) == 1
    assert findings[0].issue == "OLD_ACCESS_KEY"
    assert findings[0].severity == "HIGH"


@patch("src.security.iam_scanner.scan_iam_users")
def test_ignore_inactive_old_access_key(mock_scan):
    mock_scan.return_value = [
        _user(
            access_keys=[
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Inactive",
                    "CreateDate": (
                        datetime.now(timezone.utc) - timedelta(days=120)
                    ),
                }
            ]
        )
    ]

    assert scan_iam_security() == []


@patch("src.security.iam_scanner.scan_iam_users")
def test_no_findings_for_secure_user(mock_scan):
    mock_scan.return_value = [
        _user(
            access_keys=[
                {
                    "AccessKeyId": "AKIAEXAMPLE123",
                    "Status": "Active",
                    "CreateDate": (
                        datetime.now(timezone.utc) - timedelta(days=30)
                    ),
                }
            ]
        )
    ]

    assert scan_iam_security() == []


@patch("src.security.iam_scanner.scan_iam_users")
def test_scan_multiple_users(mock_scan):
    mock_scan.return_value = [
        _user(username="alice", mfa_enabled=False),
        _user(
            username="bob",
            attached_policies=[{"PolicyName": "AdministratorAccess"}],
        ),
    ]

    findings = scan_iam_security()

    assert len(findings) == 2
    assert findings[0].resource_id == "alice"
    assert findings[1].resource_id == "bob"


@patch("src.security.iam_scanner.scan_iam_users")
def test_scan_empty_user_list(mock_scan):
    mock_scan.return_value = []

    assert scan_iam_security() == []
