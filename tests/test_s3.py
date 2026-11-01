import json
from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

from src.aws.s3 import (
    get_bucket_security_details,
    list_buckets,
    scan_bucket_security,
)


@patch("src.aws.s3.get_session")
def test_list_buckets(mock_get_session):
    mock_s3_client = MagicMock()
    mock_s3_client.list_buckets.return_value = {
        "Buckets": [
            {"Name": "test-bucket"},
            {"Name": "another-bucket"},
        ]
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3_client
    mock_get_session.return_value = mock_session

    buckets = list_buckets()

    assert len(buckets) == 2
    assert buckets[0]["Name"] == "test-bucket"
    mock_session.client.assert_called_once_with("s3")


@patch("src.aws.s3.get_session")
def test_list_buckets_returns_empty_list(mock_get_session):
    mock_s3_client = MagicMock()
    mock_s3_client.list_buckets.return_value = {"Buckets": []}

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3_client
    mock_get_session.return_value = mock_session

    assert list_buckets() == []


def test_get_bucket_security_details():
    mock_s3_client = MagicMock()

    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    mock_s3_client.get_bucket_policy_status.return_value = {
        "PolicyStatus": {"IsPublic": False}
    }

    mock_s3_client.get_bucket_policy.return_value = {
        "Policy": json.dumps({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": "arn:aws:iam::123456789012:root"
                    },
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ]
        })
    }

    mock_s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        }
    }

    details = get_bucket_security_details(
        "test-bucket",
        mock_s3_client,
    )

    assert details["Name"] == "test-bucket"
    assert details["PolicyStatus"]["IsPublic"] is False
    assert details["Encryption"] is True
    assert details["PublicAccessBlock"]["BlockPublicAcls"] is True
    assert "Statement" in details["Policy"]

    mock_s3_client.get_public_access_block.assert_called_once()
    mock_s3_client.get_bucket_policy_status.assert_called_once()
    mock_s3_client.get_bucket_policy.assert_called_once()
    mock_s3_client.get_bucket_encryption.assert_called_once()


@patch("src.aws.s3.get_session")
def test_scan_bucket_security(mock_get_session):
    mock_s3_client = MagicMock()

    mock_s3_client.list_buckets.return_value = {
        "Buckets": [{"Name": "test-bucket"}]
    }

    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    mock_s3_client.get_bucket_policy_status.return_value = {
        "PolicyStatus": {"IsPublic": False}
    }

    mock_s3_client.get_bucket_policy.return_value = {
        "Policy": "{}"
    }

    mock_s3_client.get_bucket_encryption.return_value = {
        "ServerSideEncryptionConfiguration": {
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        }
    }

    mock_session = MagicMock()
    mock_session.client.return_value = mock_s3_client
    mock_get_session.return_value = mock_session

    results = scan_bucket_security()

    assert len(results) == 1
    assert results[0]["Name"] == "test-bucket"
    assert results[0]["Encryption"] is True


def test_access_denied_is_reported_as_inaccessible():
    mock_s3_client = MagicMock()

    access_denied = ClientError(
        {
            "Error": {
                "Code": "AccessDenied",
                "Message": "Access Denied",
            }
        },
        "GetPublicAccessBlock",
    )

    mock_s3_client.get_public_access_block.side_effect = access_denied
    mock_s3_client.get_bucket_policy_status.side_effect = access_denied
    mock_s3_client.get_bucket_policy.side_effect = access_denied
    mock_s3_client.get_bucket_encryption.side_effect = access_denied

    details = get_bucket_security_details(
        "restricted-bucket",
        mock_s3_client,
    )

    assert details["PublicAccessBlockAccessible"] is False
    assert details["PolicyStatusAccessible"] is False
    assert details["PolicyAccessible"] is False
    assert details["EncryptionAccessible"] is False


def test_missing_encryption_is_not_access_denied():
    mock_s3_client = MagicMock()

    mock_s3_client.get_public_access_block.return_value = {
        "PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }
    }

    mock_s3_client.get_bucket_policy_status.return_value = {
        "PolicyStatus": {"IsPublic": False}
    }

    mock_s3_client.get_bucket_policy.side_effect = ClientError(
        {
            "Error": {
                "Code": "NoSuchBucketPolicy",
                "Message": "Policy not found",
            }
        },
        "GetBucketPolicy",
    )

    mock_s3_client.get_bucket_encryption.side_effect = ClientError(
        {
            "Error": {
                "Code": "ServerSideEncryptionConfigurationNotFoundError",
                "Message": "Encryption configuration not found",
            }
        },
        "GetBucketEncryption",
    )

    details = get_bucket_security_details(
        "unencrypted-bucket",
        mock_s3_client,
    )

    assert details["Encryption"] is False
    assert details["EncryptionAccessible"] is True
    assert details["PolicyAccessible"] is True
    assert details["Policy"] == {}