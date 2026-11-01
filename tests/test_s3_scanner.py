from src.security.s3_scanner import scan_s3_buckets


def test_detects_public_bucket():
    buckets = [
        {
            "Name": "public-bucket",
            "PublicAccessBlock": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
            "PolicyStatus": {
                "IsPublic": True
            },
            "Encryption": True,
        }
    ]

    findings = scan_s3_buckets(buckets)

    assert any(
        finding.issue == "Public S3 bucket"
        for finding in findings
    )


def test_detects_disabled_public_access_block():
    buckets = [
        {
            "Name": "unprotected-bucket",
            "PublicAccessBlock": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "PolicyStatus": {
                "IsPublic": False
            },
            "Encryption": True,
        }
    ]

    findings = scan_s3_buckets(buckets)

    assert any(
        finding.issue == "S3 public access block disabled"
        for finding in findings
    )


def test_detects_risky_bucket_policy():
    buckets = [
        {
            "Name": "risky-policy-bucket",
            "PublicAccessBlock": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "PolicyStatus": {
                "IsPublic": False
            },
            "Policy": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "*",
                    }
                ]
            },
            "Encryption": True,
        }
    ]

    findings = scan_s3_buckets(buckets)

    assert any(
        finding.issue == "Risky S3 bucket policy"
        for finding in findings
    )


def test_detects_missing_bucket_encryption():
    buckets = [
        {
            "Name": "unencrypted-bucket",
            "PublicAccessBlock": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "PolicyStatus": {
                "IsPublic": False
            },
            "Encryption": False,
        }
    ]

    findings = scan_s3_buckets(buckets)

    assert any(
        finding.issue == "S3 bucket encryption disabled"
        for finding in findings
    )