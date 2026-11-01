import json

from botocore.exceptions import ClientError

from src.aws.session import get_session


def list_buckets(region_name=None):
    session = get_session(region_name)
    s3_client = session.client("s3")

    response = s3_client.list_buckets()

    return response.get("Buckets", [])


def _get_error_code(error):
    return error.response.get("Error", {}).get("Code", "Unknown")


def get_bucket_security_details(bucket_name, s3_client):
    details = {
        "Name": bucket_name,
        "PublicAccessBlock": {},
        "PublicAccessBlockAccessible": True,
        "PolicyStatus": {},
        "PolicyStatusAccessible": True,
        "Policy": {},
        "PolicyAccessible": True,
        "Encryption": False,
        "EncryptionAccessible": True,
    }

    # 1. Get Public Access Block configuration
    try:
        response = s3_client.get_public_access_block(
            Bucket=bucket_name
        )
        details["PublicAccessBlock"] = response.get(
            "PublicAccessBlockConfiguration", {}
        )

    except ClientError as error:
        error_code = _get_error_code(error)

        if error_code == "AccessDenied":
            details["PublicAccessBlockAccessible"] = False
        elif error_code != "NoSuchPublicAccessBlockConfiguration":
            raise

    # 2. Get bucket policy status
    try:
        response = s3_client.get_bucket_policy_status(
            Bucket=bucket_name
        )
        details["PolicyStatus"] = response.get(
            "PolicyStatus", {}
        )

    except ClientError as error:
        error_code = _get_error_code(error)

        if error_code == "AccessDenied":
            details["PolicyStatusAccessible"] = False
        elif error_code != "NoSuchBucketPolicy":
            raise

    # 3. Get bucket policy
    try:
        response = s3_client.get_bucket_policy(
            Bucket=bucket_name
        )
        details["Policy"] = json.loads(
            response.get("Policy", "{}")
        )

    except ClientError as error:
        error_code = _get_error_code(error)

        if error_code == "AccessDenied":
            details["PolicyAccessible"] = False
        elif error_code != "NoSuchBucketPolicy":
            raise

    # 4. Check default encryption
    try:
        response = s3_client.get_bucket_encryption(
            Bucket=bucket_name
        )
        details["Encryption"] = bool(
            response.get("ServerSideEncryptionConfiguration")
        )

    except ClientError as error:
        error_code = _get_error_code(error)

        if error_code == "AccessDenied":
            details["EncryptionAccessible"] = False
        elif error_code != "ServerSideEncryptionConfigurationNotFoundError":
            raise

    return details


def scan_bucket_security(region_name=None):
    session = get_session(region_name)
    s3_client = session.client("s3")

    buckets = list_buckets(region_name)
    results = []

    for bucket in buckets:
        bucket_name = bucket["Name"]

        details = get_bucket_security_details(
            bucket_name,
            s3_client,
        )

        results.append(details)

    return results