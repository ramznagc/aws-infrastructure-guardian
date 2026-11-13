from src.aws.session import get_session


def list_iam_users():
    """List all IAM users in the AWS account."""
    session = get_session()
    iam_client = session.client("iam")

    paginator = iam_client.get_paginator("list_users")
    users = []

    for page in paginator.paginate():
        users.extend(page.get("Users", []))

    return users


def get_user_mfa_status(username, iam_client):
    """Return whether the IAM user has at least one MFA device."""
    response = iam_client.list_mfa_devices(UserName=username)
    return bool(response.get("MFADevices", []))


def get_user_attached_policies(username, iam_client):
    """List managed policies directly attached to an IAM user."""
    paginator = iam_client.get_paginator(
        "list_attached_user_policies"
    )
    policies = []

    for page in paginator.paginate(UserName=username):
        policies.extend(page.get("AttachedPolicies", []))

    return policies


def get_user_inline_policies(username, iam_client):
    """List inline policy names directly embedded in an IAM user."""
    paginator = iam_client.get_paginator(
        "list_user_policies"
    )
    policy_names = []

    for page in paginator.paginate(UserName=username):
        policy_names.extend(page.get("PolicyNames", []))

    return policy_names


def get_user_access_keys(username, iam_client):
    """List access key metadata for an IAM user."""
    response = iam_client.list_access_keys(UserName=username)
    return response.get("AccessKeyMetadata", [])


def get_user_security_details(username, iam_client):
    """Collect security-relevant IAM details for one user."""
    return {
        "mfa_enabled": get_user_mfa_status(
            username,
            iam_client,
        ),
        "attached_policies": get_user_attached_policies(
            username,
            iam_client,
        ),
        "inline_policies": get_user_inline_policies(
            username,
            iam_client,
        ),
        "access_keys": get_user_access_keys(
            username,
            iam_client,
        ),
    }


def scan_iam_users():
    """Collect security details for every IAM user."""
    session = get_session()
    iam_client = session.client("iam")

    users = list_iam_users()
    results = []

    for user in users:
        username = user["UserName"]
        details = get_user_security_details(username, iam_client)

        results.append({
            "username": username,
            **details,
        })

    return results
