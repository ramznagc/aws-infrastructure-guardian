from src.compliance.rules import REQUIRED_TAGS


def find_missing_tags(resource_tags):
    existing_tags = {
        tag["Key"]
        for tag in resource_tags
    }

    missing_tags = [
        tag
        for tag in REQUIRED_TAGS
        if tag not in existing_tags
    ]

    return missing_tags