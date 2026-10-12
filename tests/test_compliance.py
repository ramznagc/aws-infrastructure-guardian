from src.compliance.scanner import find_missing_tags


def test_finds_missing_tags():
    resource_tags = [
        {"Key": "Environment", "Value": "Production"},
        {"Key": "Owner", "Value": "Platform-Team"},
    ]

    missing_tags = find_missing_tags(resource_tags)

    assert missing_tags == ["Project"]


def test_returns_empty_list_when_all_tags_exist():
    resource_tags = [
        {"Key": "Environment", "Value": "Production"},
        {"Key": "Owner", "Value": "Platform-Team"},
        {"Key": "Project", "Value": "Infrastructure-Guardian"},
    ]

    missing_tags = find_missing_tags(resource_tags)

    assert missing_tags == []


def test_returns_all_required_tags_when_none_exist():
    missing_tags = find_missing_tags([])

    assert missing_tags == ["Environment", "Owner", "Project"]