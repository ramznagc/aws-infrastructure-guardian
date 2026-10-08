from src.aws.ec2 import list_instances


def test_list_instances():
    instances = list_instances()
    assert isinstance(instances, list)