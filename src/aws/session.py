import boto3


def get_session(region_name=None):
    return boto3.Session(region_name=region_name)