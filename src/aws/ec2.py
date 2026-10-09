from .session import get_session


def list_instances(region_name=None):
    session = get_session(region_name)
    ec2 = session.client("ec2")

    response = ec2.describe_instances()

    instances = []

    for reservation in response["Reservations"]:
        for instance in reservation["Instances"]:
            instances.append(
                {
                    "id": instance["InstanceId"],
                    "state": instance["State"]["Name"],
                    "type": instance["InstanceType"],
                    "public_ip": instance.get("PublicIpAddress"),
                }
            )

    return instances