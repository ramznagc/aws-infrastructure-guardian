from src.aws.s3 import scan_bucket_security
from src.aws.ebs import scan_ebs_security
from src.aws.rds import scan_rds_security
from src.aws.ec2 import list_instances, list_security_groups
from src.aws.vpc import scan_vpc_flow_logs as discover_vpc_flow_logs
from src.security.s3_scanner import scan_s3_buckets
from src.security.ebs_scanner import scan_ebs_resources
from src.security.rds_scanner import scan_rds_instances
from src.security.iam_scanner import scan_iam_security
from src.security.scanner import scan_ec2_instances, scan_ec2_metadata_options
from src.security.security_group_scanner import scan_security_groups
from src.security.vpc_scanner import scan_vpc_flow_logs
from src.reporting.summary import build_report
from src.reporting.json_report import write_json_report


def main():
    print("AWS Infrastructure Guardian")

    all_findings = []

    # S3 Security Scan
    print("\nScanning S3 buckets...")
    bucket_details = scan_bucket_security()
    s3_findings = scan_s3_buckets(bucket_details)
    all_findings.extend(s3_findings)
    print(f"S3 buckets scanned: {len(bucket_details)}")
    print(f"S3 security findings: {len(s3_findings)}")

    # EBS Security Scan
    print("\nScanning EBS volumes and snapshots...")
    ebs_resources = scan_ebs_security()
    ebs_findings = scan_ebs_resources(ebs_resources)
    all_findings.extend(ebs_findings)
    print(f"EBS volumes scanned: {len(ebs_resources['Volumes'])}")
    print(f"EBS snapshots scanned: {len(ebs_resources['Snapshots'])}")
    print(f"EBS security findings: {len(ebs_findings)}")

    # RDS Security Scan
    print("\nScanning RDS DB instances...")
    rds_instances = scan_rds_security()
    rds_findings = scan_rds_instances(rds_instances)
    all_findings.extend(rds_findings)
    print(f"RDS instances scanned: {len(rds_instances)}")
    print(f"RDS security findings: {len(rds_findings)}")

    # EC2 Instance Scan
    print("\nScanning EC2 instances...")
    ec2_instances = list_instances()
    ec2_instance_findings = scan_ec2_instances(ec2_instances)
    all_findings.extend(ec2_instance_findings)
    print(f"EC2 instances scanned: {len(ec2_instances)}")
    print(f"EC2 instance findings: {len(ec2_instance_findings)}")

    # EC2 Instance Metadata Scan
    print("\nChecking EC2 Instance Metadata Service settings...")
    metadata_findings = scan_ec2_metadata_options(ec2_instances)
    all_findings.extend(metadata_findings)
    print(f"IMDSv2 configuration findings: {len(metadata_findings)}")

    # EC2 Security Group Scan
    print("\nScanning EC2 security groups...")
    security_groups = list_security_groups()
    security_group_findings = scan_security_groups(security_groups)
    all_findings.extend(security_group_findings)
    print(f"Security groups scanned: {len(security_groups)}")
    print(f"Security group findings: {len(security_group_findings)}")

    # VPC Flow Logs Scan
    print("\nChecking VPC Flow Logs coverage...")
    vpc_resources = discover_vpc_flow_logs()
    vpc_findings = scan_vpc_flow_logs(vpc_resources)
    all_findings.extend(vpc_findings)
    print(f"VPCs scanned: {len(vpc_resources['Vpcs'])}")
    print(f"VPC Flow Logs findings: {len(vpc_findings)}")

    # IAM Security Scan
    print("\nScanning IAM users...")
    iam_findings = scan_iam_security()
    all_findings.extend(iam_findings)
    print(f"IAM security findings: {len(iam_findings)}")

    # Build consolidated report
    report = build_report(all_findings)
    print("\nSecurity Scan Summary")
    print("---------------------")
    print(f"Total findings: {report['total_findings']}")
    for severity, count in report["severity_counts"].items():
        print(f"{severity}: {count}")

    print("\nSecurity Findings")
    for finding in all_findings:
        print(f"[{finding.severity}] {finding.resource_id}: {finding.issue}")

    write_json_report(report, "reports/security_report.json")
    print("\nJSON report saved to reports/security_report.json")


if __name__ == "__main__":
    main()
