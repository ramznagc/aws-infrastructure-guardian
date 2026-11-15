
from src.aws.s3 import scan_bucket_security
from src.aws.ebs import scan_ebs_security
from src.security.s3_scanner import scan_s3_buckets
from src.security.ebs_scanner import scan_ebs_resources
from src.security.iam_scanner import scan_iam_security
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

    # Display findings
    print("\nSecurity Findings")

    for finding in all_findings:
        print(
            f"[{finding.severity}] "
            f"{finding.resource_id}: {finding.issue}"
        )

    # Export JSON report
    write_json_report(
        report,
        "reports/security_report.json",
    )

    print("\nJSON report saved to reports/security_report.json")


if __name__ == "__main__":
    main()
