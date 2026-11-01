from src.aws.s3 import scan_bucket_security
from src.security.s3_scanner import scan_s3_buckets


def main():
    print("AWS Infrastructure Guardian")

    print("\nScanning S3 buckets...")

    bucket_details = scan_bucket_security()
    findings = scan_s3_buckets(bucket_details)

    print(f"\nS3 buckets scanned: {len(bucket_details)}")
    print(f"S3 security findings: {len(findings)}")

    for finding in findings:
        print(
            f"[{finding.severity}] "
            f"{finding.resource_id}: {finding.issue}"
        )


if __name__ == "__main__":
    main()