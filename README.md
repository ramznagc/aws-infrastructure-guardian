# AWS Infrastructure Guardian

AWS infrastructure security, compliance, and monitoring automation platform built with Python and Boto3.

## Project Goal

AWS environments can contain many EC2 instances, S3 buckets, Lambda functions, IAM users, and CloudWatch alarms.

AWS Infrastructure Guardian is designed to provide a centralized way to:

- Discover AWS resources
- Analyze infrastructure security
- Check compliance requirements
- Detect missing resource tags
- Generate infrastructure reports
- Monitor AWS environments
- Automate security and operational checks

## Planned Architecture

```text
Developer
   |
   v
GitHub
   |
   v
GitHub Actions
   |
   v
AWS Infrastructure Guardian
   |
   +---- Boto3
   |
   +---- Security Scanner
   |
   +---- Compliance Engine
   |
   +---- Report Generator
   |
   v
AWS Account
   |
   +---- EC2
   +---- S3
   +---- Lambda
   +---- IAM
   +---- CloudWatch

## RDS Security Scanner (Day 18)

The RDS scanner discovers DB instances and reports these configuration risks:

| Check | Finding severity |
|---|---|
| Publicly accessible DB instance | CRITICAL |
| Storage encryption disabled | HIGH |
| Automated backup retention below 7 days | MEDIUM |
| Deletion protection disabled | MEDIUM |

### How it works

The AWS discovery layer uses the RDS `describe_db_instances` paginator to collect DB instance metadata. The security scanner evaluates each instance and adds findings to the consolidated Guardian report.

### Run the scanner

Run the project entry point using your configured AWS credentials and default region:

```bash
python -m src.guardian
```

The scanner performs read-only discovery; it does not create, modify, or delete AWS resources. Unit tests use mocked AWS clients, so they do not require a live AWS account.

### Recommended baseline

- Keep production databases private and restrict inbound access to trusted application networks.
- Enable encryption at rest.
- Configure automated backup retention for at least 7 days.
- Enable deletion protection for production databases.
