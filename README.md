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