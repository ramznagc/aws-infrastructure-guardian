# AWS Infrastructure Guardian

A Python and Boto3 learning project for discovering AWS resources and identifying selected infrastructure security risks. The repository contains AWS access modules, security scanners, finding/reporting components, Terraform material, a Dockerfile and automated tests.

> **Project status:** This is an evolving portfolio project. The README describes capabilities present in the repository and commit history; it is not a claim of a certified compliance product or production security service.

## Current security checks

- **IAM user security**
  - Users without MFA
  - High-privilege managed policies such as `AdministratorAccess` and `PowerUserAccess`
  - Directly attached and inline policies requiring review
  - Active access keys older than 90 days
- **EBS security**
  - Unencrypted EBS volumes and snapshots
  - Publicly shared snapshots
  - Snapshot permissions that could not be verified
- **S3 security**
  - S3 bucket discovery and security scanning
- **RDS security**
  - Publicly accessible database instances
  - Storage encryption disabled
  - Automated backup retention below 7 days
  - Deletion protection disabled
- **EC2 instance security**
  - Instances with a public IPv4 address (MEDIUM)
- **EC2 security groups**
  - SSH (TCP/22) exposed to all IPv4 or IPv6 addresses (HIGH)
  - Unrestricted protocol access exposed to all IPv4 or IPv6 addresses (HIGH)

Findings include resource identifiers, issue descriptions and severity levels, then flow into the consolidated Guardian report. A public IP is a network-exposure signal, not proof that an instance is reachable: effective reachability also depends on subnet routing, security groups and network ACLs.

## Architecture

```text
AWS Account
   |
   +-- Boto3 discovery
   |      +-- IAM
   |      +-- EC2 instances / security groups
   |      +-- EBS volumes / snapshots
   |      +-- S3 buckets
   |      +-- RDS DB instances
   |
   +-- Security scanners
   +-- Consolidated findings
   +-- Summary and JSON reporting
```

## Technology

- Python and Boto3 / Botocore
- Pytest-style unit tests with mocked AWS clients
- Docker
- Terraform material in `terraform/`
- GitHub Actions CI

## Run locally

1. Clone the repository:
   ```bash
   git clone https://github.com/ramznagc/aws-infrastructure-guardian.git
   cd aws-infrastructure-guardian
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
   On Windows PowerShell: `\.venv\Scripts\Activate.ps1`
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure AWS credentials using a secure local profile, environment or attached IAM role. Never put access keys in source code or commit them.
5. Run the Guardian:
   ```bash
   python -m src.guardian
   ```

## Tests

Run the test suite with:

```bash
pytest
```

AWS API calls in unit tests are mocked. The scanner is read-only: it discovers configuration and does not create, modify or delete AWS resources.

## Security principles

- Prefer IAM roles and least-privilege permissions.
- Do not commit AWS access keys, secret values, local environment files or Terraform state.
- Treat access-denied responses as incomplete visibility, not proof that a resource is safe.
- Review findings before making remediation changes.
- Run scans only against accounts where you have explicit authorization.

## Day 18 — RDS security scanner

The RDS discovery layer uses the `describe_db_instances` paginator. Checks cover public accessibility (CRITICAL), disabled storage encryption (HIGH), backup retention below 7 days (MEDIUM), and disabled deletion protection (MEDIUM).

## Day 19 — EC2 security-group scanner integration

The EC2 discovery layer retrieves security groups with the `describe_security_groups` paginator. The Guardian reports SSH exposed to `0.0.0.0/0` or `::/0`, and unrestricted protocol rules exposed to those ranges (HIGH).

## Day 20 — EC2 instance security scanner integration

EC2 instance discovery now uses the `describe_instances` paginator to collect instances across all response pages. The existing EC2 instance scanner is integrated into the Guardian report and flags instances with a public IPv4 address (MEDIUM).

A public IP alone does not establish that an instance is reachable from the internet; subnet routes, security-group rules and network ACLs also determine effective reachability. This check is intended as an inventory signal for review, not a definitive exposure verdict. Tests use mocked EC2 clients and do not require live AWS credentials.

## Roadmap

- Add clear CLI options for regions and output paths.
- Improve structured JSON/HTML reports.
- Add coverage reporting.
- Add integration tests in an isolated AWS test account.
- Document the IAM permissions required for each scanner.

## Author

Ramazan Agac · [GitHub](https://github.com/ramznagc)
