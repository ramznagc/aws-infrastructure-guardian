# AWS Infrastructure Guardian

A Python and Boto3 learning project for discovering AWS resources and identifying selected infrastructure security risks. The repository contains AWS access modules, security scanners, finding/reporting components, Terraform material, a Dockerfile and automated tests.

> **Project status:** This is an evolving portfolio project. The README describes capabilities present in the repository and commit history; it is not a claim of a certified compliance product or production security service.

## Current security checks

The implementation currently includes work on:

- **IAM user security**
  - Users without MFA
  - High-privilege managed policies such as `AdministratorAccess` and `PowerUserAccess`
  - Directly attached and inline policies requiring review
  - Active access keys older than 90 days
- **EBS security**
  - Unencrypted EBS volumes
  - Unencrypted EBS snapshots
  - Publicly shared snapshots
  - Snapshot permissions that could not be verified
- **S3 security**
  - S3 discovery and security scanning modules are part of the project; review the scanner implementation for the exact checks currently enabled.

Findings are represented with resource identifiers, issue descriptions and severity levels, then combined by the guardian entry point. The EBS scanner assigns high severity to missing encryption and critical severity to public snapshots; permission checks that cannot be verified are surfaced as medium severity.

## Architecture

```text
AWS Account
   |
   +-- Boto3 AWS access modules
   |      +-- IAM discovery
   |      +-- EBS volume / snapshot discovery
   |      +-- S3 discovery
   |
   +-- Security scanners
   |      +-- IAM scanner
   |      +-- EBS scanner
   |      +-- S3 scanner
   |
   +-- Security findings
   |
   +-- Summary / JSON reporting
```

## Technology

- Python
- Boto3 / Botocore
- Pytest-style unit tests with mocks
- Docker
- Terraform material in the `terraform/` directory
- GitHub repository and source control

## Repository layout

```text
.
├── src/
│   ├── aws/          # AWS API access and resource discovery
│   ├── security/     # Security checks and finding models
│   ├── reporting/    # Summary and JSON reporting
│   └── guardian.py   # Scan orchestration
├── tests/            # Automated tests
├── terraform/        # Infrastructure-as-Code material
├── Dockerfile
└── requirements.txt
```

The exact modules evolve as new checks are added. Consult the source tree for the current implementation.

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

   On Windows PowerShell:

   ```powershell
   .venv\Scripts\Activate.ps1
   ```

3. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure AWS credentials using a secure local profile, environment or an attached IAM role. Do not put access keys in source code or commit them.

5. Run the project entry point using the command and module path currently present in the repository. Check the source tree before running if the entry point has changed.

## Tests

The repository includes mocked tests for AWS API behavior and security rule evaluation. Run the test suite with:

```bash
pytest
```

Tests that mock AWS clients help validate scanner logic without requiring live AWS resources. They do not replace integration tests against a dedicated test account.

## Security principles

- Prefer IAM roles and least-privilege permissions.
- Do not commit AWS access keys, secret values, local environment files or Terraform state.
- Treat access-denied responses as incomplete visibility, not proof that a resource is safe.
- Review findings before making remediation changes.
- Run scans against accounts where you have explicit authorization.

## Roadmap

- Expand S3 and additional AWS service checks with documented rule coverage.
- Add clear CLI options for regions and output paths.
- Improve structured JSON/HTML reports.
- Add CI workflow execution and coverage reporting.
- Add integration tests in an isolated AWS test account.
- Document the IAM permissions required for each scanner.

## Author

Ramazan Agac · [GitHub](https://github.com/ramznagc)
