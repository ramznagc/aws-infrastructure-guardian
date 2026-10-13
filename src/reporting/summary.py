def build_report(findings, compliance_results=None):
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for finding in findings:
        severity = finding.severity.upper()

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "findings": [
            {
                "resource_id": finding.resource_id,
                "issue": finding.issue,
                "severity": finding.severity,
                "description": finding.description,
            }
            for finding in findings
        ],
        "compliance_results": compliance_results or {},
    }