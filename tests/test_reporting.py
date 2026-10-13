from src.reporting.summary import build_report
from src.security.finding import SecurityFinding


def test_build_report_counts_findings():
    finding = SecurityFinding(
        resource_id="i-123",
        issue="Public IP assigned",
        severity="MEDIUM",
        description="Review network rules",
    )

    report = build_report([finding])

    assert report["total_findings"] == 1
    assert report["severity_counts"]["MEDIUM"] == 1


def test_build_report_handles_no_findings():
    report = build_report([])

    assert report["total_findings"] == 0
    assert report["findings"] == []


def test_build_report_includes_compliance_results():
    compliance = {"missing_tags": ["Project"]}

    report = build_report([], compliance_results=compliance)

    assert report["compliance_results"] == compliance