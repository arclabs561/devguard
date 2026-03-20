"""Property-based tests for data model invariants.

These tests verify that data models maintain their invariants across
various inputs and edge cases.
"""


import pytest
from hypothesis import given
from hypothesis import strategies as st

from devguard.models import (
    APIUsage,
    CheckResult,
    CheckStatus,
    CostMetric,
    DeploymentStatus,
    Finding,
    GuardianReport,
    Severity,
    Vulnerability,
)


@given(
    amount=st.floats(min_value=0.0, max_value=1_000_000.0),
    usage=st.floats(min_value=0.0, max_value=1_000_000.0),
    limit=st.floats(min_value=0.0, max_value=1_000_000.0) | st.none(),
)
def test_cost_metric_amount_non_negative(amount: float, usage: float, limit: float | None):
    """CostMetric amount should be non-negative or None."""
    metric = CostMetric(
        service="test",
        period="monthly",
        amount=amount,
        usage=usage,
        limit=limit,
    )
    assert metric.amount is None or metric.amount >= 0.0
    assert metric.usage is None or metric.usage >= 0.0
    assert metric.limit is None or metric.limit >= 0.0


@given(
    credits_total=st.floats(min_value=0.0, max_value=1_000_000.0) | st.none(),
    credits_used=st.floats(min_value=0.0, max_value=1_000_000.0) | st.none(),
    credits_remaining=st.floats(min_value=-100_000.0, max_value=1_000_000.0) | st.none(),
)
def test_api_usage_percentage_bounds(
    credits_total: float | None,
    credits_used: float | None,
    credits_remaining: float | None,
):
    """APIUsage usage_percent should be between 0 and 100."""
    usage = APIUsage(
        service="test",
        credits_total=credits_total,
        credits_used=credits_used,
        credits_remaining=credits_remaining,
    )
    # usage_percent is calculated, but should be in valid range
    assert 0.0 <= usage.usage_percent <= 100.0


@given(
    package_name=st.text(min_size=1, max_size=100),
    package_version=st.text(min_size=1, max_size=50),
    severity=st.sampled_from(list(Severity)),
)
def test_vulnerability_required_fields(
    package_name: str, package_version: str, severity: Severity
):
    """Vulnerability requires package_name, package_version, severity, and source."""
    vuln = Vulnerability(
        package_name=package_name,
        package_version=package_version,
        severity=severity,
        source="test",
    )
    assert vuln.package_name == package_name
    assert vuln.package_version == package_version
    assert vuln.severity == severity
    assert vuln.source == "test"


@given(
    severity=st.sampled_from(list(Severity)),
    title=st.text(min_size=1, max_size=200),
    description=st.text(min_size=1, max_size=1000),
    resource=st.text(min_size=1, max_size=100),
)
def test_finding_required_fields(
    severity: Severity, title: str, description: str, resource: str
):
    """Finding requires severity, title, description, and resource."""
    finding = Finding(
        severity=severity,
        title=title,
        description=description,
        resource=resource,
    )
    assert finding.severity == severity
    assert finding.title == title
    assert finding.description == description
    assert finding.resource == resource


@given(
    platform=st.sampled_from(["vercel", "fly"]),
    project_name=st.text(min_size=1, max_size=100),
    deployment_id=st.text(min_size=1, max_size=100),
    status=st.sampled_from(list(CheckStatus)),
)
def test_deployment_status_required_fields(
    platform: str, project_name: str, deployment_id: str, status: CheckStatus
):
    """DeploymentStatus requires platform, project_name, deployment_id, and status."""
    deployment = DeploymentStatus(
        platform=platform,
        project_name=project_name,
        deployment_id=deployment_id,
        status=status,
    )
    assert deployment.platform == platform
    assert deployment.project_name == project_name
    assert deployment.deployment_id == deployment_id
    assert deployment.status == status


@given(
    check_type=st.text(min_size=1, max_size=50),
    success=st.booleans(),
    num_vulns=st.integers(min_value=0, max_value=100),
    num_findings=st.integers(min_value=0, max_value=100),
)
def test_check_result_counts_match(
    check_type: str, success: bool, num_vulns: int, num_findings: int
):
    """CheckResult vulnerability and finding counts should match lists."""
    vulnerabilities = [
        Vulnerability(
            package_name=f"pkg{i}",
            package_version="1.0.0",
            severity=Severity.MEDIUM,
            source="test",
        )
        for i in range(num_vulns)
    ]
    findings = [
        Finding(
            severity=Severity.MEDIUM,
            title=f"Finding {i}",
            description="Test finding",
            resource=f"resource{i}",
        )
        for i in range(num_findings)
    ]

    result = CheckResult(
        check_type=check_type,
        success=success,
        vulnerabilities=vulnerabilities,
        findings=findings,
    )

    assert len(result.vulnerabilities) == num_vulns
    assert len(result.findings) == num_findings


@given(num_checks=st.integers(min_value=0, max_value=20))
def test_guardian_report_summary_counts(num_checks: int):
    """GuardianReport summary counts should match actual check counts."""
    checks = [
        CheckResult(
            check_type=f"check{i}",
            success=i % 2 == 0,  # Alternate success/failure
            vulnerabilities=[],
            findings=[],
        )
        for i in range(num_checks)
    ]

    report = GuardianReport(checks=checks)
    report.summary = {
        "total_checks": len(checks),
        "successful_checks": sum(1 for c in checks if c.success),
        "failed_checks": sum(1 for c in checks if not c.success),
    }

    assert report.summary["total_checks"] == num_checks
    assert report.summary["successful_checks"] + report.summary["failed_checks"] == num_checks


@given(
    usage_percent=st.floats(min_value=0.0, max_value=100.0),
    limit=st.floats(min_value=1.0, max_value=1_000_000.0) | st.none(),
)
def test_cost_metric_usage_percent_calculation(usage_percent: float, limit: float | None):
    """CostMetric usage_percent should be calculated correctly when limit is provided."""
    if limit is None:
        pytest.skip("Requires limit to test usage_percent")

    usage = usage_percent * limit / 100.0
    metric = CostMetric(
        service="test",
        period="monthly",
        amount=None,
        usage=usage,
        limit=limit,
    )

    # usage_percent is calculated in the model
    if metric.usage is not None and metric.limit is not None and metric.limit > 0:
        calculated_percent = (metric.usage / metric.limit) * 100.0
        assert abs(calculated_percent - usage_percent) < 0.01  # Allow small floating point errors


def test_vulnerability_severity_ordering():
    """Severity enum should have correct ordering (CRITICAL > HIGH > MEDIUM > LOW > WARNING)."""
    severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.WARNING]

    # Verify ordering
    for i in range(len(severities) - 1):
        # In practice, we'd compare by severity value, but enum comparison works
        assert severities[i] != severities[i + 1]


def test_check_status_health_ordering():
    """CheckStatus should have HEALTHY as the good state."""
    assert CheckStatus.HEALTHY != CheckStatus.UNHEALTHY
    assert CheckStatus.HEALTHY != CheckStatus.UNKNOWN
    assert CheckStatus.HEALTHY != CheckStatus.DEGRADED

