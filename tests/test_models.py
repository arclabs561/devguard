"""Tests for data models."""

from devguard.models import (
    CheckResult,
    CheckStatus,
    DeploymentStatus,
    GuardianReport,
    Severity,
    Vulnerability,
)


def test_vulnerability_model():
    """Test Vulnerability model."""
    vuln = Vulnerability(
        package_name="test-package",
        package_version="1.0.0",
        severity=Severity.HIGH,
        source="npm",
    )
    assert vuln.package_name == "test-package"
    assert vuln.severity == Severity.HIGH


def test_deployment_status_model():
    """Test DeploymentStatus model."""
    deployment = DeploymentStatus(
        platform="vercel",
        project_name="test-project",
        deployment_id="dpl_123",
        status=CheckStatus.HEALTHY,
    )
    assert deployment.platform == "vercel"
    assert deployment.status == CheckStatus.HEALTHY


def test_guardian_report_summary():
    """Test GuardianReport summary methods."""
    report = GuardianReport(
        checks=[
            CheckResult(
                check_type="npm",
                success=True,
                vulnerabilities=[
                    Vulnerability(
                        package_name="vuln-pkg",
                        package_version="1.0.0",
                        severity=Severity.CRITICAL,
                        source="npm",
                    )
                ],
            )
        ]
    )

    assert report.get_total_vulnerabilities() == 1
    assert len(report.get_critical_vulnerabilities()) == 1


def test_guardian_report_unhealthy_deployments():
    """Test GuardianReport unhealthy deployments."""
    report = GuardianReport(
        checks=[
            CheckResult(
                check_type="vercel",
                success=True,
                deployments=[
                    DeploymentStatus(
                        platform="vercel",
                        project_name="test",
                        deployment_id="dpl_123",
                        status=CheckStatus.UNHEALTHY,
                    )
                ],
            )
        ]
    )

    unhealthy = report.get_unhealthy_deployments()
    assert len(unhealthy) == 1
    assert unhealthy[0].status == CheckStatus.UNHEALTHY
