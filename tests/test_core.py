"""Tests for core guardian functionality."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from guardian.core import Guardian
from guardian.models import CheckResult, CheckStatus, DeploymentStatus, Severity, Vulnerability


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock()
    settings.npm_packages_to_monitor = []
    settings.snyk_token = None
    settings.github_token = None
    settings.vercel_token = None
    settings.fly_api_token = None
    settings.firecrawl_api_key = None
    settings.tavily_api_key = None
    settings.check_interval_seconds = 3600
    # Disable optional checkers by default
    settings.redteam_enabled = False
    settings.npm_security_enabled = False
    settings.secret_scan_enabled = False
    settings.container_check_enabled = False  # Disable by default in tests
    settings.aws_iam_check_enabled = False  # Disable by default in tests
    settings.aws_cost_check_enabled = False  # Disable by default in tests
    settings.tailscale_check_enabled = False  # Disable by default in tests
    settings.domain_check_enabled = False  # Disable by default in tests
    settings.swarm_check_enabled = False  # Disable by default in tests
    settings.api_usage_check_enabled = False  # Disable by default in tests
    return settings


@pytest.mark.asyncio
async def test_guardian_initializes_with_no_checkers(mock_settings):
    """Test that guardian initializes with no checkers when no tokens are set."""
    guardian = Guardian(mock_settings)
    assert len(guardian.checkers) == 0


@pytest.mark.asyncio
async def test_guardian_initializes_npm_checker(mock_settings):
    """Test that guardian initializes npm checker when packages are configured."""
    mock_settings.npm_packages_to_monitor = ["package1", "package2"]
    guardian = Guardian(mock_settings)
    # May include additional checkers like NpmSecurityChecker
    assert len(guardian.checkers) >= 1
    checker_types = [c.check_type for c in guardian.checkers]
    assert "npm" in checker_types


@pytest.mark.asyncio
async def test_guardian_initializes_github_checker(mock_settings):
    """Test that guardian initializes GitHub checker when token is set."""
    mock_settings.github_token = "test_token"
    guardian = Guardian(mock_settings)
    assert len(guardian.checkers) == 1
    assert guardian.checkers[0].check_type == "gh"


@pytest.mark.asyncio
async def test_guardian_initializes_vercel_checker(mock_settings):
    """Test that guardian initializes Vercel checker when token is set."""
    mock_settings.vercel_token = "test_token"
    guardian = Guardian(mock_settings)
    # May include additional checkers like RedTeamChecker
    assert len(guardian.checkers) >= 1
    checker_types = [c.check_type for c in guardian.checkers]
    assert "vercel" in checker_types


@pytest.mark.asyncio
async def test_guardian_initializes_fly_checker(mock_settings):
    """Test that guardian initializes Fly checker when token is set."""
    mock_settings.fly_api_token = "test_token"
    guardian = Guardian(mock_settings)
    # May include additional checkers like RedTeamChecker
    assert len(guardian.checkers) >= 1
    checker_types = [c.check_type for c in guardian.checkers]
    assert "fly" in checker_types


@pytest.mark.asyncio
async def test_guardian_runs_checks_successfully(mock_settings):
    """Test that guardian runs checks and generates report."""
    mock_settings.github_token = "test_token"
    guardian = Guardian(mock_settings)

    # Mock the checker
    mock_checker = AsyncMock()
    mock_checker.check_type = "github"
    mock_checker.check.return_value = CheckResult(
        check_type="gh",
        success=True,
        vulnerabilities=[],
        deployments=[],
        repository_alerts=[],
        errors=[],
    )
    guardian.checkers = [mock_checker]

    report = await guardian.run_checks()

    assert report is not None
    assert len(report.checks) == 1
    assert report.checks[0].success is True
    assert "total_checks" in report.summary
    assert report.summary["total_checks"] == 1
    assert report.summary["successful_checks"] == 1
    assert report.summary["failed_checks"] == 0


@pytest.mark.asyncio
async def test_guardian_handles_checker_failure(mock_settings):
    """Test that guardian handles checker failures gracefully."""
    mock_settings.github_token = "test_token"
    guardian = Guardian(mock_settings)

    # Mock a failing checker
    mock_checker = AsyncMock()
    mock_checker.check_type = "github"
    mock_checker.check.side_effect = Exception("Check failed")
    guardian.checkers = [mock_checker]

    report = await guardian.run_checks()

    assert report is not None
    assert len(report.checks) == 1
    assert report.checks[0].success is False
    assert len(report.checks[0].errors) > 0
    assert "Check failed" in report.checks[0].errors[0]
    assert report.summary["failed_checks"] == 1


@pytest.mark.asyncio
async def test_guardian_calculates_summary_correctly(mock_settings):
    """Test that guardian calculates summary statistics correctly."""
    mock_settings.github_token = "test_token"
    guardian = Guardian(mock_settings)

    # Create mock checkers with various results
    mock_checker1 = AsyncMock()
    mock_checker1.check_type = "github"
    mock_checker1.check.return_value = CheckResult(
        check_type="gh",
        success=True,
        vulnerabilities=[
            Vulnerability(
                package_name="vuln-pkg",
                package_version="1.0.0",
                severity=Severity.CRITICAL,
                source="gh",
            )
        ],
        deployments=[],
        repository_alerts=[],
        errors=[],
    )

    mock_checker2 = AsyncMock()
    mock_checker2.check_type = "vercel"
    mock_checker2.check.return_value = CheckResult(
        check_type="vercel",
        success=True,
        vulnerabilities=[],
        deployments=[
            DeploymentStatus(
                platform="vercel",
                project_name="test",
                deployment_id="dpl_123",
                status=CheckStatus.UNHEALTHY,
            )
        ],
        repository_alerts=[],
        errors=[],
    )

    guardian.checkers = [mock_checker1, mock_checker2]

    report = await guardian.run_checks()

    assert report.summary["total_checks"] == 2
    assert report.summary["successful_checks"] == 2
    assert report.summary["total_vulnerabilities"] == 1
    assert report.summary["critical_vulnerabilities"] == 1
    assert report.summary["unhealthy_deployments"] == 1
