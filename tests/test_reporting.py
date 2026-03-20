"""Tests for reporting functionality."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from devguard.models import (
    CheckResult,
    CheckStatus,
    DeploymentStatus,
    GuardianReport,
    Severity,
    Vulnerability,
)
from devguard.reporting import Reporter


@pytest.fixture
def mock_settings():
    """Create mock settings."""
    settings = MagicMock()
    settings.alert_webhook_url = None
    settings.alert_email = None
    return settings


@pytest.fixture
def sample_report():
    """Create a sample report for testing."""
    return GuardianReport(
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
                        summary="Test vulnerability",
                    )
                ],
                deployments=[],
                repository_alerts=[],
                errors=[],
            ),
            CheckResult(
                check_type="vercel",
                success=True,
                vulnerabilities=[],
                deployments=[
                    DeploymentStatus(
                        platform="vercel",
                        project_name="test-project",
                        deployment_id="dpl_123",
                        status=CheckStatus.UNHEALTHY,
                        error_message="Deployment failed",
                    )
                ],
                repository_alerts=[],
                errors=[],
            ),
        ],
        summary={
            "total_checks": 2,
            "successful_checks": 2,
            "failed_checks": 0,
            "total_vulnerabilities": 1,
            "critical_vulnerabilities": 1,
            "unhealthy_deployments": 1,
            "open_repository_alerts": 0,
        },
    )


def test_reporter_initializes(mock_settings):
    """Test that reporter initializes correctly."""
    reporter = Reporter(mock_settings)
    assert reporter.settings == mock_settings


@pytest.mark.asyncio
async def test_reporter_prints_report(mock_settings, sample_report):
    """Test that reporter prints report to console."""
    reporter = Reporter(mock_settings)

    with patch("rich.console.Console") as mock_console_class:
        mock_console = MagicMock()
        mock_console_class.return_value = mock_console

        await reporter.report(sample_report)

        # Verify console.print was called
        assert mock_console.print.called


@pytest.mark.asyncio
async def test_reporter_sends_webhook(mock_settings, sample_report):
    """Test that reporter sends webhook when configured."""
    mock_settings.alert_webhook_url = "https://example.com/webhook"
    reporter = Reporter(mock_settings)

    with patch("devguard.http_client.create_client") as mock_create_client:
        mock_client = AsyncMock()
        mock_create_client.return_value.__aenter__.return_value = mock_client
        mock_client.post = AsyncMock()
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response

        await reporter.report(sample_report)

        # Verify webhook was called
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert call_args[0][0] == "https://example.com/webhook"
        assert "json" in call_args[1]


@pytest.mark.asyncio
async def test_reporter_handles_webhook_failure(mock_settings, sample_report):
    """Test that reporter handles webhook failures gracefully."""
    mock_settings.alert_webhook_url = "https://example.com/webhook"
    reporter = Reporter(mock_settings)

    with patch("devguard.http_client.create_client") as mock_create_client:
        mock_client = AsyncMock()
        mock_create_client.return_value.__aenter__.return_value = mock_client
        mock_client.post = AsyncMock(side_effect=Exception("Network error"))

        # Should not raise exception
        await reporter.report(sample_report)


@pytest.mark.asyncio
async def test_reporter_skips_webhook_when_not_configured(mock_settings, sample_report):
    """Test that reporter skips webhook when not configured."""
    reporter = Reporter(mock_settings)

    with patch("devguard.http_client.create_client") as mock_create_client:
        await reporter.report(sample_report)

        # Verify webhook was not called
        mock_create_client.assert_not_called()


def test_reporter_converts_report_to_dict(mock_settings, sample_report):
    """Test that reporter converts report to dictionary correctly."""
    reporter = Reporter(mock_settings)
    report_dict = reporter._report_to_dict(sample_report)

    assert "generated_at" in report_dict
    assert "summary" in report_dict
    assert "checks" in report_dict
    assert "critical_vulnerabilities" in report_dict
    assert "unhealthy_deployments" in report_dict

    assert len(report_dict["checks"]) == 2
    assert len(report_dict["critical_vulnerabilities"]) == 1
    assert len(report_dict["unhealthy_deployments"]) == 1

    # Verify structure
    check = report_dict["checks"][0]
    assert "check_type" in check
    assert "success" in check
    assert "vulnerabilities_count" in check
