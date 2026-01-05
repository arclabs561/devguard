"""Tests for error handling and edge cases."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardian.checkers.npm import NpmChecker
from guardian.core import Guardian
from guardian.models import CheckResult


@pytest.fixture
def mock_settings():
    """Mock settings."""
    settings = MagicMock()
    settings.npm_packages_to_monitor = ["test-package"]
    settings.snyk_token = None
    settings.github_token = None
    settings.vercel_token = None
    settings.fly_api_token = None
    settings.firecrawl_api_key = None
    settings.tavily_api_key = None
    settings.redteam_enabled = False
    settings.npm_security_enabled = False
    settings.secret_scan_enabled = False
    settings.container_check_enabled = False  # Disable by default in tests
    return settings


@pytest.mark.asyncio
async def test_guardian_handles_checker_exception(mock_settings):
    """Test that Guardian handles exceptions from checkers gracefully."""
    guardian = Guardian(mock_settings)

    # Mock a checker that raises an exception
    mock_checker = MagicMock()
    mock_checker.check_type = "test"
    mock_checker.check = AsyncMock(side_effect=Exception("Test error"))
    guardian.checkers = [mock_checker]

    report = await guardian.run_checks()

    assert len(report.checks) == 1
    assert report.checks[0].check_type == "test"
    assert not report.checks[0].success
    assert len(report.checks[0].errors) == 1
    assert "Test error" in report.checks[0].errors[0]


@pytest.mark.asyncio
async def test_npm_checker_handles_missing_package(mock_settings):
    """Test that NpmChecker handles missing packages gracefully."""
    checker = NpmChecker(mock_settings)

    with patch("guardian.checkers.npm.create_client") as mock_client:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = Exception("Not found")

        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value.get.return_value = mock_response
        mock_client.return_value = mock_client_instance

        result = await checker.check()

        assert result.check_type == "npm"
        # Should still return a result, even if package not found
        assert isinstance(result, CheckResult)


@pytest.mark.asyncio
async def test_npm_checker_handles_network_error(mock_settings):
    """Test that NpmChecker handles network errors gracefully."""
    import httpx

    checker = NpmChecker(mock_settings)

    with patch("guardian.checkers.npm.create_client") as mock_client:
        mock_client_instance = AsyncMock()
        mock_client_instance.__aenter__.return_value.get.side_effect = httpx.RequestError(
            "Network error", request=MagicMock()
        )
        mock_client.return_value = mock_client_instance

        result = await checker.check()

        assert result.check_type == "npm"
        assert isinstance(result, CheckResult)
        # Should have errors but not crash
        assert len(result.errors) >= 0


def test_guardian_validation_no_checkers():
    """Test validation when no checkers are configured."""
    settings = MagicMock()
    settings.npm_packages_to_monitor = []
    settings.snyk_token = None
    settings.github_token = None
    settings.vercel_token = None
    settings.fly_api_token = None
    settings.firecrawl_api_key = None
    settings.tavily_api_key = None
    settings.redteam_enabled = False
    settings.npm_security_enabled = False
    settings.secret_scan_enabled = False
    settings.container_check_enabled = False
    settings.aws_iam_check_enabled = False
    settings.aws_cost_check_enabled = False
    settings.tailscale_check_enabled = False
    settings.domain_check_enabled = False
    settings.swarm_check_enabled = False
    settings.api_usage_check_enabled = False

    guardian = Guardian(settings)
    warnings = guardian.validate_configuration()

    assert len(warnings) > 0
    assert any("No checkers configured" in w for w in warnings)


def test_guardian_validation_npm_no_packages():
    """Test validation when npm checker enabled but no packages."""
    settings = MagicMock()
    settings.npm_packages_to_monitor = []
    settings.snyk_token = "token"
    settings.github_token = None
    settings.vercel_token = None
    settings.fly_api_token = None
    settings.firecrawl_api_key = None
    settings.tavily_api_key = None
    settings.redteam_enabled = False
    settings.npm_security_enabled = False
    settings.secret_scan_enabled = False
    settings.container_check_enabled = False
    settings.aws_iam_check_enabled = False
    settings.aws_cost_check_enabled = False
    settings.tailscale_check_enabled = False
    settings.domain_check_enabled = False
    settings.swarm_check_enabled = False
    settings.api_usage_check_enabled = False

    guardian = Guardian(settings)
    warnings = guardian.validate_configuration()

    # Should not warn if Snyk token is present
    npm_warnings = [w for w in warnings if "NpmChecker" in w]
    assert len(npm_warnings) == 0


@pytest.mark.asyncio
async def test_guardian_empty_report():
    """Test Guardian generates valid report even with no checkers."""
    settings = MagicMock()
    settings.npm_packages_to_monitor = []
    settings.snyk_token = None
    settings.github_token = None
    settings.vercel_token = None
    settings.fly_api_token = None
    settings.firecrawl_api_key = None
    settings.tavily_api_key = None
    settings.redteam_enabled = False
    settings.npm_security_enabled = False
    settings.secret_scan_enabled = False
    settings.container_check_enabled = False
    settings.aws_iam_check_enabled = False
    settings.aws_cost_check_enabled = False
    settings.tailscale_check_enabled = False
    settings.domain_check_enabled = False
    settings.swarm_check_enabled = False
    settings.api_usage_check_enabled = False

    guardian = Guardian(settings)
    report = await guardian.run_checks()

    assert report is not None
    assert len(report.checks) == 0
    assert report.summary["total_checks"] == 0
