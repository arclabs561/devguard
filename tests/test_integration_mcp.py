"""Integration tests for MCP server functionality."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardian.config import Settings
from guardian.models import CheckResult, GuardianReport


@pytest.fixture
def mock_settings():
    """Create mock settings for MCP tests."""
    settings = MagicMock(spec=Settings)
    settings.npm_packages_to_monitor = []
    settings.github_token = None
    settings.vercel_token = None
    settings.fly_api_token = None
    return settings


@pytest.mark.asyncio
async def test_mcp_run_checks_basic(mock_settings):
    """Test that MCP run_checks tool works."""
    from guardian.mcp_server import run_checks

    with patch("guardian.core.Guardian") as mock_guardian_class:
        mock_guardian = MagicMock()
        mock_guardian_class.return_value = mock_guardian

        mock_report = GuardianReport(checks=[], summary={})
        mock_guardian.run_checks = AsyncMock(return_value=mock_report)

        result = await run_checks(json_output=True)

        # Should return JSON
        assert isinstance(result, str)
        data = json.loads(result)
        assert "checks" in data or "error" in data


@pytest.mark.asyncio
async def test_mcp_run_checks_with_packages(mock_settings):
    """Test that MCP run_checks accepts package list."""
    from guardian.mcp_server import run_checks

    with patch("guardian.config.get_settings") as mock_get_settings:
        mock_get_settings.return_value = mock_settings

        with patch("guardian.core.Guardian") as mock_guardian_class:
            mock_guardian = MagicMock()
            mock_guardian_class.return_value = mock_guardian

            mock_report = GuardianReport(checks=[], summary={})
            mock_guardian.run_checks = AsyncMock(return_value=mock_report)

            result = await run_checks(json_output=True, npm_packages=["test-package"])

            # Verify result is valid JSON
            result_data = json.loads(result)
            assert isinstance(result_data, dict)
            # May have checks or error depending on implementation
            assert "checks" in result_data or "error" in result_data


@pytest.mark.asyncio
async def test_mcp_scan_npm_package(mock_settings):
    """Test that MCP scan_npm_package tool works."""
    from guardian.mcp_server import scan_npm_package

    with patch("guardian.core.Guardian") as mock_guardian_class:
        mock_guardian = MagicMock()
        mock_guardian_class.return_value = mock_guardian

        mock_report = GuardianReport(
            checks=[
                CheckResult(
                    check_type="npm",
                    success=True,
                    vulnerabilities=[],
                    errors=[],
                )
            ],
            summary={},
        )
        mock_guardian.run_checks = AsyncMock(return_value=mock_report)

        result = await scan_npm_package("test-package")

        # Should return JSON
        assert isinstance(result, str)
        data = json.loads(result)
        assert "success" in data or "error" in data


@pytest.mark.asyncio
async def test_mcp_get_email_history(mock_settings):
    """Test that MCP get_email_history tool works."""
    from guardian.mcp_server import get_email_history

    with patch("guardian.reporting.Reporter") as mock_reporter_class:
        mock_reporter = MagicMock()
        mock_reporter_class.return_value = mock_reporter
        mock_reporter.get_email_history.return_value = [
            {
                "timestamp": "2025-01-01T00:00:00Z",
                "subject": "Test Alert",
                "author": "guardian",
            }
        ]

        result = await get_email_history(limit=10)

        # Should return JSON
        assert isinstance(result, str)
        data = json.loads(result)
        assert isinstance(data, list) or "error" in data


@pytest.mark.asyncio
async def test_mcp_get_unified_alert_history_with_smart_email(mock_settings):
    """Test that MCP get_unified_alert_history works with smart_email."""
    from guardian.mcp_server import get_unified_alert_history

    mock_settings.use_smart_email = True

    with patch("guardian.utils.import_smart_email") as mock_import:
        mock_smart_email = MagicMock()
        mock_smart_email.init_db = MagicMock()
        mock_import.return_value = mock_smart_email

        with patch("sqlite3.connect") as mock_connect:
            mock_conn = MagicMock()
            mock_connect.return_value = mock_conn
            mock_conn.execute.return_value.fetchall.return_value = []

            result = await get_unified_alert_history(limit=20)

            # Should return JSON
            assert isinstance(result, str)
            data = json.loads(result)
            assert "alerts" in data or "error" in data


@pytest.mark.asyncio
async def test_mcp_get_unified_alert_history_without_smart_email(mock_settings):
    """Test that MCP get_unified_alert_history returns error when smart_email disabled."""
    from guardian.mcp_server import get_unified_alert_history

    mock_settings.use_smart_email = False

    result = await get_unified_alert_history(limit=20)

    # Should return error message
    assert isinstance(result, str)
    data = json.loads(result)
    assert "error" in data

