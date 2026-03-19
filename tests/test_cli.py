"""Tests for CLI interface."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from typer.testing import CliRunner

from guardian.cli import app, main


@pytest.fixture
def runner():
    """CLI test runner."""
    return CliRunner()


@pytest.fixture
def mock_settings():
    """Mock settings."""
    settings = MagicMock()
    settings.github_token = "test_token"
    settings.vercel_token = "test_vercel"
    settings.npm_packages_to_monitor = []
    settings.github_repos_to_monitor = []
    settings.fly_apps_to_monitor = []
    settings.vercel_projects_to_monitor = []
    settings.check_interval_seconds = 60
    settings.alert_webhook_url = None
    settings.alert_email = None
    settings.github_org = None
    settings.vercel_team_id = None
    settings.fly_api_token = None
    settings.snyk_token = None
    return settings


@pytest.fixture
def mock_guardian_report():
    """Mock guardian report."""
    from guardian.models import CheckResult, GuardianReport

    return GuardianReport(
        checks=[
            CheckResult(
                check_type="npm",
                success=True,
                vulnerabilities=[],
                errors=[],
            )
        ],
        summary={
            "total_checks": 1,
            "successful_checks": 1,
            "failed_checks": 0,
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
            "unhealthy_deployments": 0,
            "open_repository_alerts": 0,
        },
    )


@patch("guardian.cli.get_settings")
@patch("guardian.cli.Guardian")
@patch("guardian.cli.Reporter")
def test_check_command_basic(
    mock_reporter_class,
    mock_guardian_class,
    mock_get_settings,
    runner,
    mock_settings,
    mock_guardian_report,
):
    """Test basic check command."""
    mock_get_settings.return_value = mock_settings
    mock_guardian = MagicMock()
    mock_guardian.run_checks = AsyncMock(return_value=mock_guardian_report)
    mock_guardian_class.return_value = mock_guardian

    mock_reporter = MagicMock()
    mock_reporter.report = AsyncMock()
    mock_reporter_class.return_value = mock_reporter

    with patch("guardian.cli.asyncio.run") as mock_asyncio_run:
        result = runner.invoke(app, ["check"])

        assert result.exit_code == 0
        mock_asyncio_run.assert_called_once()
        # asyncio.run() would normally await the coroutine; our mock doesn't, so close it to
        # avoid "coroutine was never awaited" warnings during pytest.
        coro = mock_asyncio_run.call_args.args[0]
        coro.close()


@patch("guardian.cli.get_settings")
@patch("guardian.cli.Guardian")
@patch("guardian.cli.Reporter")
def test_check_command_json_output(
    mock_reporter_class,
    mock_guardian_class,
    mock_get_settings,
    runner,
    mock_settings,
    mock_guardian_report,
):
    """Test check command with JSON output."""
    mock_get_settings.return_value = mock_settings
    mock_guardian = MagicMock()
    mock_guardian.run_checks = AsyncMock(return_value=mock_guardian_report)
    mock_guardian_class.return_value = mock_guardian

    mock_reporter = MagicMock()
    mock_reporter._report_to_dict.return_value = {
        "generated_at": "2024-01-01T00:00:00Z",
        "checks": [],
    }
    mock_reporter_class.return_value = mock_reporter

    with patch("guardian.cli.asyncio.run") as mock_asyncio_run:
        result = runner.invoke(app, ["check", "--json"])

        assert result.exit_code == 0
        mock_asyncio_run.assert_called_once()
        # asyncio.run() would normally await the coroutine; our mock doesn't, so close it to
        # avoid "coroutine was never awaited" warnings during pytest.
        coro = mock_asyncio_run.call_args.args[0]
        coro.close()


@patch("guardian.cli.get_settings")
def test_config_command(mock_get_settings, runner, mock_settings):
    """Test config command."""
    mock_get_settings.return_value = mock_settings

    result = runner.invoke(app, ["config"])

    assert result.exit_code == 0
    assert "Guardian Configuration" in result.stdout
    assert "GitHub" in result.stdout
    assert "Vercel" in result.stdout


@patch("guardian.cli.get_settings")
def test_config_command_shows_configured_items(mock_get_settings, runner):
    """Test config command shows configured items."""
    settings = MagicMock()
    settings.github_token = "token"
    settings.github_org = "myorg"
    settings.github_repos_to_monitor = ["owner/repo1", "owner/repo2"]
    settings.vercel_token = "token"
    settings.vercel_team_id = "team123"
    settings.vercel_projects_to_monitor = ["project1"]
    settings.fly_api_token = "token"
    settings.fly_apps_to_monitor = ["app1", "app2"]
    settings.npm_packages_to_monitor = ["package1"]
    settings.snyk_token = "token"
    settings.check_interval_seconds = 60
    settings.alert_webhook_url = None
    settings.alert_email = None

    mock_get_settings.return_value = settings

    result = runner.invoke(app, ["config"])

    assert result.exit_code == 0
    assert "myorg" in result.stdout
    assert "owner/repo1" in result.stdout
    assert "team123" in result.stdout
    assert "project1" in result.stdout
    assert "app1" in result.stdout
    assert "package1" in result.stdout


def test_main_function():
    """Test main entry point."""
    with patch("guardian.cli.app") as mock_app:
        main()
        mock_app.assert_called_once()
