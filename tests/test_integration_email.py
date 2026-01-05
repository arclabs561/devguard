"""Integration tests for email system.

Tests the email sending functionality with both SMTP and smart_email backends.
"""

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from guardian.config import Settings
from guardian.models import GuardianReport, CheckResult, Vulnerability, Severity
from guardian.reporting import Reporter


@pytest.fixture
def temp_db_path():
    """Create a temporary database path for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test_smart_email.db"


@pytest.fixture
def temp_env_file():
    """Create a temporary .env file for testing."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".env", delete=False) as f:
        yield Path(f.name)
    # Cleanup
    if Path(f.name).exists():
        os.unlink(f.name)


@pytest.fixture
def mock_settings_smtp():
    """Create mock settings for SMTP email."""
    settings = MagicMock(spec=Settings)
    settings.alert_email = "test@example.com"
    settings.smtp_host = "smtp.example.com"
    settings.smtp_port = 587
    settings.smtp_user = "user"
    settings.smtp_password = MagicMock()
    settings.smtp_password.get_secret_value.return_value = "password"
    settings.smtp_from = "guardian@example.com"
    settings.smtp_use_tls = True
    settings.email_only_on_issues = True
    settings.use_smart_email = False
    settings.email_llm_enabled = False
    settings.email_thread_id_file = None
    settings.email_history_file = None
    return settings


@pytest.fixture
def mock_settings_smart_email(temp_db_path):
    """Create mock settings for smart_email backend."""
    settings = MagicMock(spec=Settings)
    settings.alert_email = "test@example.com"
    settings.use_smart_email = True
    settings.smart_email_db_path = str(temp_db_path)
    settings.email_only_on_issues = True
    settings.email_llm_enabled = False
    settings.email_thread_id_file = None
    settings.email_history_file = None
    return settings


@pytest.fixture
def sample_report_with_issues():
    """Create a sample report with critical issues."""
    return GuardianReport(
        checks=[
            CheckResult(
                check_type="npm",
                success=False,
                vulnerabilities=[
                    Vulnerability(
                        package_name="vuln-pkg",
                        package_version="1.0.0",
                        severity=Severity.CRITICAL,
                        source="npm",
                        summary="Critical vulnerability",
                    )
                ],
                findings=[],
                errors=[],
            )
        ],
        summary={
            "total_checks": 1,
            "successful_checks": 0,
            "failed_checks": 1,
            "total_vulnerabilities": 1,
            "critical_vulnerabilities": 1,
        },
    )


@pytest.fixture
def sample_report_no_issues():
    """Create a sample report with no issues."""
    return GuardianReport(
        checks=[
            CheckResult(
                check_type="npm",
                success=True,
                vulnerabilities=[],
                findings=[],
                errors=[],
            )
        ],
        summary={
            "total_checks": 1,
            "successful_checks": 1,
            "failed_checks": 0,
            "total_vulnerabilities": 0,
            "critical_vulnerabilities": 0,
        },
    )


@pytest.mark.asyncio
async def test_email_smtp_sends_when_issues_present(mock_settings_smtp, sample_report_with_issues):
    """Test that SMTP email is sent when issues are present."""
    reporter = Reporter(mock_settings_smtp)

    with patch("aiosmtplib.SMTP") as mock_smtp_class:
        mock_smtp = AsyncMock()
        mock_smtp_class.return_value.__aenter__.return_value = mock_smtp
        mock_smtp.send_message = AsyncMock()

        await reporter._send_email(sample_report_with_issues)

        # Verify SMTP was called
        mock_smtp.send_message.assert_called_once()


@pytest.mark.asyncio
async def test_email_smtp_skips_when_no_issues(
    mock_settings_smtp, sample_report_no_issues
):
    """Test that SMTP email is skipped when no issues and email_only_on_issues=True."""
    reporter = Reporter(mock_settings_smtp)

    with patch("aiosmtplib.SMTP") as mock_smtp_class:
        await reporter._send_email(sample_report_no_issues)

        # Verify SMTP was not called
        mock_smtp_class.assert_not_called()


@pytest.mark.asyncio
async def test_email_smart_email_sends_when_issues_present(
    mock_settings_smart_email, sample_report_with_issues, temp_db_path
):
    """Test that smart_email is used when enabled and issues are present."""
    reporter = Reporter(mock_settings_smart_email)

    with patch("guardian.utils.import_smart_email") as mock_import:
        mock_smart_email = MagicMock()
        mock_smart_email.smart_send_alert = MagicMock(return_value=True)
        mock_import.return_value = mock_smart_email

        await reporter._send_email(sample_report_with_issues)

        # Verify smart_email was called
        mock_smart_email.smart_send_alert.assert_called_once()


@pytest.mark.asyncio
async def test_email_smart_email_falls_back_to_smtp(
    mock_settings_smart_email, sample_report_with_issues
):
    """Test that system falls back to SMTP if smart_email is not available."""
    reporter = Reporter(mock_settings_smart_email)
    # Add SMTP settings for fallback
    mock_settings_smart_email.smtp_host = "smtp.example.com"
    mock_settings_smart_email.smtp_port = 587
    mock_settings_smart_email.smtp_user = "user"
    mock_settings_smart_email.smtp_password = MagicMock()
    mock_settings_smart_email.smtp_password.get_secret_value.return_value = "password"
    mock_settings_smart_email.smtp_from = "guardian@example.com"
    mock_settings_smart_email.smtp_use_tls = True
    mock_settings_smart_email.email_thread_id_file = None

    with patch("guardian.utils.import_smart_email") as mock_import:
        mock_import.return_value = None  # smart_email not available

        with patch("aiosmtplib.SMTP") as mock_smtp_class:
            mock_smtp = AsyncMock()
            mock_smtp_class.return_value.__aenter__.return_value = mock_smtp
            mock_smtp.send_message = AsyncMock()
            mock_smtp.login = AsyncMock()

            await reporter._send_email(sample_report_with_issues)

            # Verify SMTP fallback was called
            mock_smtp.send_message.assert_called_once()


def test_email_history_storage_json(mock_settings_smtp, temp_env_file):
    """Test that email history is stored in JSON file."""
    mock_settings_smtp.email_history_file = str(temp_env_file)
    reporter = Reporter(mock_settings_smtp)

    # Create a minimal report
    report = GuardianReport(checks=[], summary={})

    # Record history
    reporter._record_email_history(report, "msg-123", "Test Subject", None)

    # Verify history was saved
    assert temp_env_file.exists()
    history = reporter._load_email_history()
    assert len(history) == 1
    assert history[0]["message_id"] == "msg-123"
    assert history[0]["subject"] == "Test Subject"


def test_email_history_retrieval(mock_settings_smtp, temp_env_file):
    """Test that email history can be retrieved."""
    mock_settings_smtp.email_history_file = str(temp_env_file)
    reporter = Reporter(mock_settings_smtp)

    # Add some history
    report = GuardianReport(checks=[], summary={})
    reporter._record_email_history(report, "msg-1", "Subject 1", None)
    reporter._record_email_history(report, "msg-2", "Subject 2", None)

    # Retrieve history
    history = reporter.get_email_history(limit=10)
    assert len(history) >= 2

    # Test limit
    limited = reporter.get_email_history(limit=1)
    assert len(limited) == 1

