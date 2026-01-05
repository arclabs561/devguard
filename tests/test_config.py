"""Tests for configuration."""

import os
from unittest.mock import patch

from guardian.config import Settings, get_settings


def test_settings_loads_from_env():
    """Test that settings load from environment variables."""
    with patch.dict(
        os.environ,
        {
            "GITHUB_TOKEN": "test_token",
            "VERCEL_TOKEN": "test_vercel",
            "NPM_PACKAGES_TO_MONITOR": "package1,package2",
        },
        clear=False,
    ):
        settings = Settings()
        # SecretStr requires .get_secret_value() to compare
        assert settings.github_token.get_secret_value() == "test_token"
        assert settings.vercel_token.get_secret_value() == "test_vercel"
        assert "package1" in settings.npm_packages_to_monitor
        assert "package2" in settings.npm_packages_to_monitor


def test_settings_parses_comma_separated_lists():
    """Test that comma-separated lists are parsed correctly."""
    with patch.dict(
        os.environ,
        {
            "GITHUB_TOKEN": "test",
            "VERCEL_TOKEN": "test",
            "GITHUB_REPOS_TO_MONITOR": "owner/repo1,owner/repo2",
        },
    ):
        settings = Settings()
        assert len(settings.github_repos_to_monitor) == 2
        assert "owner/repo1" in settings.github_repos_to_monitor
        assert "owner/repo2" in settings.github_repos_to_monitor


def test_get_settings():
    """Test get_settings function."""
    settings = get_settings()
    assert isinstance(settings, Settings)
