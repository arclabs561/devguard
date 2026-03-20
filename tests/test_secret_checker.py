"""Tests for the SecretChecker."""

import shutil
from pathlib import Path

import pytest

from devguard.checkers.secret import SecretChecker
from devguard.config import Settings


@pytest.fixture
def settings():
    """Create test settings."""
    return Settings(
        secret_scan_enabled=True,
        secret_scan_paths=[],  # Will use defaults
    )


@pytest.fixture
def temp_git_repo(tmp_path):
    """Create a temporary git repo for testing."""
    repo_path = tmp_path / "test-repo"
    repo_path.mkdir()
    git_dir = repo_path / ".git"
    git_dir.mkdir()
    # Create minimal git structure
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n")
    (git_dir / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    return repo_path


class TestSecretChecker:
    """Tests for SecretChecker."""

    def test_init(self, settings):
        """Test checker initialization."""
        checker = SecretChecker(settings)
        assert checker.check_type == "secret"

    def test_trufflehog_detection(self, settings):
        """Test that checker detects if trufflehog is installed."""
        checker = SecretChecker(settings)
        # trufflehog should be installed in the test environment
        if shutil.which("trufflehog"):
            assert checker.trufflehog_path is not None
        else:
            assert checker.trufflehog_path is None

    @pytest.mark.asyncio
    async def test_check_no_trufflehog(self, settings):
        """Test check returns warning when trufflehog not installed."""
        checker = SecretChecker(settings)
        checker.trufflehog_path = None  # Simulate not installed

        result = await checker.check()

        # Falls back to regex, so may still succeed if no secrets found
        # But should warn that trufflehog is not available
        assert any("trufflehog not found" in e.lower() for e in result.errors)

    @pytest.mark.asyncio
    async def test_check_clean_repo(self, settings, temp_git_repo):
        """Test check on a repo with no secrets."""
        settings = Settings(
            secret_scan_enabled=True,
            secret_scan_paths=[str(temp_git_repo.parent)],
        )
        checker = SecretChecker(settings)

        if not checker.trufflehog_path:
            pytest.skip("trufflehog not installed")

        result = await checker.check()

        # Clean repo should have no vulnerabilities
        assert result.success
        assert len(result.vulnerabilities) == 0

    @pytest.mark.asyncio
    async def test_parse_finding(self, settings):
        """Test parsing a trufflehog JSON finding."""
        checker = SecretChecker(settings)

        finding = {
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {
                "Data": {
                    "Git": {
                        "file": "config.py",
                        "commit": "abc123def456",
                    }
                }
            },
        }

        vuln = checker._parse_finding(finding, Path("/test/repo"))

        assert vuln is not None
        assert vuln.severity.value == "critical"
        assert "AWS" in vuln.summary
        assert "config.py" in vuln.package_name
        assert vuln.source == "trufflehog"

    @pytest.mark.asyncio
    async def test_parse_unverified_finding_returns_none(self, settings):
        """Test that unverified findings are ignored."""
        checker = SecretChecker(settings)

        finding = {
            "DetectorName": "AWS",
            "Verified": False,  # Not verified
            "Raw": "AKIAIOSFODNN7EXAMPLE",
        }

        vuln = checker._parse_finding(finding, Path("/test/repo"))

        assert vuln is None

    def test_get_repos_to_scan_defaults(self, settings):
        """Test default repo detection."""
        checker = SecretChecker(settings)
        repos = checker._get_repos_to_scan()

        # Should find either the surrounding workspace repos (when present)
        # or fall back to scanning Guardian itself (so the tool can self-audit).
        repo_names = [r.name for r in repos]
        assert any(
            name in repo_names
            for name in ["infra", "_infra", "accounting", "dossier", "www", "devguard"]
        )

    def test_get_repos_to_scan_configured(self, settings, temp_git_repo):
        """Test configured repo paths."""
        settings = Settings(
            secret_scan_enabled=True,
            secret_scan_paths=[str(temp_git_repo)],
        )
        checker = SecretChecker(settings)

        repos = checker._get_repos_to_scan()

        assert len(repos) == 1
        assert repos[0] == temp_git_repo


class TestSecretCheckerIntegration:
    """Integration tests requiring trufflehog installed."""

    @pytest.mark.asyncio
    async def test_full_check_on_infra_repos(self, settings):
        """Test full check scans at least one repo successfully."""
        checker = SecretChecker(settings)

        if not checker.trufflehog_path:
            pytest.skip("trufflehog not installed")

        result = await checker.check()

        # Verify scanning works (may find historical secrets that need cleanup)
        assert "repos_scanned" in result.metadata
        scanned = result.metadata["repos_scanned"]
        assert len(scanned) > 0, "Should scan at least one repo (monorepo or subprojects)"
        # Note: Historical OpenWeather API key exists in git history (commit 378b468d)
        # This is a known issue tracked for cleanup via git filter-repo
