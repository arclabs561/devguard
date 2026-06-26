"""Tests for the PrivateDocsChecker (public-repo design/adr doc tracking)."""

import subprocess

import pytest

from devguard.checkers.private_docs import PrivateDocsChecker
from devguard.config import Settings
from devguard.models import Severity


def _init_repo(path, files=None, gitignore=None):
    """Create a real, hermetic git repo (global excludes disabled) and commit."""
    path.mkdir(parents=True)
    env_args = ["-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    # Disable the user's global gitignore so docs/adr can be tracked in the fixture.
    subprocess.run(["git", "config", "core.excludesFile", "/dev/null"], cwd=path, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", f"git@github.com:owner/{path.name}.git"],
        cwd=path,
        check=True,
    )
    for rel, content in (files or {}).items():
        f = path / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content)
    if gitignore is not None:
        (path / ".gitignore").write_text(gitignore)
    subprocess.run(["git", "add", "-A"], cwd=path, check=True)
    subprocess.run([*["git", *env_args], "commit", "-qm", "init"], cwd=path, check=True)
    return path


def _checker(scan_root, visibility_map):
    """Build a checker scoped to scan_root with visibility resolution stubbed."""
    settings = Settings(
        private_docs_check_enabled=True,
        private_docs_scan_root=str(scan_root),
    )
    checker = PrivateDocsChecker(settings)
    checker._repo_visibility = lambda repo: visibility_map.get(repo.name)  # noqa: SLF001
    return checker


def test_check_type():
    assert PrivateDocsChecker(Settings()).check_type == "private_docs"


@pytest.mark.asyncio
async def test_public_repo_tracking_adr_is_flagged(tmp_path):
    _init_repo(tmp_path / "pub-tracks", {"docs/adr/0001-x.md": "# decision\n"})
    checker = _checker(tmp_path, {"pub-tracks": "public"})

    result = await checker.check()

    assert not result.success
    assert len(result.findings) == 1
    f = result.findings[0]
    assert f.severity == Severity.HIGH
    assert "pub-tracks" in f.resource
    assert f.metadata["tracked"] == ["docs/adr/0001-x.md"]


@pytest.mark.asyncio
async def test_private_repo_tracking_adr_is_allowed(tmp_path):
    _init_repo(tmp_path / "priv-tracks", {"docs/adr/0001-x.md": "# decision\n"})
    checker = _checker(tmp_path, {"priv-tracks": "private"})

    result = await checker.check()

    assert result.success
    assert result.findings == []
    # still a candidate (it tracks the namespace), just not a violation
    assert any("priv-tracks" in c for c in result.metadata["candidates"])


@pytest.mark.asyncio
async def test_public_repo_without_design_adr_is_clean(tmp_path):
    _init_repo(tmp_path / "pub-clean", {"README.md": "# hi\n", "docs/guide.md": "x"})
    checker = _checker(tmp_path, {"pub-clean": "public"})

    result = await checker.check()

    assert result.success
    assert result.findings == []
    assert result.metadata["candidates"] == []


@pytest.mark.asyncio
async def test_gitignore_optin_is_flagged_even_without_tracked_files(tmp_path):
    _init_repo(tmp_path / "pub-optin", {"README.md": "# hi\n"}, gitignore="!docs/adr/\n")
    checker = _checker(tmp_path, {"pub-optin": "public"})

    result = await checker.check()

    assert not result.success
    assert len(result.findings) == 1
    assert result.findings[0].metadata["optin"] == ["!docs/adr/"]


@pytest.mark.asyncio
async def test_unknown_visibility_is_warning_not_high(tmp_path):
    _init_repo(tmp_path / "unknown-vis", {"docs/design/plan.md": "x"})
    checker = _checker(tmp_path, {"unknown-vis": None})

    result = await checker.check()

    assert not result.success
    assert result.findings[0].severity == Severity.WARNING


@pytest.mark.asyncio
async def test_local_only_repo_without_remote_is_skipped(tmp_path):
    repo = _init_repo(tmp_path / "local-only", {"docs/adr/0001-x.md": "# decision\n"})
    subprocess.run(["git", "remote", "remove", "origin"], cwd=repo, check=True)
    checker = _checker(tmp_path, {})  # no remote -> cannot be exposed -> skipped

    result = await checker.check()

    assert result.success
    assert result.findings == []
    assert any("local-only" in c for c in result.metadata["candidates"])
