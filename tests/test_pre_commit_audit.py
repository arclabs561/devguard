"""Tests for pre-commit hook audit sweep."""

from __future__ import annotations

from pathlib import Path

import yaml

from devguard.sweeps.pre_commit_audit import audit_pre_commit


def _make_repo(tmp_path: Path, name: str = "repo") -> Path:
    """Create a minimal fake git repo directory."""
    repo = tmp_path / name
    (repo / ".git").mkdir(parents=True)
    return repo


def _write_pre_commit_config(repo: Path, hooks: list[dict] | None = None) -> None:
    """Write a .pre-commit-config.yaml with the given hooks."""
    if hooks is None:
        hooks = []
    config = {"repos": [{"repo": "https://example.com", "hooks": hooks}]}
    (repo / ".pre-commit-config.yaml").write_text(yaml.dump(config))


def _install_hook(repo: Path, content: str = "#!/bin/sh\npre-commit run") -> None:
    """Create a fake .git/hooks/pre-commit file."""
    hooks_dir = repo / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook = hooks_dir / "pre-commit"
    hook.write_text(content)
    hook.chmod(0o755)


# ---------------------------------------------------------------------------
# No config
# ---------------------------------------------------------------------------


def test_no_pre_commit_config(tmp_path: Path) -> None:
    _make_repo(tmp_path, "repo")

    report, errors = audit_pre_commit(dev_root=tmp_path, max_depth=1)
    assert errors == []
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    check_ids = [f["check_id"] for f in repo_entry["findings"]]
    assert "no_pre_commit_config" in check_ids


# ---------------------------------------------------------------------------
# Config exists, hooks not installed
# ---------------------------------------------------------------------------


def test_has_config_no_hooks_installed(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, "repo")
    _write_pre_commit_config(repo, [{"id": "trailing-whitespace"}])

    report, errors = audit_pre_commit(dev_root=tmp_path, max_depth=1)
    assert errors == []
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    check_ids = [f["check_id"] for f in repo_entry["findings"]]
    assert "hook_not_installed" in check_ids


# ---------------------------------------------------------------------------
# Config and hooks installed (no secret scanning hook -> that finding only)
# ---------------------------------------------------------------------------


def test_has_config_hooks_installed(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, "repo")
    _write_pre_commit_config(repo, [{"id": "trailing-whitespace"}])
    _install_hook(repo)

    report, _ = audit_pre_commit(dev_root=tmp_path, max_depth=1)
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    check_ids = [f["check_id"] for f in repo_entry["findings"]]
    assert "hook_not_installed" not in check_ids
    # Still missing a secret scanning hook
    assert "no_secret_scanning_hook" in check_ids


# ---------------------------------------------------------------------------
# No secret scanning hook
# ---------------------------------------------------------------------------


def test_no_secret_scanning_hook(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, "repo")
    _write_pre_commit_config(repo, [{"id": "check-yaml"}, {"id": "black"}])
    _install_hook(repo)

    report, _ = audit_pre_commit(dev_root=tmp_path, max_depth=1)
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    check_ids = [f["check_id"] for f in repo_entry["findings"]]
    assert "no_secret_scanning_hook" in check_ids


# ---------------------------------------------------------------------------
# Has secret scanning hook (gitleaks)
# ---------------------------------------------------------------------------


def test_has_secret_scanning_hook(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, "repo")
    _write_pre_commit_config(repo, [{"id": "gitleaks"}, {"id": "black"}])
    _install_hook(repo)

    report, _ = audit_pre_commit(dev_root=tmp_path, max_depth=1)
    # Repo should either not appear or have no findings
    repo_entry = _repo_entry(report, "repo")
    if repo_entry is not None:
        check_ids = [f["check_id"] for f in repo_entry["findings"]]
        assert "no_secret_scanning_hook" not in check_ids


# ---------------------------------------------------------------------------
# Custom required_hooks
# ---------------------------------------------------------------------------


def test_custom_required_hooks(tmp_path: Path) -> None:
    repo = _make_repo(tmp_path, "repo")
    _write_pre_commit_config(repo, [{"id": "my-custom-scanner"}])
    _install_hook(repo)

    report, _ = audit_pre_commit(
        dev_root=tmp_path,
        max_depth=1,
        required_hooks=["my-custom-scanner"],
    )
    repo_entry = _repo_entry(report, "repo")
    # Should be clean since the required hook is present
    if repo_entry is not None:
        check_ids = [f["check_id"] for f in repo_entry["findings"]]
        assert "no_secret_scanning_hook" not in check_ids


# ---------------------------------------------------------------------------
# Report structure
# ---------------------------------------------------------------------------


def test_report_structure(tmp_path: Path) -> None:
    _make_repo(tmp_path, "repo")

    report, _ = audit_pre_commit(dev_root=tmp_path, max_depth=1)
    assert "generated_at" in report
    assert "scope" in report
    assert "summary" in report
    assert "repos" in report
    assert "errors" in report
    assert "dev_root" in report["scope"]
    assert "repos_scanned" in report["scope"]
    assert "required_hooks" in report["scope"]
    assert "repos_without_config" in report["summary"]
    assert "repos_hook_not_installed" in report["summary"]
    assert "repos_no_secret_scanning" in report["summary"]
    assert "total_findings" in report["summary"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_entry(report: dict, name: str) -> dict | None:
    """Find a repo entry by name substring in the report."""
    for entry in report["repos"]:
        if name in entry["repo_path"]:
            return entry
    return None
