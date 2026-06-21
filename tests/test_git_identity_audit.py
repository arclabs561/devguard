"""Tests for git identity audit sweep."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from devguard.spec import load_spec
from devguard.sweeps.git_identity_audit import audit_git_identity


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")


def _init_repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "clean@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    return repo


def test_flags_forbidden_repo_config_email(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    subprocess.run(
        ["git", "config", "user.email", "person@oldcorp.example"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    report, errors = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        forbidden_email_domains=["oldcorp.example"],
        check_global_config=False,
        check_environment=False,
    )

    assert errors == []
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    findings = repo_entry["findings"]
    assert findings[0]["check_id"] == "forbidden_git_email"
    assert findings[0]["source"] == "git config --local user.email"
    assert findings[0]["email"] == "person@oldcorp.example"


def test_flags_forbidden_environment_email(tmp_path: Path) -> None:
    _init_repo(tmp_path)

    report, errors = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        forbidden_email_domains=["oldcorp.example"],
        check_global_config=False,
        check_repo_config=False,
        check_environment=True,
        env={"GIT_AUTHOR_EMAIL": "person@oldcorp.example"},
    )

    assert errors == []
    assert report["summary"]["environment_findings"] == 1
    assert report["findings"][0]["source"] == "GIT_AUTHOR_EMAIL"


def test_loads_policy_values_from_environment(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    subprocess.run(
        ["git", "config", "user.email", "person@oldcorp.example"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    report, errors = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        forbidden_email_domains_env="DEVGUARD_TEST_FORBIDDEN_DOMAINS",
        check_global_config=False,
        check_environment=False,
        env={"DEVGUARD_TEST_FORBIDDEN_DOMAINS": "oldcorp.example"},
    )

    assert errors == []
    assert report["summary"]["repo_config_findings"] == 1
    assert report["scope"]["forbidden_email_domains_count"] == 1
    assert report["scope"]["forbidden_email_domains_env"] == "DEVGUARD_TEST_FORBIDDEN_DOMAINS"
    assert "forbidden_email_domains" not in report["scope"]


def test_spec_loads_git_identity_env_fields(tmp_path: Path) -> None:
    spec_path = tmp_path / "devguard.spec.yaml"
    spec_path.write_text(
        """
name: test
sweeps:
  git_identity_audit:
    enabled: true
    forbidden_email_domains_env: DEVGUARD_TEST_FORBIDDEN_DOMAINS
    forbidden_email_patterns_env: DEVGUARD_TEST_FORBIDDEN_PATTERNS
    allowed_email_domains_env: DEVGUARD_TEST_ALLOWED_DOMAINS
""".lstrip()
    )

    spec = load_spec(spec_path)
    audit = spec.sweeps.git_identity_audit

    assert audit.forbidden_email_domains_env == "DEVGUARD_TEST_FORBIDDEN_DOMAINS"
    assert audit.forbidden_email_patterns_env == "DEVGUARD_TEST_FORBIDDEN_PATTERNS"
    assert audit.allowed_email_domains_env == "DEVGUARD_TEST_ALLOWED_DOMAINS"


def test_history_scan_flags_old_author_after_config_is_clean(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    subprocess.run(
        ["git", "config", "user.email", "person@oldcorp.example"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "--allow-empty", "-m", "seed"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "clean@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    report, errors = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        forbidden_email_domains=["oldcorp.example"],
        check_global_config=False,
        check_repo_config=True,
        check_environment=False,
        check_history=True,
    )

    assert errors == []
    assert report["summary"]["repo_config_findings"] == 0
    assert report["summary"]["history_findings"] == 1
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    history_findings = [
        f for f in repo_entry["findings"] if f["source"] == "git log --all author/committer email"
    ]
    assert len(history_findings) == 1
    assert history_findings[0]["email"] == "person@oldcorp.example"
    assert history_findings[0]["sample_commit"]
    assert "refs/heads/main" in history_findings[0]["containing_refs"]


def test_allowed_domains_flag_unexpected_current_config(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    subprocess.run(
        ["git", "config", "user.email", "person@other.example"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    report, _ = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        allowed_email_domains=["example.com"],
        check_global_config=False,
        check_environment=False,
    )

    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    findings = repo_entry["findings"]
    assert findings[0]["check_id"] == "unexpected_git_email_domain"
    assert findings[0]["domain"] == "other.example"


def _repo_entry(report: dict, name: str) -> dict | None:
    for entry in report["repos"]:
        if name in entry["repo_path"]:
            return entry
    return None
