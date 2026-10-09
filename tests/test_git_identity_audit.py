"""Tests for git identity audit sweep."""

from __future__ import annotations

import json
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
    subprocess.run(
        ["git", "init", "--quiet", "--initial-branch=main"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
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
    assert findings[0]["email"] == "<redacted>"
    assert findings[0]["domain"] == "<redacted>"
    assert findings[0]["email_hash"].startswith("sha256:")
    assert "oldcorp.example" not in json.dumps(report)


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


def test_loads_policy_values_from_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path)
    subprocess.run(
        ["git", "config", "user.email", "person@oldcorp.example"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    (tmp_path / ".env").write_text("DEVGUARD_TEST_FORBIDDEN_DOMAINS=oldcorp.example\n")
    monkeypatch.chdir(tmp_path)

    report, errors = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        forbidden_email_domains_env="DEVGUARD_TEST_FORBIDDEN_DOMAINS",
        check_global_config=False,
        check_environment=False,
    )

    assert errors == []
    assert report["summary"]["repo_config_findings"] == 1


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
    assert history_findings[0]["email"] == "<redacted>"
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
    assert findings[0]["domain"] == "<redacted>"


def test_can_emit_unredacted_identity_findings_when_requested(tmp_path: Path) -> None:
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
        redact_emails=False,
    )

    assert errors == []
    repo_entry = _repo_entry(report, "repo")
    assert repo_entry is not None
    finding = repo_entry["findings"][0]
    assert finding["email"] == "person@oldcorp.example"
    assert finding["domain"] == "oldcorp.example"


def _repo_entry(report: dict, name: str) -> dict | None:
    for entry in report["repos"]:
        if name in entry["repo_path"]:
            return entry
    return None


def _commit_as(repo: Path, email: str, name: str = "x") -> None:
    (repo / f"{abs(hash(email))}.txt").write_text(email)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", f"user.email={email}", "-c", "user.name=t", "commit", "-qm", name],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _history_checks(report: dict) -> list[tuple[str, str]]:
    return sorted(
        (f["check_id"], f["email"]) for f in report["findings"] if f["source"].startswith("git log")
    )


def test_employer_domain_in_history_flagged_without_config(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    for email in (
        "person@gmail.com",
        "person@bigcorp.com",
        "123+person@users.noreply.github.com",
        "dependabot[bot]@users.noreply.github.com",
    ):
        _commit_as(repo, email)

    report, _ = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        check_history=True,
        flag_employer_domains=True,
        redact_emails=False,
        check_global_config=False,
        check_environment=False,
    )

    assert _history_checks(report) == [("possible_employer_email", "person@bigcorp.com")]


def test_allowed_emails_flag_every_other_address(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path)
    for email in ("me@gmail.com", "me@mydomain.io", "other@gmail.com", "me@bigcorp.com"):
        _commit_as(repo, email)

    report, _ = audit_git_identity(
        dev_root=tmp_path,
        max_depth=1,
        check_history=True,
        flag_employer_domains=True,
        allowed_emails=["Me@Gmail.com", "me@mydomain.io"],
        redact_emails=False,
        check_global_config=False,
        check_environment=False,
    )

    assert _history_checks(report) == [
        ("unexpected_git_email", "me@bigcorp.com"),
        ("unexpected_git_email", "other@gmail.com"),
    ]


def test_own_global_domain_is_not_an_employer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("[user]\n\temail = me@mydomain.io\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    repo = _init_repo(tmp_path / "ws")
    _commit_as(repo, "me@mydomain.io")
    _commit_as(repo, "me@bigcorp.com")

    report, _ = audit_git_identity(
        dev_root=tmp_path / "ws",
        max_depth=1,
        check_history=True,
        flag_employer_domains=True,
        redact_emails=False,
        check_environment=False,
    )

    assert _history_checks(report) == [("possible_employer_email", "me@bigcorp.com")]


def test_sweep_only_flags_employer_history_with_default_spec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from typer.testing import CliRunner

    from devguard.cli import app

    repo = _init_repo(tmp_path / "ws")
    _commit_as(repo, "person@bigcorp.com")
    monkeypatch.chdir(tmp_path)  # no devguard.spec.yaml

    result = CliRunner().invoke(
        app, ["sweep", "--repo", str(repo), "--only", "git_identity_audit", "--format", "json"]
    )

    payload = json.loads(result.stdout[result.stdout.index("{") :])
    checks = [f["check_id"] for f in payload["git_identity_audit"]["findings"]]
    assert checks == ["possible_employer_email"]


def test_employer_heuristic_ignores_other_contributors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("[user]\n\temail = me@gmail.com\n\tname = Me Person\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    repo = _init_repo(tmp_path / "ws")
    for email, name in (
        ("me@gmail.com", "Me Person"),
        ("me.person@bigcorp.com", "Me Person"),  # the user, at work
        ("dev@upstream.io", "Upstream Dev"),  # someone else's commit in a fork
    ):
        (repo / f"{name}-{email}.txt").write_text("x")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", f"user.email={email}", "-c", f"user.name={name}", "commit", "-qm", "c"],
            cwd=repo,
            check=True,
            capture_output=True,
        )

    report, _ = audit_git_identity(
        dev_root=tmp_path / "ws",
        max_depth=1,
        check_history=True,
        flag_employer_domains=True,
        redact_emails=False,
        check_environment=False,
    )

    assert _history_checks(report) == [("possible_employer_email", "me.person@bigcorp.com")]


def test_allowlist_ignores_other_contributors_and_marks_local_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("[user]\n\temail = me@gmail.com\n\tname = Me Person\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    remote = tmp_path / "remote.git"
    subprocess.run(["git", "init", "-q", "--bare", str(remote)], check=True)
    repo = _init_repo(tmp_path / "ws")

    def commit(email: str, name: str) -> None:
        (repo / f"{name}-{email}.txt").write_text("x")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", f"user.email={email}", "-c", f"user.name={name}", "commit", "-qm", "c"],
            cwd=repo,
            check=True,
            capture_output=True,
        )

    commit("me@gmail.com", "Me Person")
    commit("dev@upstream.io", "Upstream Dev")  # vendored contributor: not judged
    subprocess.run(["git", "remote", "add", "origin", str(remote)], cwd=repo, check=True)
    subprocess.run(
        ["git", "push", "-q", "origin", "main"], cwd=repo, check=True, capture_output=True
    )
    subprocess.run(["git", "switch", "-q", "-c", "backup/old"], cwd=repo, check=True)
    commit("me@bigcorp.com", "Me Person")  # only on a local backup branch

    report, _ = audit_git_identity(
        dev_root=tmp_path / "ws",
        max_depth=1,
        check_history=True,
        allowed_emails=["me@gmail.com"],
        redact_emails=False,
        check_environment=False,
    )

    hist = [f for f in report["findings"] if f["source"].startswith("git log")]
    assert [(f["check_id"], f["email"], f["on_remote"]) for f in hist] == [
        ("unexpected_git_email", "me@bigcorp.com", False)
    ]


def test_aliases_and_hostname_defaults_count_as_the_user(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import getpass

    gitconfig = tmp_path / "gitconfig"
    gitconfig.write_text("[user]\n\temail = me@gmail.com\n\tname = Me Person\n")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
    monkeypatch.setattr(getpass, "getuser", lambda: "mp")
    repo = _init_repo(tmp_path / "ws")
    for email, name in (
        ("me@gmail.com", "Me Person"),
        ("mp@Mes-MacBook-Pro.local", "Me"),  # first name, hostname default
        ("mp@shop.example.co", "mp"),  # OS account name, unknown domain
        ("dev@upstream.io", "Upstream Dev"),
    ):
        (repo / f"{name}-{email}.txt").write_text("x")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
        subprocess.run(
            ["git", "-c", f"user.email={email}", "-c", f"user.name={name}", "commit", "-qm", "c"],
            cwd=repo,
            check=True,
            capture_output=True,
        )

    report, _ = audit_git_identity(
        dev_root=tmp_path / "ws",
        max_depth=1,
        check_history=True,
        flag_employer_domains=True,
        redact_emails=False,
        check_environment=False,
    )

    assert _history_checks(report) == [
        ("hostname_default_email", "mp@mes-macbook-pro.local"),
        ("possible_employer_email", "mp@shop.example.co"),
    ]
