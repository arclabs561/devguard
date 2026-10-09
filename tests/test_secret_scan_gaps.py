"""Regressions for secret-scan gaps found by planting secrets in a scratch repo.

Each test reproduces one way a committed or uncommitted secret went unreported.
Token-shaped values are assembled at runtime so this file does not itself match
secret scanners.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from devguard.checkers.secret import SecretChecker
from devguard.config import Settings
from devguard.sweeps import local_dirty_worktree_secrets as dirty
from devguard.sweeps.pre_commit_audit import audit_pre_commit

AWS_KEY = "AKIA" + "Q3EGRZ7NV4XJ2W5T"
GH_TOKEN = "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"
ANTHROPIC_KEY = "sk-ant-" + "api03-" + "x" * 90 + "AA"


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True)
    _git(path, "init", "--quiet", "-b", "main")
    return path


# --- regex fallback -------------------------------------------------------


@pytest.mark.asyncio
async def test_regex_fallback_finds_keys_outside_assignments(tmp_path: Path) -> None:
    repo = tmp_path / "plant"
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "src").mkdir()
    (repo / "src" / "aws.py").write_text(f'boto3.client("s3", aws_access_key_id="{AWS_KEY}")\n')
    (repo / ".github" / "workflows" / "release.yml").write_text(f"token: {GH_TOKEN}\n")
    (repo / "src" / "tls_fixture.txt").write_text(f"{PEM_HEADER}\nMIIE...\n")
    (repo / "src" / "llm.rs").write_text(f'let key = "{ANTHROPIC_KEY}";\n')

    checker = SecretChecker(Settings(secret_scan_paths=[str(repo)]))
    found = await checker._scan_with_regex(repo)

    by_file = {v.package_name.split("/", 1)[1]: v.summary or "" for v in found}
    assert set(by_file) == {
        "src/aws.py",
        ".github/workflows/release.yml",
        "src/tls_fixture.txt",
        "src/llm.rs",
    }
    assert "AWS Access Key" in by_file["src/aws.py"]
    assert "GitHub Token" in by_file[".github/workflows/release.yml"]
    assert "Private Key" in by_file["src/tls_fixture.txt"]
    assert "Anthropic API Key" in by_file["src/llm.rs"]


@pytest.mark.asyncio
async def test_regex_fallback_skips_git_dir_and_symlinks(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    # Assignment form, so even the old assignment-only pattern would match it.
    (outside / "notes.txt").write_text(f"AWS_ACCESS_KEY_ID={AWS_KEY}\n")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".git" / "packed").write_text(f"{AWS_KEY}\n")
    (repo / "link.txt").symlink_to(outside / "notes.txt")
    (repo / "clean.txt").write_text("nothing here\n")

    found = await SecretChecker(Settings())._scan_with_regex(repo)

    assert found == []


@pytest.mark.asyncio
async def test_regex_fallback_ignores_placeholders(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".env.example").write_text(
        "AWS_ACCESS_KEY_ID=your_key_here\nOPENAI_API_KEY=sk-...\nGITHUB_TOKEN=ghp_xxx\n"
    )

    found = await SecretChecker(Settings())._scan_with_regex(repo)

    assert found == []


# --- dirty worktree path discovery ---------------------------------------


def test_dirty_paths_expand_untracked_directories(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    (repo / "src" / "plant").mkdir(parents=True)
    (repo / "src" / "plant" / "aws.py").write_text("x = 1\n")
    (repo / "src" / "plant" / "llm.rs").write_text("y\n")

    paths, err = dirty._dirty_paths(repo)

    assert err is None
    assert paths == ["src/plant/aws.py", "src/plant/llm.rs"]


def test_dirty_paths_take_new_name_of_rename(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "repo")
    (repo / "old.txt").write_text("a\n")
    _git(repo, "add", "old.txt")
    _git(repo, "commit", "--quiet", "-m", "init")
    _git(repo, "mv", "old.txt", "new.txt")

    paths, err = dirty._dirty_paths(repo)

    assert err is None
    assert paths == ["new.txt"]


def _scanned_paths(monkeypatch: pytest.MonkeyPatch, root: Path, *, only_dirty: bool) -> list[str]:
    captured: list[str] = []

    def fake_run(abs_paths: list[str], *, concurrency: int, timeout_s: int):
        captured.extend(abs_paths)
        return "", []

    monkeypatch.setattr(dirty, "_run_trufflehog_filesystem", fake_run)
    dirty.scan_dirty_worktrees(
        dev_root=root,
        max_depth=2,
        only_dirty=only_dirty,
        check_upstream=False,
        max_concurrency=1,
        timeout_s=30,
    )
    return sorted(Path(p).name for p in captured)


def test_only_dirty_false_scans_committed_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _init_repo(tmp_path / "root" / "repo")
    (repo / "committed.py").write_text("x = 1\n")
    _git(repo, "add", "committed.py")
    _git(repo, "commit", "--quiet", "-m", "init")
    (repo / "dirty.py").write_text("y = 2\n")

    assert _scanned_paths(monkeypatch, tmp_path / "root", only_dirty=True) == ["dirty.py"]
    assert _scanned_paths(monkeypatch, tmp_path / "root", only_dirty=False) == [
        "committed.py",
        "dirty.py",
    ]


def test_only_dirty_false_scans_clean_repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo = _init_repo(tmp_path / "root" / "repo")
    (repo / "committed.py").write_text("x = 1\n")
    _git(repo, "add", "committed.py")
    _git(repo, "commit", "--quiet", "-m", "init")

    assert _scanned_paths(monkeypatch, tmp_path / "root", only_dirty=True) == []
    assert _scanned_paths(monkeypatch, tmp_path / "root", only_dirty=False) == ["committed.py"]


# --- trufflehog compatibility --------------------------------------------


class _Result:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def test_trufflehog_retries_without_unknown_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if dirty._SCAN_ERRORS_FLAG in cmd:
            # trufflehog 3.88 rejects the flag with this message.
            return _Result(
                1, stderr="trufflehog: error: unknown long flag '--no-fail-on-scan-errors'"
            )
        return _Result(0, stdout='{"DetectorName": "AWS"}\n')

    monkeypatch.setattr(dirty.subprocess, "run", fake_run)
    paths = [f"/r/f{i}" for i in range(dirty._TRUFFLEHOG_BATCH + 1)]

    stdout, errors = dirty._run_trufflehog_filesystem(paths, concurrency=1, timeout_s=5)

    assert errors == []
    assert stdout.count("AWS") == 2
    # First batch tries the flag, then drops it for every later call.
    assert [dirty._SCAN_ERRORS_FLAG in c for c in calls] == [True, False, False]


# --- pre_commit_audit summary --------------------------------------------


def test_pre_commit_audit_summary_has_total_errors(tmp_path: Path) -> None:
    repo = _init_repo(tmp_path / "root" / "repo")
    (repo / ".pre-commit-config.yaml").write_text(
        "repos:\n- repo: local\n  hooks:\n  - id: ruff\n    name: ruff\n    entry: ruff\n    language: system\n"
    )

    report, _ = audit_pre_commit(dev_root=tmp_path / "root", max_depth=2)

    assert report["summary"]["total_errors"] == 1


# --- --only runs a sweep that is disabled by default ----------------------


@pytest.mark.skipif(not __import__("shutil").which("trufflehog"), reason="trufflehog not installed")
def test_only_runs_disabled_sweep_like_the_precommit_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The devguard-secrets hook runs `sweep --only local_dirty_worktree_secrets`.

    That sweep is disabled by default, so before this fix the hook scanned nothing.
    """
    import json

    from typer.testing import CliRunner

    from devguard.cli import app

    repo = _init_repo(tmp_path / "repo")
    (repo / "deploy.py").write_text(f'GITHUB_TOKEN = "{GH_TOKEN}"\n')
    _git(repo, "add", "deploy.py")  # staged, as during a commit
    monkeypatch.chdir(tmp_path)  # no devguard.spec.yaml: built-in defaults

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

    assert result.exit_code == 2, result.output
    payload = json.loads(result.stdout[result.stdout.index("{") :])
    report = payload["local_dirty_worktree_secrets"]
    assert report["summary"]["findings_total"] >= 1
