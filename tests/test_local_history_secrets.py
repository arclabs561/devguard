"""Tests for the full-history secret sweep.

The planted repo mirrors the review's dg_plant fixture: four secrets in the
tree plus a .env that was committed and then deleted. Token-shaped values are
assembled at runtime so this file does not itself match secret scanners.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from devguard.sweeps.local_history_secrets import scan_history_secrets

AWS_KEY = "AKIA" + "Q3EGRZ7NV4XJ2W5T"
AWS_SECRET = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "zQ8vN2pL4sT6"
GH_TOKEN = "ghp" + "_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
ENV_GH_TOKEN = "ghp" + "_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3i2"
PEM = (
    "-----BEGIN "
    + "PRIVATE KEY-----\n"
    + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 4
    + "\n-----END PRIVATE KEY-----\n"
)
ANTHROPIC_KEY = "sk-ant-" + "api03-" + "Xq7" * 31 + "AA"


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


def _commit_all(repo: Path, msg: str) -> None:
    _git(repo, "add", "-A", "-f")
    _git(repo, "commit", "--quiet", "-m", msg)


@pytest.fixture
def planted(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    repo = root / "plant"
    (repo / "src").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "README.md").write_text("plant\n")
    _commit_all(repo, "init")

    # trufflehog's AWS detector rejects synthetic key IDs, so the deleted file
    # also carries a GitHub token that every engine recognizes.
    (repo / ".env").write_text(
        f"AWS_ACCESS_KEY_ID={AWS_KEY}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\nGITHUB_TOKEN={ENV_GH_TOKEN}\n"
    )
    _commit_all(repo, "add env")
    (repo / ".env").unlink()
    _commit_all(repo, "remove env")

    (repo / "src" / "aws.py").write_text(
        f'boto3.client("s3", aws_access_key_id="{AWS_KEY}", aws_secret_access_key="{AWS_SECRET}")\n'
    )
    (repo / ".github" / "workflows" / "release.yml").write_text(f"token: {GH_TOKEN}\n")
    (repo / "src" / "tls_fixture.txt").write_text(PEM)
    (repo / "src" / "llm.rs").write_text(f'let key = "{ANTHROPIC_KEY}";\n')
    _commit_all(repo, "add code")
    return root


def _by_file(report: dict) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for f in report["findings"]:
        out.setdefault(f["file"], []).append(f)
    return out


def test_regex_engine_finds_tree_and_deleted_secrets(planted: Path) -> None:
    report, errors = scan_history_secrets(dev_root=planted, max_depth=2, engine="regex")

    found = _by_file(report)
    assert set(found) == {
        ".env",
        "src/aws.py",
        ".github/workflows/release.yml",
        "src/tls_fixture.txt",
        "src/llm.rs",
    }
    assert sorted(f["rule"] for f in found[".env"]) == [
        "AWS Access Key",
        "AWS Secret Key",
        "GitHub Token",
    ]
    assert all(f["in_head"] is False for f in found[".env"])
    assert all("still in history" in f["message"] for f in found[".env"])
    assert all(f["in_head"] is True for path, fs in found.items() if path != ".env" for f in fs)
    assert all(f["severity"] == "high" for f in report["findings"])
    assert report["summary"]["history_only_findings"] == 3
    assert report["repos"][0]["status"] == "scanned"
    assert errors  # notes that the regex fallback has narrower coverage


@pytest.mark.skipif(not shutil.which("gitleaks"), reason="gitleaks not installed")
def test_gitleaks_engine_finds_deleted_env(planted: Path) -> None:
    report, _ = scan_history_secrets(dev_root=planted, max_depth=2, engine="gitleaks")

    found = _by_file(report)
    assert report["repos"][0]["engine"] == "gitleaks"
    assert found[".env"] and all(f["in_head"] is False for f in found[".env"])
    assert {"src/aws.py", ".github/workflows/release.yml", "src/tls_fixture.txt"} <= set(found)


@pytest.mark.skipif(not shutil.which("trufflehog"), reason="trufflehog not installed")
def test_trufflehog_engine_finds_deleted_env(planted: Path) -> None:
    report, _ = scan_history_secrets(dev_root=planted, max_depth=2, engine="trufflehog")

    found = _by_file(report)
    assert report["repos"][0]["engine"] == "trufflehog"
    assert found[".env"] and all(f["in_head"] is False for f in found[".env"])
    assert {".github/workflows/release.yml", "src/llm.rs"} <= set(found)


def test_report_never_contains_secret_values(planted: Path) -> None:
    report, _ = scan_history_secrets(dev_root=planted, max_depth=2, engine="regex")

    text = str(report)
    for value in (AWS_KEY, AWS_SECRET, GH_TOKEN, ENV_GH_TOKEN, ANTHROPIC_KEY):
        assert value not in text


def test_placeholders_and_lockfiles_yield_nothing(tmp_path: Path) -> None:
    repo = tmp_path / "root" / "clean"
    repo.mkdir(parents=True)
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / ".env.example").write_text(
        "AWS_ACCESS_KEY_ID=your_key_here\nOPENAI_API_KEY=sk-...\nGITHUB_TOKEN=ghp_xxx\n"
    )
    (repo / "uv.lock").write_text(f"hash = {AWS_KEY}\n")
    (repo / "static").mkdir()
    (repo / "static" / "bundle.min.css").write_text(f".a{{content:'{AWS_KEY}'}}\n")
    _commit_all(repo, "init")

    report, _ = scan_history_secrets(dev_root=tmp_path / "root", max_depth=2, engine="regex")

    assert report["findings"] == []
    assert report["summary"]["repos_scanned"] == 1


def test_test_fixtures_are_low_severity(tmp_path: Path) -> None:
    repo = tmp_path / "root" / "lib"
    (repo / "tests").mkdir(parents=True)
    _git(repo, "init", "--quiet", "-b", "main")
    (repo / "tests" / "test_keys.py").write_text(f'FAKE = "{AWS_KEY}"\n')
    _commit_all(repo, "init")

    report, _ = scan_history_secrets(dev_root=tmp_path / "root", max_depth=2, engine="regex")

    assert [f["severity"] for f in report["findings"]] == ["low"]
    assert report["summary"]["high_findings"] == 0


def test_unrunnable_engine_reports_not_scanned(
    planted: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PATH", "/nonexistent")
    git = shutil.which("git", path="/usr/bin:/opt/homebrew/bin:/usr/local/bin")
    assert git

    report, errors = scan_history_secrets(dev_root=planted, max_depth=2, engine="gitleaks")

    assert report["repos"][0]["status"] == "not_scanned"
    assert report["summary"]["repos_not_scanned"] == 1
    assert report["summary"]["total_errors"] == 1
    assert report["findings"] == []
    assert any("gitleaks" in e for e in errors)
