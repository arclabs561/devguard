"""Tests for repo_lint: own-crate pin drift, README versions, metadata, CI gaps."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from devguard.sweeps.repo_lint import lint_repos, requirement_allows


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")


@pytest.mark.parametrize(
    ("req", "version", "allowed"),
    [
        ("0.2.1", (0, 2, 5), True),
        ("0.2.1", (0, 3, 2), False),
        ("^1.2", (1, 9, 0), True),
        ("1.2", (2, 0, 0), False),
        ("0.1", (0, 1, 9), True),
        ("0.0.3", (0, 0, 4), False),
        ("~1.2.3", (1, 2, 9), True),
        ("~1.2.3", (1, 3, 0), False),
        ("=0.4.0", (0, 4, 1), False),
        ("0.5", (0, 4, 9), False),
        (">=0.1, <0.5", (0, 9, 0), None),
        ("*", (9, 9, 9), None),
    ],
)
def test_requirement_allows_follows_cargo_semantics(req, version, allowed) -> None:
    assert requirement_allows(req, version) is allowed


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", *args],
        cwd=repo,
        check=True,
        capture_output=True,
    )


def _crate(
    root: Path, name: str, toml: str, files: dict[str, str] | None = None, tag: str | None = None
) -> Path:
    repo = root / name
    repo.mkdir(parents=True)
    (repo / "Cargo.toml").write_text(toml)
    for rel, text in (files or {}).items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_text(text)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "init")
    if tag:
        _git(repo, "tag", tag)
    return repo


CI_OK = {".github/workflows/ci.yml": "steps:\n  - run: cargo clippy -- -D warnings\n"}


def test_pin_drift_against_released_version(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    _crate(
        root,
        "fynch",
        '[package]\nname = "fynch"\nversion = "0.3.2"\nrust-version = "1.80"\n',
        CI_OK,
        tag="v0.3.2",
    )
    # Local version ahead of its last tag: drift is judged against the tag.
    _crate(
        root,
        "innr",
        '[package]\nname = "innr"\nversion = "0.7.0-dev"\nrust-version = "1.80"\n',
        CI_OK,
        tag="v0.6.3",
    )
    _crate(
        root,
        "hopfield",
        '[package]\nname = "hopfield"\nversion = "0.2.2"\nrust-version = "1.80"\n'
        '[dependencies]\nfynch = "0.2.1"\ninnr = "0.6"\nserde = "1"\n',
        CI_OK,
    )

    report, errors = lint_repos(dev_root=root, max_depth=1)

    assert errors == []
    assert [(Path(f["repo_path"]).name, f["check"], f["message"]) for f in report["findings"]] == [
        (
            "hopfield",
            "own_crate_pin_drift",
            'fynch = "0.2.1" excludes the released fynch 0.3.2 (fynch)',
        )
    ]


def test_readme_metadata_and_ci_gaps(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    _crate(
        root,
        "anno",
        '[workspace]\nmembers = ["crates/anno"]\n',
        {
            "README.md": '```toml\nanno = "0.13"\n```\n',
            "crates/anno/Cargo.toml": '[package]\nname = "anno"\nversion = "0.14.0"\nreadme = "../../README.md"\n'
            'documentation = "https://anno.example/docs"\n',
            "fuzz/Cargo.toml": '[package]\nname = "anno-fuzz"\nversion = "0.0.0"\npublish = false\n',
            ".github/workflows/ci.yml": "steps:\n  - run: cargo clippy --all-targets\n",
        },
    )

    report, _ = lint_repos(dev_root=root, max_depth=1)

    assert sorted((f["check"], f["severity"], f["file"]) for f in report["findings"]) == [
        ("cargo_metadata", "info", "crates/anno/Cargo.toml"),
        ("cargo_metadata", "low", "crates/anno/Cargo.toml"),
        ("ci_gaps", "low", ".github/workflows/"),
        ("ci_gaps", "low", "fuzz/"),
        ("readme_version_drift", "low", "README.md"),
    ]


def test_clean_crate_has_no_findings(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    _crate(
        root,
        "clean",
        '[package]\nname = "clean"\nversion = "1.2.0"\nrust-version = "1.80"\n'
        'documentation = "https://docs.rs/clean"\n',
        {**CI_OK, "README.md": 'clean = "1.2"\n'},
    )

    report, _ = lint_repos(dev_root=root, max_depth=1)

    assert report["findings"] == []
