"""Tests for tracked-but-ignored files, personal paths, and local path deps."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from devguard.sweeps.repo_hygiene import (
    _check_hardcoded_paths,
    _check_local_path_deps,
    _check_tracked_ignored,
    _git_ls_files,
)


@pytest.fixture(autouse=True)
def _isolate_git_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")


def _repo(path: Path, files: dict[str, str | bytes]) -> Path:
    path.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    for rel, body in files.items():
        (path / rel).parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            (path / rel).write_bytes(body)
        else:
            (path / rel).write_text(body)
    subprocess.run(["git", "add", "-f", "-A"], cwd=path, check=True)
    return path


def test_tracked_env_file_matching_gitignore_is_medium(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            ".gitignore": ".env*\n*.log\n",
            ".env.development": "X=1\n",
            ".env.example": "X=\n",
            "run.log": "x\n",
        },
    )

    f = _check_tracked_ignored(repo)

    assert f is not None
    assert f.severity == "medium"
    assert f.files[0] == ".env.development"
    assert set(f.files) == {".env.development", ".env.example", "run.log"}


def test_tracked_ignored_without_secret_names_is_low(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {".gitignore": "*.log\n", "run.log": "x\n"})

    f = _check_tracked_ignored(repo)

    assert f is not None and f.severity == "low"


def test_nothing_tracked_and_ignored(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {".gitignore": "*.log\n", "main.py": "x\n"})

    assert _check_tracked_ignored(repo) is None


def test_personal_paths_found_in_any_text_file(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "docs/setup.md": "Run /Users/alice/dev/tool/build.sh\n",
            "src/config.rs": 'let p = "C:\\\\Users\\\\bob\\\\data";\n',
            "ci.yml": "path: /home/runner/work/x\n",
            "README.md": "See /Users/example/project and /home/user/x\n",
            "blob.bin": b"\0\0/Users/carol/secret\0",
        },
    )

    f = _check_hardcoded_paths(repo, _git_ls_files(repo))

    assert f is not None
    assert sorted(loc.split(":")[0] for loc in f.files) == ["docs/setup.md", "src/config.rs"]


def test_local_path_dependencies_outside_repo(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "ws" / "app",
        {
            "package.json": json.dumps(
                {
                    "dependencies": {
                        "ui": "file:../ui",
                        "local": "file:./packages/local",
                        "react": "^18",
                    }
                }
            ),
            "crates/a/Cargo.toml": '[package]\nname="a"\n[dependencies]\nb = { path = "../b" }\nz = { path = "../../../z" }\n',
            "crates/b/Cargo.toml": '[package]\nname="b"\n',
            "pyproject.toml": '[tool.uv.sources]\nlib = { path = "../../lib" }\n',
        },
    )

    f = _check_local_path_deps(repo, _git_ls_files(repo))

    assert f is not None
    assert sorted(f.files) == [
        "crates/a/Cargo.toml: path = ../../../z",
        "package.json: ui -> file:../ui",
        "pyproject.toml: lib -> ../../lib",
    ]


def _commit(repo: Path, msg: str) -> None:
    subprocess.run(["git", "add", "-f", "-A"], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", msg],
        cwd=repo,
        check=True,
    )


def test_history_bloat_reports_deleted_big_blob_and_artifacts(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_history_bloat

    repo = _repo(tmp_path / "r", {"README.md": "x\n"})
    (repo / "model.bin").write_bytes(b"\1" * (6 * 1024 * 1024))
    (repo / "target" / "debug").mkdir(parents=True)
    (repo / "target" / "debug" / "libx.rlib").write_bytes(b"rlib")
    _commit(repo, "oops")
    subprocess.run(["git", "rm", "-rq", "model.bin", "target"], cwd=repo, check=True)
    _commit(repo, "remove")

    f = _check_history_bloat(repo, _git_ls_files(repo))

    assert f is not None
    assert f.severity == "low"
    assert f.files == ["model.bin (6.0 MiB, history only)", "target/debug/libx.rlib"]


def test_history_bloat_quiet_for_small_clean_history(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_history_bloat

    repo = _repo(tmp_path / "r", {"README.md": "x\n", "src/main.rs": "fn main() {}\n"})
    _commit(repo, "init")

    assert _check_history_bloat(repo, _git_ls_files(repo)) is None
