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


def test_stray_files_groups(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_stray_files

    repo = _repo(
        tmp_path / "r",
        {
            ".yamlfmt.bak": "x\n",
            "docs/progress.md": "# Session 3\n",
            "docs/typst-output/main.pdf": "x\n",
            "static/bundle.js": "var a=1;" * 1000 + "\n",
            "static/app.js": "const a = 1;\n//# sourceMappingURL=app.js.map\n",
            "src/main.js": "const a = 1;\n",
            "Scripts/run.sh": "x\n",
            "package.json": '{"scripts": {"build": "javascript-obfuscator src"}}',
        },
    )
    # A second directory differing only in case cannot be created on a
    # case-insensitive filesystem, so add it straight to the index.
    blob = (
        subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=repo,
            input=b"y\n",
            capture_output=True,
            check=True,
        )
        .stdout.decode()
        .strip()
    )
    subprocess.run(
        ["git", "update-index", "--add", "--cacheinfo", f"100644,{blob},scripts/other.sh"],
        cwd=repo,
        check=True,
    )

    f = _check_stray_files(repo, _git_ls_files(repo))

    assert f is not None
    assert sorted(f.files) == [
        "backup: .yamlfmt.bak",
        "built_docs: docs/...",
        "bundled: static/app.js",
        "bundled: static/bundle.js",
        "case_collision: Scripts vs scripts",
        "obfuscated_build: package.json",
        "session_log: docs/progress.md",
    ]


def test_stray_files_quiet_for_ordinary_repo(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_stray_files

    repo = _repo(
        tmp_path / "r",
        {"README.md": "x\n", "src/main.js": "const a = 1;\n", "docs/guide.md": "x\n"},
    )

    assert _check_stray_files(repo, _git_ls_files(repo)) is None


def test_http_reference_paths_are_not_local_home_paths(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "references.html": '<a href="https://www.usna.edu/Users/math/traves/_files/documents/Writing.pdf">Reference</a>',
            "links.md": "[Docs](http://example.test/home/alice/docs)\n<https://example.test/Users/bob/docs>",
            "mixed.md": "https://example.test/Users/math/docs /Users/alice/local",
            "quoted.py": 'url="https://example.test/Users/math/docs"; local="/home/alice/work"',
            "file.md": "file:///Users/alice/local",
            "query.md": "https://example.test/search?path=/Users/alice/local",
            "fragment.md": "https://example.test/page#path=/Users/alice/local",
            "malformed.md": "https:///Users/alice/local",
            "windows.md": r"https://example.test/Users/math/docs C:\Users\alice\local",
        },
    )
    finding = _check_hardcoded_paths(repo, _git_ls_files(repo))
    assert finding is not None
    assert sorted(location.split(":")[0] for location in finding.files) == [
        "file.md",
        "fragment.md",
        "malformed.md",
        "mixed.md",
        "query.md",
        "quoted.py",
        "windows.md",
    ]


def test_tracked_ignored_uses_only_repository_gitignore_files(tmp_path: Path, monkeypatch) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            ".gitignore": "*.log\n",
            "repo.log": "tracked",
            "global.md": "tracked",
            "local.md": "tracked",
            "nested/.gitignore": "*.txt\n!keep.txt\n",
            "nested/drop.txt": "tracked",
            "nested/keep.txt": "tracked",
        },
    )
    excludes = tmp_path / "global-ignore"
    excludes.write_text("global.md\n")
    config = tmp_path / "global-config"
    subprocess.run(
        ["git", "config", "--file", str(config), "core.excludesFile", str(excludes)], check=True
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))
    (repo / ".git/info/exclude").write_text("local.md\n")
    finding = _check_tracked_ignored(repo)
    assert finding is not None
    assert set(finding.files) == {"repo.log", "nested/drop.txt"}
