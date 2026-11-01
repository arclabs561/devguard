"""Tests for tracked-but-ignored files, personal paths, local path deps, untracked build inputs."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from devguard.sweeps.repo_hygiene import (
    _check_hardcoded_paths,
    _check_local_path_deps,
    _check_required_file_untracked,
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


def test_untracked_included_header_reports_ignore_rule(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            ".gitignore": "vendor/\n",
            "tools/annoy-sys/build.rs": (
                'fn main() {\n    cc::Build::new().include("vendor").compile("annoy");\n}\n'
            ),
        },
    )
    (repo / "tools/annoy-sys/vendor").mkdir(parents=True)
    (repo / "tools/annoy-sys/vendor/annoylib.h").write_text("// upstream header\n")

    finding = _check_required_file_untracked(repo, _git_ls_files(repo))

    assert finding is not None
    assert finding.check == "required_file_untracked"
    assert finding.severity == "medium"
    assert finding.files == [
        "tools/annoy-sys/vendor/annoylib.h <- tools/annoy-sys/build.rs "
        "(include; ignored by .gitignore:1:vendor/)"
    ]


def test_untracked_global_exclude_names_the_global_rule(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = _repo(
        tmp_path / "r",
        {".gitignore": "", "build.rs": 'fn main() { cc::Build::new().include("vendor"); }\n'},
    )
    (repo / "vendor").mkdir()
    (repo / "vendor" / "x.h").write_text("// h\n")
    excludes = tmp_path / "global-ignore"
    excludes.write_text("vendor/\n")
    config = tmp_path / "global-config"
    subprocess.run(
        ["git", "config", "--file", str(config), "core.excludesFile", str(excludes)], check=True
    )
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(config))

    finding = _check_required_file_untracked(repo, _git_ls_files(repo))

    assert finding is not None
    assert finding.severity == "medium"
    assert finding.files == [f"vendor/x.h <- build.rs (include; ignored by {excludes}:1:vendor/)"]


def test_untracked_include_str_and_cargo_target_path(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "r"\nversion = "0.1.0"\n'
                '[[bin]]\nname = "tool"\npath = "src/bin/tool.rs"\n'
            ),
            "src/lib.rs": 'pub const GREETING: &str = include_str!("templates/greet.txt");\n',
        },
    )
    (repo / "src" / "templates").mkdir(parents=True)
    (repo / "src" / "templates" / "greet.txt").write_text("hi\n")
    (repo / "src" / "bin").mkdir()
    (repo / "src" / "bin" / "tool.rs").write_text("fn main() {}\n")

    finding = _check_required_file_untracked(repo, _git_ls_files(repo))

    assert finding is not None
    assert finding.severity == "low"
    assert finding.files == [
        "src/bin/tool.rs <- Cargo.toml (Cargo.toml path =)",
        "src/templates/greet.txt <- src/lib.rs (include_str!/include_bytes!)",
    ]


def test_package_data_glob_reports_untracked_file(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            "pyproject.toml": (
                '[project]\nname = "x"\nversion = "0"\n'
                "[tool.setuptools.package-data]\n"
                'pkg = ["data/*.json"]\n'
            ),
            "pkg/__init__.py": "",
        },
    )
    (repo / "pkg" / "data").mkdir()
    (repo / "pkg" / "data" / "table.json").write_text("{}\n")

    finding = _check_required_file_untracked(repo, _git_ls_files(repo))

    assert finding is not None
    assert finding.files == ["pkg/data/table.json <- pyproject.toml (package_data)"]


def test_tracked_references_are_quiet(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path / "r",
        {
            ".gitignore": "vendor/\n",
            "build.rs": 'fn main() { cc::Build::new().include("vendor"); }\n',
            "vendor/x.h": "// h\n",
            "Cargo.toml": (
                '[package]\nname = "r"\nversion = "0.1.0"\n'
                '[[bin]]\nname = "tool"\npath = "src/bin/tool.rs"\n'
            ),
            "src/bin/tool.rs": "fn main() {}\n",
            "src/lib.rs": 'pub const G: &str = include_str!("../README.md");\n',
            "README.md": "hi\n",
        },
    )

    assert _check_required_file_untracked(repo, _git_ls_files(repo)) is None


def test_missing_referenced_file_is_not_reported(tmp_path: Path) -> None:
    """Only files present in the working tree can be added; absent ones are other bugs."""
    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "r"\nversion = "0.1.0"\n'
                '[[bin]]\nname = "tool"\npath = "src/bin/tool.rs"\n'
            )
        },
    )

    assert _check_required_file_untracked(repo, _git_ls_files(repo)) is None


# --- feature_name_unknown ----------------------------------------------------


def test_unknown_feature_in_workflow_is_flagged(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "burn-sys"\nversion = "0.1.0"\n[features]\nburn-ndarray = []\n'
            ),
            ".github/workflows/ci.yml": "run: cargo clippy --features burn-wgpu\n",
        },
    )
    finding = _check_unknown_features(repo, _git_ls_files(repo))
    assert finding is not None
    assert finding.check == "feature_name_unknown"
    assert "burn-wgpu" in finding.files[0]
    assert "burn-ndarray" in finding.files[0]


def test_known_feature_in_workflow_is_quiet(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "burn-sys"\nversion = "0.1.0"\n[features]\nburn-ndarray = []\n'
            ),
            ".github/workflows/ci.yml": "run: cargo clippy --features burn-ndarray\n",
        },
    )
    assert _check_unknown_features(repo, _git_ls_files(repo)) is None


def test_unknown_feature_today_burn_flex_case(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "burn-sys"\nversion = "0.1.0"\n'
                "[features]\nburn-flex = []\nburn-wgpu = []\n"
            ),
            ".github/workflows/ci.yml": (
                'run: cargo clippy --features "burn-ndarray,burn-wgpu"\n'
                "run: cargo test --features burn-ndarray\n"
            ),
        },
    )
    finding = _check_unknown_features(repo, _git_ls_files(repo))
    assert finding is not None
    files = " ".join(finding.files)
    assert "burn-ndarray" in files
    assert "nearest:" in files


# --- test_target_missing_gate -------------------------------------------------


def test_ungated_test_using_feature_gated_module_is_flagged(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_test_target_missing_gate

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "vicinity"\nversion = "0.1.0"\n[features]\nhnsw = []\n'
            ),
            "src/lib.rs": '#[cfg(feature = "hnsw")]\npub mod hnsw;\n',
            "tests/ann_matrix.rs": "use vicinity::hnsw::Index;\n",
        },
    )
    finding = _check_test_target_missing_gate(repo, _git_ls_files(repo))
    assert finding is not None
    assert finding.check == "test_target_missing_gate"
    assert "ann_matrix.rs" in finding.files[0]
    assert "hnsw" in finding.files[0]


def test_gated_test_using_feature_gated_module_is_quiet(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_test_target_missing_gate

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "vicinity"\nversion = "0.1.0"\n[features]\nhnsw = []\n'
            ),
            "src/lib.rs": '#[cfg(feature = "hnsw")]\npub mod hnsw;\n',
            "tests/ann_matrix.rs": '#![cfg(feature = "hnsw")]\nuse vicinity::hnsw::Index;\n',
        },
    )
    assert _check_test_target_missing_gate(repo, _git_ls_files(repo)) is None


def test_required_features_target_is_quiet(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_test_target_missing_gate

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "vicinity"\nversion = "0.1.0"\n'
                "[features]\nhnsw = []\n"
                '[[test]]\nname = "ann_matrix"\npath = "tests/ann_matrix.rs"\nrequired-features = ["hnsw"]\n'
            ),
            "src/lib.rs": '#[cfg(feature = "hnsw")]\npub mod hnsw;\n',
            "tests/ann_matrix.rs": "use vicinity::hnsw::Index;\n",
        },
    )
    assert _check_test_target_missing_gate(repo, _git_ls_files(repo)) is None


def test_ann_matrix_today_case_ungated_use_with_gated_mod(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_test_target_missing_gate

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "vicinity"\nversion = "0.1.0"\n[features]\nhnsw = []\n'
            ),
            "src/lib.rs": '#[cfg(feature = "hnsw")]\npub mod hnsw;\n',
            "tests/ann_matrix.rs": (
                "use vicinity::hnsw::Index;\n"
                '#[cfg(feature = "hnsw")]\n'
                "mod gated { fn helper() {} }\n"
            ),
        },
    )
    finding = _check_test_target_missing_gate(repo, _git_ls_files(repo))
    assert finding is not None
    assert "ann_matrix.rs" in finding.files[0]


# --- readme_install_version ---------------------------------------------------


def test_readme_version_mismatch_is_flagged(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_readme_install_version

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": '[package]\nname = "tnorms"\nversion = "0.2.2"\n',
            "README.md": '```toml\ntnorms = "0.2.1"\n```\n',
        },
    )
    finding = _check_readme_install_version(repo, _git_ls_files(repo))
    assert finding is not None
    assert finding.check == "readme_install_version"
    assert "0.2.1" in finding.files[0]


def test_readme_version_match_is_quiet(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_readme_install_version

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": '[package]\nname = "tnorms"\nversion = "0.2.2"\n',
            "README.md": '```toml\ntnorms = "0.2.2"\n```\n',
        },
    )
    assert _check_readme_install_version(repo, _git_ls_files(repo)) is None


def test_readme_prerelease_version_is_quiet(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_readme_install_version

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": '[package]\nname = "tnorms"\nversion = "0.2.2-alpha.1"\n',
            "README.md": '```toml\ntnorms = "0.2.2"\n```\n',
        },
    )
    assert _check_readme_install_version(repo, _git_ls_files(repo)) is None


# --- devguard:allow pragmas --------------------------------------------------


def _feature_manifest() -> str:
    return '[package]\nname = "demo"\nversion = "0.1.0"\n[features]\nreal = []\n'


def test_allow_pragma_with_reason_silences_the_line(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": _feature_manifest(),
            "justfile": (
                "# devguard: allow feature_name_unknown reason: historical log, kept verbatim\n"
                "cargo test --features gone\n"
            ),
        },
    )
    assert _check_unknown_features(repo, _git_ls_files(repo)) is None


def test_allow_pragma_without_a_reason_does_not_silence(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": _feature_manifest(),
            "justfile": "# devguard: allow feature_name_unknown\ncargo test --features gone\n",
        },
    )
    finding = _check_unknown_features(repo, _git_ls_files(repo))
    assert finding is not None, "an unreasoned pragma must not hide the finding"


def test_allow_file_pragma_covers_the_whole_document(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": _feature_manifest(),
            "justfile": (
                "# devguard: allow-file feature_name_unknown reason: historical record\n"
                "cargo test --features gone\n" + "\n" * 10 + "cargo test --features alsoGone\n"
            ),
        },
    )
    assert _check_unknown_features(repo, _git_ls_files(repo)) is None


def test_allow_pragma_window_is_bounded(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_unknown_features

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": _feature_manifest(),
            "justfile": (
                "# devguard: allow feature_name_unknown reason: one old command\n"
                "cargo test --features gone\n" + "\n" * 10 + "cargo test --features alsoGone\n"
            ),
        },
    )
    finding = _check_unknown_features(repo, _git_ls_files(repo))
    assert finding is not None, "a pragma six lines up must not cover this command"
    assert any("alsoGone" in f for f in finding.files)


def test_transitively_enabled_feature_satisfies_the_gate(tmp_path: Path) -> None:
    from devguard.sweeps.repo_hygiene import _check_test_target_missing_gate

    repo = _repo(
        tmp_path / "r",
        {
            "Cargo.toml": (
                '[package]\nname = "demo"\nversion = "0.1.0"\n[features]\n'
                'default = []\nwide = ["narrow"]\nnarrow = []\n'
            ),
            "src/lib.rs": '#[cfg(feature = "narrow")]\npub mod inner;\n',
            "tests/uses_inner.rs": "use demo::inner::Thing;\n\n#[test]\nfn t() {}\n",
        },
    )
    # No required-features at all: the finding stands.
    assert _check_test_target_missing_gate(repo, _git_ls_files(repo)) is not None

    manifest = (repo / "Cargo.toml").read_text()
    (repo / "Cargo.toml").write_text(
        manifest + '\n[[test]]\nname = "uses_inner"\nrequired-features = ["wide"]\n'
    )
    # `wide` enables `narrow`, so the gate is satisfied transitively.
    assert _check_test_target_missing_gate(repo, _git_ls_files(repo)) is None
