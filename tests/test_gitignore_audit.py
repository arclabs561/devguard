"""Tests for gitignore audit sweep."""

from pathlib import Path
from unittest.mock import patch

from devguard.sweeps.gitignore_audit import (
    _detect_languages,
    _is_likely_public,
    _pattern_satisfied,
    _read_gitignore_lines,
    audit_gitignores,
)


def test_detect_languages_rust(tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname = 'x'")
    assert "rust" in _detect_languages(tmp_path)


def test_detect_languages_python(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'x'")
    assert "python" in _detect_languages(tmp_path)


def test_detect_languages_js(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"name": "x"}')
    langs = _detect_languages(tmp_path)
    assert "js" in langs
    assert "ts" in langs


def test_detect_languages_empty(tmp_path: Path) -> None:
    assert _detect_languages(tmp_path) == set()


def test_is_likely_public_with_license(tmp_path: Path) -> None:
    (tmp_path / "LICENSE").write_text("MIT")
    assert _is_likely_public(tmp_path) is True


def test_is_likely_public_without_license(tmp_path: Path) -> None:
    assert _is_likely_public(tmp_path) is False


def test_read_gitignore_lines(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("# comment\n\n.env\ntarget/\n")
    lines = _read_gitignore_lines(tmp_path)
    assert lines == [".env", "target/"]


def test_read_gitignore_lines_missing(tmp_path: Path) -> None:
    assert _read_gitignore_lines(tmp_path) == []


def test_pattern_satisfied_exact_match() -> None:
    assert _pattern_satisfied([".env", "target/"], [".env"]) is True


def test_pattern_satisfied_with_slash_normalization() -> None:
    assert _pattern_satisfied(["target/"], ["target"]) is True
    assert _pattern_satisfied(["/target"], ["target"]) is True


def test_pattern_satisfied_glob_match() -> None:
    # .env.* in gitignore should satisfy .env.local
    assert _pattern_satisfied([".env.*"], [".env.local"]) is True


def test_pattern_satisfied_double_star_prefix() -> None:
    # **/*.log in gitignore covers *.log, **/dist covers dist
    assert _pattern_satisfied(["**/*.log"], ["*.log"]) is True
    assert _pattern_satisfied(["**/dist"], ["dist"]) is True
    assert _pattern_satisfied(["**/node_modules"], ["node_modules"]) is True


def test_pattern_satisfied_not_found() -> None:
    assert _pattern_satisfied(["target/"], [".env"]) is False


def test_pattern_satisfied_negation_ignored() -> None:
    # A negation line (!.env) should not count as satisfying the pattern
    assert _pattern_satisfied(["!.env"], [".env"]) is False


@patch("devguard.sweeps.gitignore_audit._read_global_gitignore_lines", return_value=[])
def test_audit_gitignores_basic(_mock_global, tmp_path: Path) -> None:
    """End-to-end audit on a minimal repo structure."""
    # Create a repo with a gap
    repo = tmp_path / "myrepo"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / ".gitignore").write_text("target/\n")
    (repo / "Cargo.toml").write_text("[package]\nname = 'x'")

    report, errors = audit_gitignores(dev_root=tmp_path, max_depth=1)
    assert errors == []
    assert report["scope"]["repos_scanned"] == 1
    # Should find gaps for .env, .state, .claude, *.log, .DS_Store, *.sqlite
    assert report["summary"]["total_gaps"] > 0
    # Check the repo appears in results
    assert len(report["repos"]) == 1
    assert "myrepo" in report["repos"][0]["repo_path"]


def test_audit_gitignores_clean_repo(tmp_path: Path) -> None:
    """Repo with all patterns present should not appear in results."""
    repo = tmp_path / "clean"
    repo.mkdir()
    (repo / ".git").mkdir()
    gi = "\n".join(
        [
            ".env",
            ".env.*",
            ".state/",
            ".claude/",
            "*.log",
            ".DS_Store",
            "*.sqlite",
            "*.sqlite3",
            "*.db",
            "target/",
        ]
    )
    (repo / ".gitignore").write_text(gi)
    (repo / "Cargo.toml").write_text("[package]\nname = 'x'")

    report, errors = audit_gitignores(dev_root=tmp_path, max_depth=1)
    assert report["summary"]["total_gaps"] == 0
    assert len(report["repos"]) == 0


@patch("devguard.sweeps.gitignore_audit._read_global_gitignore_lines", return_value=[])
def test_audit_gitignores_public_flagging(_mock_global, tmp_path: Path) -> None:
    """Public repos (with LICENSE) are flagged separately."""
    repo = tmp_path / "pub"
    repo.mkdir()
    (repo / ".git").mkdir()
    (repo / "LICENSE").write_text("MIT")
    (repo / ".gitignore").write_text("target/\n")
    (repo / "Cargo.toml").write_text("[package]")

    report, _ = audit_gitignores(dev_root=tmp_path, max_depth=1)
    assert report["summary"]["public_repos_with_gaps"] == 1
    assert report["repos"][0]["is_public"] is True
