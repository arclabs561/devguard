"""Tests for AI editor config audit sweep -- unicode injection detection."""

import os
import subprocess
from pathlib import Path

import pytest

from devguard.sweeps.ai_editor_config_audit import (
    RepoAuditResult,
    _check_memory_dir,
    _check_unicode_injection,
    _check_unicode_injection_repo,
)


def test_check_unicode_injection_zwj(tmp_path: Path) -> None:
    """Zero-width joiner in a file is detected."""
    f = tmp_path / "CLAUDE.md"
    f.write_text("normal text\u200dhidden instruction", encoding="utf-8")
    findings = _check_unicode_injection(f)
    assert len(findings) == 1
    assert findings[0]["check"] == "unicode_injection"
    assert findings[0]["severity"] == "error"
    assert findings[0]["line"] == 1
    assert "U+200D" in findings[0]["message"]
    assert "ZERO WIDTH JOINER" in findings[0]["message"]
    assert "[U+200D]" in findings[0]["context"]


def test_check_unicode_injection_bidi(tmp_path: Path) -> None:
    """Bidirectional override characters are detected."""
    f = tmp_path / ".cursorrules"
    # U+202E = RIGHT-TO-LEFT OVERRIDE
    f.write_text("line one\nsome \u202e bidi text\nline three", encoding="utf-8")
    findings = _check_unicode_injection(f)
    assert len(findings) == 1
    assert findings[0]["line"] == 2
    assert "U+202E" in findings[0]["message"]


def test_check_unicode_injection_multiple(tmp_path: Path) -> None:
    """Multiple suspicious chars across lines are all reported."""
    f = tmp_path / "rules.md"
    # U+200B on line 1, U+FEFF on line 2
    f.write_text("a\u200bb\nfoo\ufeffbar", encoding="utf-8")
    findings = _check_unicode_injection(f)
    assert len(findings) == 2
    lines = {fd["line"] for fd in findings}
    assert lines == {1, 2}


def test_check_unicode_injection_clean(tmp_path: Path) -> None:
    """A clean file produces no findings."""
    f = tmp_path / "clean.md"
    f.write_text("# Normal markdown\nNo hidden chars here.\n", encoding="utf-8")
    findings = _check_unicode_injection(f)
    assert findings == []


def test_check_unicode_injection_variation_selector(tmp_path: Path) -> None:
    """Variation selectors (U+FE00-U+FE0F) are detected."""
    f = tmp_path / "test.md"
    f.write_text("text\ufe0fmore", encoding="utf-8")
    findings = _check_unicode_injection(f)
    assert len(findings) == 1
    assert "U+FE0F" in findings[0]["message"]


def test_check_unicode_injection_tag_characters(tmp_path: Path) -> None:
    """Tag characters (U+E0001-U+E007F) are detected."""
    f = tmp_path / "test.md"
    # U+E0001 = LANGUAGE TAG, U+E0041 = TAG LATIN CAPITAL LETTER A
    f.write_text("before\U000e0041after", encoding="utf-8")
    findings = _check_unicode_injection(f)
    assert len(findings) == 1
    assert "E0041" in findings[0]["message"]


def test_check_unicode_injection_repo_scans_all_paths(tmp_path: Path) -> None:
    """The repo-level check scans all expected AI config files."""
    # Create files with a ZWJ embedded
    (tmp_path / ".cursorrules").write_text("a\u200db", encoding="utf-8")

    claude_rules = tmp_path / ".claude" / "rules"
    claude_rules.mkdir(parents=True)
    (claude_rules / "foo.md").write_text("x\u200cy", encoding="utf-8")

    cursor_rules = tmp_path / ".cursor" / "rules"
    cursor_rules.mkdir(parents=True)
    (cursor_rules / "bar.mdc").write_text("p\u202aq", encoding="utf-8")

    github_dir = tmp_path / ".github"
    github_dir.mkdir()
    (github_dir / "copilot-instructions.md").write_text("m\u200bn", encoding="utf-8")

    (tmp_path / "CLAUDE.md").write_text("clean file", encoding="utf-8")

    result = RepoAuditResult(
        repo_path=str(tmp_path),
        repo_name=tmp_path.name,
        is_public=False,
    )
    _check_unicode_injection_repo(tmp_path, result)

    unicode_findings = [f for f in result.findings if f.check == "unicode_injection"]
    assert len(unicode_findings) == 4
    # All should be errors
    assert all(f.severity == "error" for f in unicode_findings)


def test_check_unicode_injection_nonexistent_file(tmp_path: Path) -> None:
    """Non-existent file returns empty findings (no crash)."""
    findings = _check_unicode_injection(tmp_path / "nope.md")
    assert findings == []


@pytest.mark.parametrize("tracked", [True, False])
def test_public_memory_directory_requires_content_review(tmp_path: Path, tracked: bool) -> None:
    """An intentionally public source directory is not evidence of private agent state."""
    subprocess.run(["git", "init", "--quiet", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "core.excludesFile", os.devnull], check=True
    )
    memory_dir = tmp_path / "memory"
    memory_dir.mkdir()
    (memory_dir / "README.md").write_text(
        "# Memory allocator examples\nIntentionally public project documentation.\n",
        encoding="utf-8",
    )
    if tracked:
        subprocess.run(["git", "-C", str(tmp_path), "add", "memory/README.md"], check=True)
    result = RepoAuditResult(repo_path=str(tmp_path), repo_name=tmp_path.name, is_public=True)

    _check_memory_dir(tmp_path, result)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "info"
    advice = finding.message + " " + finding.detail
    assert "Review" in advice
    for unsupported_advice in ("git rm", ".gitignore_global", "~/.claude/projects/", "belongs"):
        assert unsupported_advice not in advice
    assert (memory_dir / "README.md").is_file()
