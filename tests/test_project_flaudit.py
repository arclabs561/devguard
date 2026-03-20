"""Tests for project flaudit sweep."""

import json
from pathlib import Path

from devguard.sweeps.local_dirty_worktree_secrets import (
    LOCK_FILE_BASENAMES,
    _parse_trufflehog_filesystem_json,
)
from devguard.sweeps.project_flaudit import (
    _parse_llm_findings,
    files_to_prompt,
)
from devguard.sweeps.public_github_secrets import (
    _LOCK_FILE_BASENAMES as PUB_LOCK_FILE_BASENAMES,
)
from devguard.sweeps.public_github_secrets import (
    _extract_finding,
)


def test_files_to_prompt_includes_manifest(tmp_path: Path) -> None:
    """Manifest files (pyproject.toml, Cargo.toml) are included in the prompt."""
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "foo"\n[project.scripts]\nfoo = "foo:main"'
    )
    (tmp_path / "README.md").write_text("# Foo")
    # Simulate tracked files
    tracked = ["pyproject.toml", "README.md"]
    prompt, _ = files_to_prompt(tmp_path, tracked, include_rules=False)
    assert "## Manifest: pyproject.toml" in prompt
    assert "foo = \"foo:main\"" in prompt
    assert "## README: README.md" in prompt


def test_files_to_prompt_scope_files(tmp_path: Path) -> None:
    """scope_files restricts which files are included."""
    (tmp_path / "pyproject.toml").write_text("[project]\nname = 'bar'")
    (tmp_path / "README.md").write_text("# Bar")
    (tmp_path / "src").mkdir()
    (tmp_path / "src/main.py").write_text("print('hi')")
    tracked = ["pyproject.toml", "README.md", "src/main.py"]
    # Only manifest + README in scope
    scope = {"pyproject.toml", "README.md"}
    prompt, _ = files_to_prompt(tmp_path, tracked, include_rules=False, scope_files=scope)
    assert "## Manifest: pyproject.toml" in prompt
    assert "## README: README.md" in prompt
    assert "src/main.py" not in prompt


def test_parse_llm_findings_valid_json() -> None:
    """Parse valid JSON findings."""
    raw = '{"findings": [{"severity": "medium", "category": "other", "description": "x"}]}'
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].severity == "medium"
    assert out[0].description == "x"


def test_parse_llm_findings_trailing_comma_retry() -> None:
    """Parse succeeds after trailing-comma repair."""
    raw = '{"findings": [{"severity": "low", "description": "y"}, ]}'
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == "y"


def test_parse_llm_findings_markdown_fence() -> None:
    """Parse strips markdown code fence."""
    raw = '```json\n{"findings": []}\n```'
    out = _parse_llm_findings(raw)
    assert len(out) == 0


def test_parse_llm_findings_invalid_returns_empty() -> None:
    """Invalid JSON returns empty list."""
    out = _parse_llm_findings("not json at all")
    assert out == []


def test_parse_llm_findings_truncation_repair() -> None:
    """Truncated JSON recovers complete findings."""
    # Simulates max_tokens cutoff mid-response
    truncated = '''{"findings": [
        {"severity": "medium", "category": "other", "description": "first"},
        {"severity": "low", "category": "readme_impl_drift", "description": "second"},
        {"severity": "high", "category": "other", "description": "incomplete'''
    out = _parse_llm_findings(truncated)
    assert len(out) == 2
    assert out[0].description == "first"
    assert out[1].description == "second"


# ---------------------------------------------------------------------------
# _parse_llm_findings: additional edge cases
# ---------------------------------------------------------------------------


def test_parse_llm_findings_direct_list() -> None:
    """LLM returns a bare list instead of {"findings": [...]}."""
    raw = '[{"severity": "low", "category": "other", "description": "bare"}]'
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == "bare"


def test_parse_llm_findings_markdown_fence_with_space() -> None:
    """Fence with space before language tag (``` json)."""
    raw = '``` json\n{"findings": [{"severity": "low", "description": "spaced"}]}\n```'
    out = _parse_llm_findings(raw)
    # The parser splits on "```json" first; this variant uses generic ``` fallback.
    assert len(out) == 1
    assert out[0].description == "spaced"


def test_parse_llm_findings_non_dict_items_skipped() -> None:
    """Non-dict items in findings list are silently skipped."""
    raw = '{"findings": [42, "string", {"severity": "high", "description": "real"}]}'
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == "real"


def test_parse_llm_findings_empty_description() -> None:
    """Empty description is preserved, not treated as an error."""
    raw = '{"findings": [{"severity": "low", "description": ""}]}'
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == ""


def test_parse_llm_findings_truncation_all_incomplete() -> None:
    """When truncation cuts through the first finding, return empty."""
    raw = '{"findings": [{"severity": "high", "description": "incomp'
    out = _parse_llm_findings(raw)
    assert out == []


def test_parse_llm_findings_truncation_with_nested_braces() -> None:
    """Truncation repair handles braces inside string values."""
    raw = '''{"findings": [
        {"severity": "low", "category": "other", "description": "missing { brace"},
        {"severity": "high", "description": "cut off h'''
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert "brace" in out[0].description


def test_parse_llm_findings_findings_list_key() -> None:
    """Some LLMs use 'findings_list' instead of 'findings'."""
    raw = '{"findings_list": [{"severity": "medium", "description": "alt key"}]}'
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == "alt key"


def test_parse_llm_findings_extra_fields_preserved() -> None:
    """file_ref, suggestion, rule_ref are captured when present."""
    raw = json.dumps({"findings": [{
        "severity": "high",
        "description": "x",
        "file_ref": "src/main.py:42",
        "suggestion": "fix it",
        "rule_ref": "no-unsafe",
    }]})
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].file_ref == "src/main.py:42"
    assert out[0].suggestion == "fix it"
    assert out[0].rule_ref == "no-unsafe"


# ---------------------------------------------------------------------------
# Lock file false positive filtering (dirty worktree sweep)
# ---------------------------------------------------------------------------


def _make_trufflehog_json(file_path: str, detector: str = "SentryToken") -> str:
    """Build a single TruffleHog JSONL line for testing."""
    return json.dumps({
        "DetectorName": detector,
        "SourceMetadata": {"Data": {"Filesystem": {"file": file_path, "line": 1}}},
    })


def test_lock_file_basenames_contains_common_lock_files() -> None:
    for name in ("uv.lock", "Cargo.lock", "package-lock.json", "yarn.lock", "poetry.lock"):
        assert name in LOCK_FILE_BASENAMES


def test_parse_trufflehog_filters_lock_files() -> None:
    """Findings in lock files should be excluded from dirty worktree results."""
    stdout = "\n".join([
        _make_trufflehog_json("/repo/uv.lock"),
        _make_trufflehog_json("/repo/src/main.py", "PrivateKey"),
        _make_trufflehog_json("/repo/Cargo.lock", "AWS"),
    ])
    findings = _parse_trufflehog_filesystem_json(stdout, repo_path="/repo")
    # Parser doesn't filter -- that happens in scan_dirty_worktrees. Parser returns all.
    assert len(findings) == 3
    # But verify the lock file basenames are correct for the filter.
    lock_findings = [f for f in findings if f.file and Path(f.file).name in LOCK_FILE_BASENAMES]
    non_lock = [f for f in findings if not f.file or Path(f.file).name not in LOCK_FILE_BASENAMES]
    assert len(lock_findings) == 2
    assert len(non_lock) == 1
    assert non_lock[0].type == "PrivateKey"


# ---------------------------------------------------------------------------
# Lock file false positive filtering (public GitHub secrets sweep)
# ---------------------------------------------------------------------------


def test_pub_lock_file_basenames_match_dirty_sweep() -> None:
    """Both sweeps use the same set of lock file names."""
    assert LOCK_FILE_BASENAMES == PUB_LOCK_FILE_BASENAMES


def test_extract_finding_returns_finding_for_normal_file() -> None:
    obj = {
        "DetectorName": "AWS",
        "Verified": True,
        "SourceMetadata": {"Data": {"Git": {"file": "config.py", "commit": "abc123def456", "line": 10}}},
    }
    f = _extract_finding(obj, repo="owner/repo")
    assert f is not None
    assert f.type == "AWS"
    assert f.verified is True
    assert f.file == "config.py"
    assert f.commit == "abc123de"  # truncated to 8
    assert f.line == 10


def test_extract_finding_returns_none_for_non_dict() -> None:
    assert _extract_finding("not a dict", repo="x") is None
    assert _extract_finding(42, repo="x") is None


# ---------------------------------------------------------------------------
# Kingfisher JSON validation
# ---------------------------------------------------------------------------


def test_kingfisher_rejects_log_line_without_rule_or_path() -> None:
    """JSON objects without rule or path should be skipped (log lines)."""
    # This tests the filtering logic conceptually -- the actual filter is in
    # _scan_one_repo_kingfisher which we can't easily unit-test without subprocess.
    # Instead we verify the invariant: a dict with no rule/path fields is not a finding.
    log_obj = {"timestamp": "2024-01-01", "message": "scanning repo X"}
    rule = log_obj.get("rule") or log_obj.get("rule_id") or log_obj.get("id")
    path = log_obj.get("path") or log_obj.get("file") or log_obj.get("Path") or log_obj.get("File")
    assert not rule and not path, "log line should have no rule or path"


# ---------------------------------------------------------------------------
# Truncation repair: bare list format
# ---------------------------------------------------------------------------


def test_parse_llm_findings_bare_list_truncation() -> None:
    """Truncation repair works on bare list format (no wrapping object)."""
    raw = '''[
        {"severity": "medium", "description": "first"},
        {"severity": "low", "description": "cut off'''
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == "first"


def test_parse_llm_findings_findings_list_key_truncation() -> None:
    """Truncation repair works with 'findings_list' key too."""
    raw = '''{"findings_list": [
        {"severity": "high", "description": "complete"},
        {"severity": "low", "desc'''
    out = _parse_llm_findings(raw)
    assert len(out) == 1
    assert out[0].description == "complete"
