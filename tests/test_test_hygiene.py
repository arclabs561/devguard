"""Tests for the Rust test-hygiene checks in the repo hygiene sweep."""

from pathlib import Path

from devguard.sweeps.repo_hygiene import (
    _check_crate_level_test_gates,
    _check_ignored_tests_without_reason,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_crate_level_gate_is_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path / "tests" / "recall.rs",
        '#![cfg(all(feature = "a", feature = "b"))]\n#[test]\nfn t() {}\n',
    )
    finding = _check_crate_level_test_gates(tmp_path)
    assert finding is not None
    assert finding.check == "crate_level_test_gate"
    assert finding.severity == "medium"
    assert finding.files == ["tests/recall.rs"]


def test_per_test_gate_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path / "tests" / "fine.rs",
        '#[cfg(feature = "a")]\n#[test]\nfn t() {}\n',
    )
    assert _check_crate_level_test_gates(tmp_path) is None


def test_bare_ignore_is_flagged_and_reasoned_ignore_is_not(tmp_path: Path) -> None:
    _write(tmp_path / "src" / "a.rs", "#[ignore]\n#[test]\nfn t() {}\n")
    _write(
        tmp_path / "src" / "b.rs",
        '#[ignore = "needs a windows host"]\n#[test]\nfn t() {}\n',
    )
    finding = _check_ignored_tests_without_reason(tmp_path, ["src/a.rs", "src/b.rs"])
    assert finding is not None
    assert finding.check == "ignored_test_without_reason"
    assert finding.files == ["src/a.rs"]
