"""Tests for repo hygiene sweep (unused workspace dependencies check)."""

from pathlib import Path

from devguard.sweeps.repo_hygiene import (
    _check_unused_workspace_deps,
    _workspace_dep_consumers,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_unused_workspace_deps_dead_key_flagged(tmp_path: Path) -> None:
    """Dead key flagged; consumed and rename-consumed keys are not."""
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["member"]\n'
        "[workspace.dependencies]\n"
        'deadkey = "1.0"\n'
        'serde = { version = "1.0", features = ["derive"] }\n'
        'innr-compat = { package = "innr", version = "0.4" }\n',
    )
    _write(
        tmp_path / "member" / "Cargo.toml",
        '[package]\nname = "member"\nversion = "0.1.0"\n'
        "[dependencies]\n"
        "serde = { workspace = true }\n"
        "innr-compat = { workspace = true }\n",
    )
    finding = _check_unused_workspace_deps(tmp_path)
    assert finding is not None
    assert finding.check == "unused_workspace_deps"
    assert finding.severity == "low"
    assert finding.files == ["Cargo.toml: deadkey"]


def test_unused_workspace_deps_all_consumed(tmp_path: Path) -> None:
    """No finding when every declared key has a workspace = true consumer."""
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["member"]\n[workspace.dependencies]\nserde = "1.0"\n',
    )
    _write(
        tmp_path / "member" / "Cargo.toml",
        '[package]\nname = "member"\nversion = "0.1.0"\n[dependencies]\nserde.workspace = true\n',
    )
    assert _check_unused_workspace_deps(tmp_path) is None


def test_unused_workspace_deps_root_package_consumes(tmp_path: Path) -> None:
    """Single-crate workspace: root [dependencies] counts as the consumer."""
    _write(
        tmp_path / "Cargo.toml",
        '[package]\nname = "solo"\nversion = "0.1.0"\n'
        "[workspace]\n"
        '[workspace.dependencies]\ntokio = "1"\n'
        "[dependencies]\ntokio = { workspace = true }\n",
    )
    assert _check_unused_workspace_deps(tmp_path) is None


def test_unused_workspace_deps_subtable_declaration(tmp_path: Path) -> None:
    """[workspace.dependencies.key] sub-table declarations are seen."""
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["member"]\n[workspace.dependencies.deadkey]\nversion = "1.0"\n',
    )
    _write(
        tmp_path / "member" / "Cargo.toml",
        '[package]\nname = "member"\nversion = "0.1.0"\n',
    )
    finding = _check_unused_workspace_deps(tmp_path)
    assert finding is not None
    assert finding.files == ["Cargo.toml: deadkey"]


def test_unused_workspace_deps_unparseable_member_skips(tmp_path: Path) -> None:
    """A member manifest that fails to parse suppresses the whole workspace."""
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["member"]\n[workspace.dependencies]\ndeadkey = "1.0"\n',
    )
    _write(tmp_path / "member" / "Cargo.toml", "not [ valid toml = =\n")
    assert _check_unused_workspace_deps(tmp_path) is None


def test_unused_workspace_deps_no_manifests(tmp_path: Path) -> None:
    assert _check_unused_workspace_deps(tmp_path) is None


def test_unused_workspace_deps_path_dep_is_member(tmp_path: Path) -> None:
    """An in-tree path dependency of a member counts as a consumer."""
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["member"]\n[workspace.dependencies]\nserde = "1.0"\n',
    )
    _write(
        tmp_path / "member" / "Cargo.toml",
        '[package]\nname = "member"\nversion = "0.1.0"\n'
        '[dependencies]\nhelper = { path = "../helper" }\n',
    )
    _write(
        tmp_path / "helper" / "Cargo.toml",
        '[package]\nname = "helper"\nversion = "0.1.0"\n'
        "[dependencies]\nserde = { workspace = true }\n",
    )
    assert _check_unused_workspace_deps(tmp_path) is None


def test_unused_workspace_deps_excluded_dir_not_consumer(tmp_path: Path) -> None:
    """A manifest under workspace.exclude does not count as a consumer."""
    _write(
        tmp_path / "Cargo.toml",
        '[workspace]\nmembers = ["member", "archive/*"]\nexclude = ["archive/*"]\n'
        '[workspace.dependencies]\ndeadkey = "1.0"\n',
    )
    _write(
        tmp_path / "member" / "Cargo.toml",
        '[package]\nname = "member"\nversion = "0.1.0"\n',
    )
    _write(
        tmp_path / "archive" / "old" / "Cargo.toml",
        '[package]\nname = "old"\nversion = "0.1.0"\n'
        "[dependencies]\ndeadkey = { workspace = true }\n",
    )
    finding = _check_unused_workspace_deps(tmp_path)
    assert finding is not None
    assert finding.files == ["Cargo.toml: deadkey"]


def test_workspace_dep_consumers_all_dep_tables() -> None:
    """Consumption is detected in dev-, build-, and target dep tables."""
    manifest = {
        "dependencies": {"a": {"workspace": True}, "pinned": "1.0"},
        "dev-dependencies": {"b": {"workspace": True}},
        "build-dependencies": {"c": {"workspace": True}},
        "target": {
            'cfg(target_os = "linux")': {"dependencies": {"d": {"workspace": True}}},
        },
    }
    assert _workspace_dep_consumers(manifest) == {"a", "b", "c", "d"}
