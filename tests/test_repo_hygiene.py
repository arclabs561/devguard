"""Tests for repo hygiene sweep (unused workspace dependencies check)."""

import re
from pathlib import Path

from devguard.spec import load_spec
from devguard.sweeps.repo_hygiene import (
    _check_public_text_patterns,
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


def test_public_text_policy_flags_public_repo(tmp_path: Path) -> None:
    """Configured public text policy reports locations without exposing patterns."""
    _write(tmp_path / "LICENSE", "MIT\n")
    _write(tmp_path / "README.md", "private ADR-0001 context should stay local\n")

    finding = _check_public_text_patterns(
        tmp_path,
        ["LICENSE", "README.md"],
        True,
        [re.compile(r"ADR-\d{4}")],
        ["*.md"],
    )

    assert finding is not None
    assert finding.check == "public_text_policy"
    assert finding.severity == "medium"
    assert finding.files == ["README.md:1"]
    assert "ADR-0001" not in finding.message


def test_public_text_policy_skips_private_repo(tmp_path: Path) -> None:
    """Configured public text policy only applies to public repos."""
    _write(tmp_path / "README.md", "ADR-0001 is fine in a private planning repo\n")

    assert (
        _check_public_text_patterns(
            tmp_path,
            ["README.md"],
            False,
            [re.compile(r"ADR-\d{4}")],
            ["*.md"],
        )
        is None
    )


def test_spec_loads_public_text_policy_fields(tmp_path: Path) -> None:
    """repo_hygiene accepts the public text policy fields from YAML."""
    spec_path = tmp_path / "devguard.spec.yaml"
    spec_path.write_text(
        """
name: test
sweeps:
  repo_hygiene:
    public_text_patterns: ["ADR-[0-9]{4}"]
    public_text_patterns_env: DEVGUARD_PUBLIC_TEXT_PATTERNS
    public_text_file_globs: ["*.md"]
"""
    )

    repo_hygiene = load_spec(spec_path).sweeps.repo_hygiene
    assert repo_hygiene.public_text_patterns == ["ADR-[0-9]{4}"]
    assert repo_hygiene.public_text_patterns_env == "DEVGUARD_PUBLIC_TEXT_PATTERNS"
    assert repo_hygiene.public_text_file_globs == ["*.md"]
