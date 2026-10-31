from pathlib import Path

import pytest
import yaml

from devguard.spec import load_spec


def test_load_spec_rejects_duplicate_mapping_keys(tmp_path: Path) -> None:
    spec_path = tmp_path / "devguard.spec.yaml"
    spec_path.write_text(
        """\
name: duplicate-sweep
sweeps:
  project_flaudit:
    enabled: false
  project_flaudit:
    enabled: true
"""
    )

    with pytest.raises(yaml.constructor.ConstructorError, match="duplicate key 'project_flaudit'"):
        load_spec(spec_path)


def test_load_spec_accepts_distinct_nested_mapping_keys(tmp_path: Path) -> None:
    spec_path = tmp_path / "devguard.spec.yaml"
    spec_path.write_text(
        """\
name: distinct-sweeps
sweeps:
  project_flaudit:
    enabled: false
  repo_hygiene:
    enabled: true
"""
    )

    spec = load_spec(spec_path)

    assert spec.name == "distinct-sweeps"
    assert spec.sweeps.project_flaudit.enabled is False
    assert spec.sweeps.repo_hygiene.enabled is True


def test_example_spec_selects_real_owner_and_engine() -> None:
    # Curly quotes parse as literal owner/engine names, so a copied example
    # would select zero repos while still exiting 0.
    example = Path(__file__).resolve().parents[1] / "devguard.spec.example.yaml"

    pub = load_spec(example).sweeps.public_github_secrets

    assert pub.owners == ["@me"]
    assert pub.engines == ["trufflehog"]
    assert example.read_text(encoding="utf-8").isascii()


def test_resolve_spec_path_prefers_cwd_then_env_then_user_config(tmp_path, monkeypatch):
    from devguard.spec import resolve_spec_path

    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.chdir(work)
    config_home = tmp_path / "config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
    monkeypatch.delenv("DEVGUARD_SPEC", raising=False)

    # Nothing exists: the default name comes back unchanged.
    assert resolve_spec_path() == Path("devguard.spec.yaml")

    user = config_home / "devguard" / "devguard.spec.yaml"
    user.parent.mkdir(parents=True)
    user.write_text("version: '1.0'\n")
    assert resolve_spec_path() == user

    env_spec = tmp_path / "env.yaml"
    env_spec.write_text("version: '1.0'\n")
    monkeypatch.setenv("DEVGUARD_SPEC", str(env_spec))
    assert resolve_spec_path() == env_spec

    (work / "devguard.spec.yaml").write_text("version: '1.0'\n")
    assert resolve_spec_path() == Path("devguard.spec.yaml")

    explicit = tmp_path / "explicit.yaml"
    assert resolve_spec_path(str(explicit)) == explicit
