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
