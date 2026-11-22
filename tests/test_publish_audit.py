from pathlib import Path

import pytest

from devguard.sweeps import publish_audit


@pytest.mark.parametrize("audit", [publish_audit._audit_pypi_repo, publish_audit._audit_npm_repo])
def test_split_license_files(tmp_path: Path, audit, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(publish_audit, "_is_likely_public", lambda repo: True)
    workflow = tmp_path / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("name: CI")
    assert any(f.check == "no_license_file" for f in audit(tmp_path).findings)
    for name in ("LICENSE-APACHE", "LICENSE-MIT"):
        license_file = tmp_path / name
        license_file.write_text("license")
        assert all(f.check != "no_license_file" for f in audit(tmp_path).findings)
        license_file.unlink()


def test_pypi_workflow_without_oidc_returns_finding(tmp_path: Path) -> None:
    workflow = tmp_path / ".github/workflows/publish.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("run: twine upload dist/*")
    assert any(f.check == "no_oidc" for f in publish_audit._audit_pypi_repo(tmp_path).findings)
