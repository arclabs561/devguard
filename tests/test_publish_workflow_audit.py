"""publish_workflow_audit against fixture workflows."""

import subprocess
from pathlib import Path

from devguard.sweeps.publish_workflow_audit import audit_publish_workflows, audit_workflows

SHA = "34e114876b0b11c390a56381ad16ebd13914f8d5"

TAG_PUSH_NO_CREDS = f"""
name: publish
on: {{push: {{tags: ["v*"]}}}}
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{SHA}
        with:
          persist-credentials: false
      - run: cargo publish
      - name: Push tag
        run: |
          git tag v1.2.3
          git push origin v1.2.3
"""

TAG_PUSH_WITH_TOKEN = f"""
jobs:
  publish:
    steps:
      - uses: actions/checkout@{SHA}
        with:
          persist-credentials: false
      - run: git remote set-url origin "https://x-access-token:${{{{ secrets.GITHUB_TOKEN }}}}@github.com/${{{{ github.repository }}}}"
      - run: git push origin v1.2.3
"""

TAG_PUSH_DEFAULT_CHECKOUT = f"""
jobs:
  publish:
    steps:
      - uses: actions/checkout@{SHA}
      - run: git push origin v1.2.3
"""

CI_WITH_PINS = f"""
jobs:
  msrv:
    steps:
      - uses: actions/checkout@{SHA}
      - uses: dtolnay/rust-toolchain@{SHA}
        with:
          toolchain: "1.75"
      - run: cargo update -p half --precise 2.4.1
      - run: cargo update -p  zerofrom --precise 0.1.5
      - run: cargo check
"""

PUBLISH_MSRV_PARTIAL = f"""
jobs:
  verify-msrv:
    steps:
      - uses: actions/checkout@{SHA}
      - uses: dtolnay/rust-toolchain@{SHA}
        with:
          toolchain: "1.75"
      - run: cargo update -p half --precise 2.4.1
      - run: cargo publish --dry-run
"""

SEMVER_DEFAULT = f"""
jobs:
  semver:
    steps:
      - uses: actions/checkout@{SHA}
      - uses: obi1kenobi/cargo-semver-checks-action@{SHA}
"""

SEMVER_FEATURE_GROUP = f"""
jobs:
  semver:
    steps:
      - uses: actions/checkout@{SHA}
      - uses: obi1kenobi/cargo-semver-checks-action@{SHA}
        with:
          feature-group: default-features
"""

UNPINNED = """
jobs:
  publish:
    steps:
      - uses: actions/checkout@v4
      - uses: pypa/gh-action-pypi-publish@release/v1
      - uses: ./.github/actions/local
"""

PLATFORM_CARGO = """
[package]
name = "demo"
version = "0.1.0"

[features]
default = []
apple = ["dep:objc2"]

[target.'cfg(target_os = "macos")'.dependencies]
objc2 = { version = "0.5", optional = true }
"""

ARCH_ONLY_CARGO = """
[package]
name = "demo"
version = "0.1.0"

[target.'cfg(target_arch = "aarch64")'.dependencies]
pulp = "0.18"
"""

METAL_FEATURE_CARGO = """
[package]
name = "demo"
version = "0.1.0"

[features]
metal = []
"""

PORTABLE_CARGO = """
[package]
name = "demo"
version = "0.1.0"

[features]
default = []
serde = []
"""


def _repo(tmp_path: Path, workflows: dict[str, str], cargo: str | None = None) -> Path:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    for name, text in workflows.items():
        (wf / name).write_text(text)
    if cargo is not None:
        (tmp_path / "Cargo.toml").write_text(cargo)
    return tmp_path


def _checks(findings: list[dict]) -> list[str]:
    return sorted(f["check"] for f in findings)


def test_tag_push_after_persist_false_is_error(tmp_path: Path) -> None:
    findings = audit_workflows(_repo(tmp_path, {"publish.yml": TAG_PUSH_NO_CREDS}))
    assert _checks(findings) == ["tag_push_without_credentials"]
    assert findings[0]["severity"] == "error"
    assert "Push tag" in findings[0]["message"]


def test_tag_push_with_token_remote_or_default_checkout_is_clean(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        {"publish.yml": TAG_PUSH_WITH_TOKEN, "release.yml": TAG_PUSH_DEFAULT_CHECKOUT},
    )
    assert audit_workflows(repo) == []


def test_msrv_pins_missing_from_publish(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"ci.yml": CI_WITH_PINS, "publish.yml": PUBLISH_MSRV_PARTIAL})
    findings = audit_workflows(repo)
    assert _checks(findings) == ["msrv_pins_missing"]
    assert "zerofrom --precise 0.1.5" in findings[0]["message"]
    assert "half" not in findings[0]["message"]


def test_msrv_pins_present_is_clean(tmp_path: Path) -> None:
    full = PUBLISH_MSRV_PARTIAL + "      - run: cargo update -p zerofrom --precise 0.1.5\n"
    repo = _repo(tmp_path, {"ci.yml": CI_WITH_PINS, "publish.yml": full})
    assert audit_workflows(repo) == []


def test_semver_checks_default_features_on_platform_crate(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"publish.yml": SEMVER_DEFAULT}, PLATFORM_CARGO)
    findings = audit_workflows(repo)
    assert _checks(findings) == ["semver_checks_all_features"]
    assert "target-specific dependencies" in findings[0]["message"]


def test_semver_checks_default_features_on_metal_feature(tmp_path: Path) -> None:
    repo = _repo(tmp_path, {"publish.yml": SEMVER_DEFAULT}, METAL_FEATURE_CARGO)
    findings = audit_workflows(repo)
    assert _checks(findings) == ["semver_checks_all_features"]
    assert "platform features: metal" in findings[0]["message"]


def test_semver_checks_ok_with_feature_group_or_portable_crate(tmp_path: Path) -> None:
    a = _repo(tmp_path / "a", {"publish.yml": SEMVER_FEATURE_GROUP}, PLATFORM_CARGO)
    b = _repo(tmp_path / "b", {"publish.yml": SEMVER_DEFAULT}, PORTABLE_CARGO)
    c = _repo(tmp_path / "c", {"publish.yml": SEMVER_DEFAULT}, ARCH_ONLY_CARGO)
    assert audit_workflows(a) == []
    assert audit_workflows(b) == []
    assert audit_workflows(c) == []


def test_unpinned_refs_flagged_only_when_repo_pins_elsewhere(tmp_path: Path) -> None:
    mixed = _repo(tmp_path / "mixed", {"ci.yml": CI_WITH_PINS, "release.yml": UNPINNED})
    findings = audit_workflows(mixed)
    assert _checks(findings) == ["unpinned_action_ref"]
    assert "actions/checkout@v4" in findings[0]["message"]
    assert "./.github" not in findings[0]["message"]

    unpinned_everywhere = _repo(tmp_path / "loose", {"release.yml": UNPINNED})
    assert audit_workflows(unpinned_everywhere) == []


def test_non_publish_workflows_are_ignored(tmp_path: Path) -> None:
    assert audit_workflows(_repo(tmp_path, {"ci.yml": TAG_PUSH_NO_CREDS})) == []


def test_sweep_report_counts_errors(tmp_path: Path) -> None:
    repo = _repo(tmp_path / "r", {"publish.yml": TAG_PUSH_NO_CREDS})
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    report, errors = audit_publish_workflows(dev_root=tmp_path, max_depth=1)
    assert errors == []
    assert report["summary"]["total_errors"] == 1
    assert report["repos"][0]["repo_path"] == str(repo.resolve())
