"""Tests for cargo_publish_audit's dependency, CI-doc and registry checks."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from devguard.sweeps.cargo_publish_audit import _audit_repo, audit_cargo_publish

CI = """name: ci
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: cargo fmt --check
      - run: cargo clippy -- -D warnings
      - run: cargo test
"""


def _git(repo: Path, *args: str, date: str | None = None) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.com",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.com",
    }
    if date:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = date
    subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True)


def _repo(tmp_path: Path, cargo: str, ci: str = CI) -> Path:
    repo = tmp_path / "crate"
    (repo / "src").mkdir(parents=True)
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / "Cargo.toml").write_text(cargo)
    (repo / "src" / "lib.rs").write_text("pub fn f() {}\n")
    (repo / "LICENSE-MIT").write_text("MIT\n")
    (repo / ".github" / "workflows" / "ci.yml").write_text(ci)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init", date="2026-01-01T00:00:00Z")
    return repo


def _checks(repo: Path, **kw: Any) -> list[str]:
    return [f.check for f in _audit_repo(repo, **kw).findings]


PKG = '[package]\nname = "demo"\nversion = "0.1.0"\n'


def test_git_dependency_without_version_is_an_error(tmp_path: Path) -> None:
    repo = _repo(tmp_path, PKG + '[dependencies]\nfoo = { git = "https://x/foo" }\n')
    findings = _audit_repo(repo).findings
    hit = [f for f in findings if f.check == "git_dependency"]
    assert len(hit) == 1
    assert hit[0].severity == "error"
    assert "`foo`" in hit[0].message


def test_git_dependency_with_version_is_shadowed(tmp_path: Path) -> None:
    cargo = PKG + '[dependencies]\nfoo = { version = "0.6", git = "https://x/foo" }\n'
    checks = _checks(_repo(tmp_path, cargo))
    assert "git_dependency_shadowed" in checks
    assert "git_dependency" not in checks


def test_patch_crates_io_is_shadowed(tmp_path: Path) -> None:
    cargo = (
        PKG + '[dependencies]\nfoo = "0.6"\n\n[patch.crates-io]\nfoo = { git = "https://x/foo" }\n'
    )
    findings = _audit_repo(_repo(tmp_path, cargo)).findings
    msgs = [f.message for f in findings if f.check == "git_dependency_shadowed"]
    assert msgs == ["[patch.crates-io] overrides `foo`"]


def test_target_specific_git_dependency_is_checked(tmp_path: Path) -> None:
    cargo = PKG + "[target.'cfg(unix)'.dependencies]\nbar = { git = \"https://x/bar\" }\n"
    assert "git_dependency" in _checks(_repo(tmp_path, cargo))


def test_git_dev_dependency_is_ignored(tmp_path: Path) -> None:
    cargo = PKG + '[dev-dependencies]\nfoo = { git = "https://x/foo" }\n'
    checks = _checks(_repo(tmp_path, cargo))
    assert "git_dependency" not in checks
    assert "git_dependency_shadowed" not in checks


def test_ci_without_cargo_doc_is_flagged(tmp_path: Path) -> None:
    assert "ci_no_doc" in _checks(_repo(tmp_path, PKG))
    with_doc = CI + '      - run: RUSTDOCFLAGS="-D warnings" cargo doc --no-deps\n'
    assert "ci_no_doc" not in _checks(_repo(tmp_path / "b", PKG, ci=with_doc))


def _fetch(owners: list[str], version: str, published: str) -> Any:
    def fetch(url: str) -> dict[str, Any] | None:
        if url.endswith("/owners"):
            return {"users": [{"login": o} for o in owners]}
        return {
            "crate": {"max_version": version},
            "versions": [{"num": version, "created_at": published}],
        }

    return fetch


def test_registry_checks_are_off_without_fetch(tmp_path: Path) -> None:
    checks = _checks(_repo(tmp_path, PKG))
    for check in ("registry_name_foreign", "published_untagged", "release_lag"):
        assert check not in checks


def test_foreign_crates_io_name(tmp_path: Path) -> None:
    repo = _repo(tmp_path, PKG)
    checks = _checks(
        repo,
        registry_fetch=_fetch(["someone"], "0.1.0", "2026-01-02T00:00:00Z"),
        registry_owner="me",
    )
    assert "registry_name_foreign" in checks
    # A foreign name stops the remaining registry checks.
    assert "published_untagged" not in checks
    owned = _checks(
        repo, registry_fetch=_fetch(["me"], "0.1.0", "2026-01-02T00:00:00Z"), registry_owner="me"
    )
    assert "registry_name_foreign" not in owned


def test_published_untagged_and_tagged(tmp_path: Path) -> None:
    repo = _repo(tmp_path, PKG)
    fetch = _fetch(["me"], "0.1.0", "2026-01-02T00:00:00Z")
    assert "published_untagged" in _checks(repo, registry_fetch=fetch, registry_owner="me")
    _git(repo, "tag", "v0.1.0")
    assert "published_untagged" not in _checks(repo, registry_fetch=fetch, registry_owner="me")


def test_release_lag_counts_code_commits_after_publish(tmp_path: Path) -> None:
    repo = _repo(tmp_path, PKG)
    _git(repo, "tag", "v0.1.0")
    fetch = _fetch(["me"], "0.1.0", "2026-01-02T00:00:00Z")
    assert "release_lag" not in _checks(repo, registry_fetch=fetch, registry_owner="me")

    (repo / "README.md").write_text("docs only\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-q", "-m", "docs", date="2026-01-03T00:00:00Z")
    assert "release_lag" not in _checks(repo, registry_fetch=fetch, registry_owner="me")

    (repo / "src" / "lib.rs").write_text("pub fn f() -> u8 { 1 }\n")
    _git(repo, "commit", "-q", "-am", "fix", date="2026-01-04T00:00:00Z")
    findings = _audit_repo(repo, registry_fetch=fetch, registry_owner="me").findings
    lag = [f for f in findings if f.check == "release_lag"]
    assert len(lag) == 1
    assert lag[0].message.startswith("1 code commit(s)")


def test_dual_license_files_mark_a_repo_public(tmp_path: Path) -> None:
    # The fixture ships only LICENSE-MIT, the usual Rust layout with LICENSE-APACHE.
    assert _audit_repo(_repo(tmp_path, PKG)).is_public


def _workspace(tmp_path: Path, command: str, *, defaults: str = "") -> Path:
    from textwrap import indent

    repo = _repo(
        tmp_path,
        '[workspace]\nmembers = ["lib", "bin"]\n' + defaults,
        ci=CI + "      - run: |\n" + indent(command, "          ") + "\n",
    )
    for name in ("lib", "bin"):
        (repo / name).mkdir()
        (repo / name / "Cargo.toml").write_text(f'[package]\nname = "{name}"\nversion = "0.1.0"\n')
    return repo


def test_shared_staging_in_workspace_script_with_unpublished_root(tmp_path: Path) -> None:
    repo = _workspace(tmp_path, "bash scripts/check.sh")
    manifest = repo / "Cargo.toml"
    manifest.write_text(manifest.read_text() + PKG + "publish = false\n")
    (repo / "scripts").mkdir()
    script = repo / "scripts/check.sh"
    script.write_text(
        "#!/bin/bash\n"
        'work_dir=$(mktemp -d "${TMPDIR:-/tmp}/publish.XXXXXX")\n'
        "if cargo publish --workspace --dry-run; then\n"
        "    echo ok\nfi\n"
    )
    hits = [f for f in _audit_repo(repo).findings if f.check == "reused_publish_staging"]
    assert len(hits) == 1
    assert "scripts/check.sh, line 3" in hits[0].message
    assert "ci.yml (job test, step 4)" in hits[0].detail
    script.write_text(
        script.read_text().replace("--dry-run;", '--dry-run --target-dir "$work_dir/target";')
    )
    assert "reused_publish_staging" not in _checks(repo)


def test_implicit_selection_and_option_scope(tmp_path: Path) -> None:
    repo = _workspace(
        tmp_path,
        """
        echo 'cargo publish --workspace --dry-run'
        # cargo publish --workspace --dry-run
        cargo publish --workspace --dry-run --exclude bin
        cargo publish -p lib --dry-run
        cargo publish --workspace
        cargo publish --workspace --dry-run --no-verify
        cargo publish --dry-run
        cargo +stable publish --dry-run -p lib -p bin --target-dir=target
    """,
    )
    hits = [f for f in _audit_repo(repo).findings if f.check == "reused_publish_staging"]
    assert len(hits) == 2
    (repo / "Cargo.toml").write_text(
        (repo / "Cargo.toml").read_text() + 'default-members = ["lib"]\n'
    )
    assert _checks(repo).count("reused_publish_staging") == 1


def test_target_must_be_fresh_for_this_command(tmp_path: Path) -> None:
    repo = _workspace(
        tmp_path,
        """
        staging=$(mktemp -d)
        CARGO_TARGET_DIR="$staging" cargo publish --workspace --dry-run
        CARGO_TARGET_DIR="$staging" cargo publish --workspace --dry-run
        cargo publish --workspace --dry-run --target-dir "$(mktemp -d)"
        # The fresh inline assignment above does not persist.
        cargo publish --workspace --dry-run
        export CARGO_TARGET_DIR="$(mktemp -d)"
        cargo publish --workspace --dry-run --target-dir target/shared
    """,
    )
    assert _checks(repo).count("reused_publish_staging") == 3


def test_workflow_commands_cannot_follow_scripts_outside_checkout(tmp_path: Path) -> None:
    repo = _workspace(tmp_path, "./outside.sh")
    path = tmp_path / "private.sh"
    path.write_text("cargo publish --workspace --dry-run\n")
    (repo / "outside.sh").symlink_to(path)
    assert "reused_publish_staging" not in _checks(repo)


def test_fresh_shell_variable_requires_export_for_cargo(tmp_path: Path) -> None:
    repo = _workspace(
        tmp_path,
        """
        CARGO_TARGET_DIR="$(mktemp -d)"
        cargo publish --workspace --dry-run
        export CARGO_TARGET_DIR
        cargo publish --workspace --dry-run
        unset CARGO_TARGET_DIR
        cargo publish --workspace --dry-run
    """,
    )
    assert _checks(repo).count("reused_publish_staging") == 2


def test_standard_sweep_reaches_nested_workspace(tmp_path: Path) -> None:
    repo = _workspace(tmp_path, "cargo publish --dry-run")
    source = repo / "rust"
    source.mkdir()
    for entry in ("Cargo.toml", "lib", "bin"):
        (repo / entry).rename(source / entry)
    workflow = repo / ".github/workflows/ci.yml"
    workflow.write_text(
        workflow.read_text().replace(
            "      - run: |", "      - working-directory: rust\n        run: |"
        )
    )
    _git(repo, "add", ".")
    report, errors = audit_cargo_publish(dev_root=tmp_path)
    assert not errors
    assert report["scope"]["staging_only_repos"] == ["crate"]
    assert [f["check"] for f in report["repos"][0]["findings"]] == ["reused_publish_staging"]


def test_feature_test_finding_survives_fleet_serialization(tmp_path: Path) -> None:
    from devguard.fleet import extract_findings

    repo = _repo(tmp_path, PKG + "[features]\nstore = []\n")
    (repo / "tests").mkdir()
    (repo / "tests/mixed.rs").write_text(
        '#[cfg(feature = "store")]\nmod store_tests { use demo::store::Index; }'
    )
    report, errors = audit_cargo_publish(dev_root=tmp_path)
    assert not errors
    (raw,) = [f for f in report["repos"][0]["findings"] if f["check"] == "ungated_feature_test"]
    assert raw["file"] == "tests/mixed.rs"
    assert raw["severity"] == "warning"
    assert "cargo test" in raw["message"] and "--features store" in raw["message"]
    assert "will fail" not in raw["message"] + raw["detail"]
    findings = extract_findings({"cargo_publish_audit": report})
    (row,) = [f for f in findings if f["check"] == "ungated_feature_test"]
    assert (row["file"], row["severity"]) == ("tests/mixed.rs", "medium")


def test_feature_test_respects_only_its_own_required_features(tmp_path: Path) -> None:
    repo = _repo(
        tmp_path,
        PKG + "[features]\nstore = []\nother = []\n"
        '[[test]]\nname="configured"\npath="./tests/custom.rs"\nrequired-features=["store"]\n'
        '[[test]]\nname="mismatch"\nrequired-features=["other"]\n',
    )
    (repo / "tests").mkdir()
    for name in ("custom", "mismatch"):
        (repo / f"tests/{name}.rs").write_text("use demo::store::Index;")
    hits = [f for f in _audit_repo(repo).findings if f.check == "ungated_feature_test"]
    assert [f.file for f in hits] == ["tests/mismatch.rs"]
