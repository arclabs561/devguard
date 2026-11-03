"""Tests for cargo_publish_audit's dependency, CI-doc and registry checks."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any

from devguard.sweeps.cargo_publish_audit import _audit_repo

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
