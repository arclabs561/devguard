"""Cargo publish audit sweep: check Rust repos for correct CI publish pipelines.

Scans git repos under a dev root for Cargo.toml, then audits the full e2e
publish pipeline: tag triggers, OIDC trusted publishing, dry-run checks,
version consistency, and workflow correctness.
"""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import utc_now as _utc_now


def _iter_rust_repos(root: Path, max_depth: int, exclude_globs: list[str]) -> list[Path]:
    """Discover git repos with Cargo.toml under root."""
    root = root.resolve()
    max_depth = max(0, min(int(max_depth), 6))
    junk = {
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
        ".git",
        ".cache",
        ".state",
        "__pycache__",
        "_trash",
        "_scratch",
        "_external",
        "_archive",
        "_forks",
        "target",
    }
    repos: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen: set[Path] = set()
    while stack:
        cur, depth = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if (cur / ".git").exists() and (cur / "Cargo.toml").exists():
            if not any(fnmatch.fnmatch(str(cur), g) for g in exclude_globs):
                repos.append(cur)
            continue
        if depth >= max_depth:
            continue
        try:
            for child in cur.iterdir():
                if not child.is_dir():
                    continue
                name = child.name
                if name in junk or name.startswith("."):
                    continue
                stack.append((child, depth + 1))
        except Exception:
            continue
    return sorted(repos)


def _is_likely_public(repo: Path) -> bool:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"):
        if (repo / name).exists():
            return True
    return False


def _read_cargo_version(repo: Path) -> str | None:
    """Read version from Cargo.toml (root package)."""
    cargo_toml = repo / "Cargo.toml"
    if not cargo_toml.is_file():
        return None
    try:
        text = cargo_toml.read_text(encoding="utf-8", errors="replace")
        # Simple regex -- good enough for [package] version = "x.y.z"
        m = re.search(r'^\[package\].*?^version\s*=\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL)
        return m.group(1) if m else None
    except Exception:
        return None


def _read_cargo_publish(repo: Path) -> bool | None:
    """Check if publish = false in Cargo.toml."""
    cargo_toml = repo / "Cargo.toml"
    if not cargo_toml.is_file():
        return None
    try:
        text = cargo_toml.read_text(encoding="utf-8", errors="replace")
        # Check for publish = false in [package] section
        pkg_match = re.search(r"^\[package\](.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
        if pkg_match:
            pkg_section = pkg_match.group(1)
            if re.search(r"^publish\s*=\s*false", pkg_section, re.MULTILINE):
                return False
        return True
    except Exception:
        return None


def _get_latest_version_tag(repo: Path) -> str | None:
    """Get latest semver tag from git."""
    try:
        res = subprocess.run(
            ["git", "tag", "--sort=-v:refname"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if res.returncode != 0:
            return None
        for line in res.stdout.strip().splitlines():
            tag = line.strip()
            # Match v0.1.0, 0.1.0, crate-name-v0.1.0
            m = re.search(r"v?(\d+\.\d+\.\d+(?:-[\w.]+)?)", tag)
            if m:
                return m.group(1)
        return None
    except Exception:
        return None


def _read_workflow_files(repo: Path) -> list[tuple[str, str]]:
    """Read all .yml/.yaml files from .github/workflows/."""
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    results = []
    for f in sorted(wf_dir.iterdir()):
        if f.suffix in (".yml", ".yaml") and f.is_file():
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                results.append((f.name, text))
            except Exception:
                continue
    return results


@dataclass
class Finding:
    check: str
    severity: str  # "error", "warning", "info"
    message: str
    detail: str = ""


@dataclass
class RepoAuditResult:
    repo_path: str
    repo_name: str
    is_public: bool
    cargo_version: str | None
    latest_tag: str | None
    publish_enabled: bool
    has_workflows: bool
    findings: list[Finding] = field(default_factory=list)


def _read_features(repo: Path) -> set[str]:
    """Extract feature names from Cargo.toml [features] section."""
    cargo_toml = repo / "Cargo.toml"
    if not cargo_toml.is_file():
        return set()
    try:
        text = cargo_toml.read_text(encoding="utf-8", errors="replace")
        feat_section = re.search(r"^\[features\](.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
        if not feat_section:
            return set()
        features = set()
        for m in re.finditer(r"^(\w[\w-]*)\s*=", feat_section.group(1), re.MULTILINE):
            features.add(m.group(1))
        return features
    except Exception:
        return set()


def _check_feature_gated_tests(repo: Path, result: RepoAuditResult) -> None:
    """Flag integration tests that import feature-gated modules without a #![cfg] gate.

    Pattern: a test file uses `use crate_name::feature_module::` but doesn't have
    `#![cfg(feature = "...")]` at the top. This causes compilation failures when
    running `cargo test` without that feature enabled.
    """
    features = _read_features(repo)
    if not features:
        return

    # Find crate name from Cargo.toml
    cargo_toml = repo / "Cargo.toml"
    try:
        text = cargo_toml.read_text(encoding="utf-8", errors="replace")
        name_match = re.search(
            r'^\[package\].*?^name\s*=\s*"([^"]+)"', text, re.MULTILINE | re.DOTALL
        )
        if not name_match:
            return
        crate_name = name_match.group(1).replace("-", "_")
    except Exception:
        return

    # Scan tests/ and also workspace member tests/
    test_dirs = [repo / "tests"]
    # Check workspace members
    members_match = re.search(
        r"^\[workspace\].*?members\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL
    )
    if members_match:
        for m in re.finditer(r'"([^"]+)"', members_match.group(1)):
            member_path = repo / m.group(1)
            test_dirs.append(member_path / "tests")
            # Also read that member's features and crate name
            member_toml = member_path / "Cargo.toml"
            if member_toml.is_file():
                try:
                    mt = member_toml.read_text(encoding="utf-8", errors="replace")
                    mname = re.search(
                        r'^\[package\].*?^name\s*=\s*"([^"]+)"', mt, re.MULTILINE | re.DOTALL
                    )
                    if mname:
                        member_crate = mname.group(1).replace("-", "_")
                        mfeats = re.search(
                            r"^\[features\](.*?)(?=^\[|\Z)", mt, re.MULTILINE | re.DOTALL
                        )
                        if mfeats:
                            for feat_m in re.finditer(
                                r"^(\w[\w-]*)\s*=", mfeats.group(1), re.MULTILINE
                            ):
                                features.add(feat_m.group(1))
                            crate_name = member_crate  # use member name for import matching
                except Exception:
                    pass

    for test_dir in test_dirs:
        if not test_dir.is_dir():
            continue
        try:
            for test_file in test_dir.iterdir():
                if not test_file.is_file() or test_file.suffix != ".rs":
                    continue
                try:
                    content = test_file.read_text(encoding="utf-8", errors="replace")
                except Exception:
                    continue

                # Check if file has a top-level cfg gate
                has_cfg = bool(re.search(r"#!\[cfg\(feature\s*=", content[:500]))
                if has_cfg:
                    continue

                # Check if file imports feature-gated modules
                for feat in features:
                    feat_mod = feat.replace("-", "_")
                    # Look for `use crate_name::feat_mod` or `crate_name::feat_mod::`
                    pattern = rf"\b{re.escape(crate_name)}::{re.escape(feat_mod)}\b"
                    if re.search(pattern, content):
                        result.findings.append(
                            Finding(
                                check="ungated_feature_test",
                                severity="error",
                                message=f"{test_file.name}: imports `{crate_name}::{feat_mod}` "
                                f'but lacks `#![cfg(feature = "{feat}")]`',
                                detail="This test will fail to compile without the feature enabled. "
                                'Add `#![cfg(feature = "...")]` at the top of the test file.',
                            )
                        )
                        break  # one finding per file is enough
        except Exception:
            continue


def _audit_repo(repo: Path) -> RepoAuditResult:
    """Run all cargo publish checks on a single repo."""
    name = repo.name
    is_public = _is_likely_public(repo)
    cargo_version = _read_cargo_version(repo)
    publish_enabled = _read_cargo_publish(repo) is not False
    latest_tag = _get_latest_version_tag(repo)
    workflows = _read_workflow_files(repo)
    has_workflows = len(workflows) > 0

    result = RepoAuditResult(
        repo_path=str(repo),
        repo_name=name,
        is_public=is_public,
        cargo_version=cargo_version,
        latest_tag=latest_tag,
        publish_enabled=publish_enabled,
        has_workflows=has_workflows,
    )

    # Skip unpublishable crates
    if not publish_enabled:
        result.findings.append(
            Finding(
                check="publish_disabled",
                severity="info",
                message="publish = false in Cargo.toml; skipping publish checks",
            )
        )
        return result

    # Check: has any workflow files at all
    if not has_workflows:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(
                check="no_workflows",
                severity=sev,
                message="No .github/workflows/ directory or no workflow files",
            )
        )
        return result

    all_text = "\n".join(text for _, text in workflows)

    # Check: has a publish workflow (any file with cargo publish)
    publish_files = [
        (f, t) for f, t in workflows if "cargo publish" in t.lower() or "cargo-publish" in t.lower()
    ]
    has_publish_wf = len(publish_files) > 0

    if not has_publish_wf:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(
                check="no_publish_workflow",
                severity=sev,
                message="No workflow contains `cargo publish`",
                detail="Expected at least one workflow with a publish step",
            )
        )

    # Check: tag-triggered release
    has_tag_trigger = bool(re.search(r"on:\s*\n\s+push:\s*\n\s+tags:", all_text, re.MULTILINE))
    # Also check workflow_dispatch / release event as alternatives
    has_release_trigger = "release:" in all_text or "workflow_dispatch:" in all_text
    has_any_release_trigger = has_tag_trigger or has_release_trigger

    if has_publish_wf and not has_any_release_trigger:
        result.findings.append(
            Finding(
                check="no_tag_trigger",
                severity="warning",
                message="Publish workflow has no tag/release trigger",
                detail="Expected `on: push: tags:` or `on: release:` or `workflow_dispatch`",
            )
        )

    # Check: OIDC trusted publishing (id-token: write)
    has_oidc = bool(re.search(r"id-token\s*:\s*write", all_text))
    # Also check for crates.io trusted publishing action patterns
    has_trusted_publish_action = "trusted-publishing" in all_text.lower()

    if has_publish_wf and not has_oidc and not has_trusted_publish_action:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(
                check="no_oidc",
                severity=sev,
                message="No OIDC trusted publishing setup (missing `id-token: write`)",
                detail="Trusted publishing avoids long-lived API tokens. "
                "Set `permissions: id-token: write` and configure crates.io trusted publishers.",
            )
        )

    # Check: dry-run on PRs
    has_dry_run = bool(re.search(r"cargo\s+publish\s+.*--dry-run", all_text))
    # Also check for separate CI workflow with cargo check/test
    has_ci_workflow = any(
        ("pull_request" in t or "push:" in t)
        and ("cargo test" in t or "cargo check" in t or "cargo clippy" in t)
        for _, t in workflows
    )

    if has_publish_wf and not has_dry_run:
        result.findings.append(
            Finding(
                check="no_dry_run",
                severity="warning",
                message="No `cargo publish --dry-run` found in CI",
                detail="Dry-run catches packaging errors (missing files, bad metadata) before tagging. "
                "Consider adding it to PR checks.",
            )
        )

    if not has_ci_workflow and not has_dry_run:
        result.findings.append(
            Finding(
                check="no_pr_ci",
                severity="warning",
                message="No PR/push CI workflow with cargo test/check/clippy",
                detail="Basic CI catches build failures before publish",
            )
        )

    # Check: hardcoded tokens (anti-pattern)
    for fname, text in workflows:
        # Look for literal token values (not ${{ secrets.X }})
        if re.search(r'CARGO_REGISTRY_TOKEN\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}', text):
            result.findings.append(
                Finding(
                    check="hardcoded_token",
                    severity="error",
                    message=f"Possible hardcoded registry token in {fname}",
                    detail="Use ${{{{ secrets.CARGO_REGISTRY_TOKEN }}}} or OIDC trusted publishing",
                )
            )

    # Check: secret-based auth when OIDC is available (migration target)
    for fname, text in publish_files:
        uses_secret = bool(re.search(r"secrets\.CARGO_REGISTRY_TOKEN", text))
        if uses_secret and not has_oidc:
            result.findings.append(
                Finding(
                    check="secret_based_auth",
                    severity="warning",
                    message=f"{fname}: uses secrets.CARGO_REGISTRY_TOKEN instead of OIDC",
                    detail="Migrate to rust-lang/crates-io-auth-action@v1 for short-lived tokens. "
                    "Add `permissions: id-token: write` and remove the secret.",
                )
            )

    # Check: LICENSE file for public repos
    if is_public:
        has_license = any(
            (repo / name).exists()
            for name in (
                "LICENSE",
                "LICENSE.md",
                "LICENSE.txt",
                "LICENSE-MIT",
                "LICENSE-APACHE",
                "LICENCE",
            )
        )
        if not has_license:
            result.findings.append(
                Finding(
                    check="no_license_file",
                    severity="error",
                    message="Public repo has no LICENSE file",
                    detail="Cargo.toml may declare a license but crates.io and legal compliance "
                    "require the actual license text. Add LICENSE-MIT and/or LICENSE-APACHE.",
                )
            )

    # Check: CI quality (fmt + clippy in CI workflows)
    if has_ci_workflow:
        ci_text = "\n".join(t for _, t in workflows if "pull_request" in t or "push:" in t)
        has_fmt = bool(re.search(r"cargo\s+fmt", ci_text))
        has_clippy = bool(re.search(r"cargo\s+clippy", ci_text))
        if not has_fmt:
            result.findings.append(
                Finding(
                    check="ci_no_fmt",
                    severity="info",
                    message="CI does not run `cargo fmt --check`",
                    detail="Formatting drift accumulates without CI enforcement.",
                )
            )
        if not has_clippy:
            result.findings.append(
                Finding(
                    check="ci_no_clippy",
                    severity="info",
                    message="CI does not run `cargo clippy`",
                )
            )

    # Check: feature-gated tests without cfg gate.
    # Tests that import feature-gated modules (e.g., `use crate::qdrant::`) but lack
    # `#![cfg(feature = "...")]` will fail to compile without that feature enabled.
    _check_feature_gated_tests(repo, result)

    # Check: version vs tag consistency
    if cargo_version and latest_tag:
        if cargo_version != latest_tag:
            # Could be intentional (dev version bump), so just info
            result.findings.append(
                Finding(
                    check="version_tag_mismatch",
                    severity="info",
                    message=f"Cargo.toml version ({cargo_version}) != latest tag ({latest_tag})",
                    detail="If you've bumped the version for a pending release, this is expected. "
                    "Otherwise, ensure tags match published versions.",
                )
            )
    elif cargo_version and not latest_tag:
        result.findings.append(
            Finding(
                check="no_version_tags",
                severity="info",
                message=f"Cargo.toml version is {cargo_version} but no semver tags found",
                detail="Tag releases with `v{version}` for traceability",
            )
        )

    # Check: publish workflow has checkout + build/test before publish
    for fname, text in publish_files:
        has_checkout = "actions/checkout" in text
        has_test_before = bool(
            re.search(r"cargo\s+(test|build|check|clippy).*\n.*cargo\s+publish", text, re.DOTALL)
        )
        if not has_checkout:
            result.findings.append(
                Finding(
                    check="missing_checkout",
                    severity="warning",
                    message=f"{fname}: publish workflow missing actions/checkout",
                )
            )
        if not has_test_before and "cargo test" not in text and "cargo build" not in text:
            result.findings.append(
                Finding(
                    check="no_test_before_publish",
                    severity="warning",
                    message=f"{fname}: no test/build step before cargo publish",
                    detail="Run tests before publishing to catch regressions",
                )
            )

    # Check: environment protection (for publish jobs)
    for fname, text in publish_files:
        has_environment = bool(re.search(r"environment\s*:", text))
        if not has_environment and has_oidc:
            result.findings.append(
                Finding(
                    check="no_environment_protection",
                    severity="info",
                    message=f"{fname}: OIDC publish without GitHub environment protection",
                    detail="Using a named environment (e.g., `crates-io`) adds an approval gate",
                )
            )

    return result


def audit_cargo_publish(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    only_public: bool = False,
    repo_names: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit cargo publish pipelines across repos and return a report."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]

    repos = _iter_rust_repos(root, max_depth=max_depth, exclude_globs=globs)

    if repo_names:
        name_set = set(repo_names)
        repos = [r for r in repos if r.name in name_set]

    if only_public:
        repos = [r for r in repos if _is_likely_public(r)]

    results: list[RepoAuditResult] = []
    for repo in repos:
        try:
            result = _audit_repo(repo)
            results.append(result)
        except Exception as exc:
            errors.append(f"failed to audit {repo}: {exc}")

    # Sort: public repos with errors first
    results.sort(
        key=lambda r: (
            -r.is_public,
            -sum(1 for f in r.findings if f.severity == "error"),
            -sum(1 for f in r.findings if f.severity == "warning"),
            r.repo_name,
        )
    )

    # Summary stats
    repos_with_errors = [r for r in results if any(f.severity == "error" for f in r.findings)]
    repos_with_warnings = [r for r in results if any(f.severity == "warning" for f in r.findings)]
    check_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            check_counts[f.check] = check_counts.get(f.check, 0) + 1

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "rust_repos_found": len(results),
            "max_depth": max_depth,
            "only_public": only_public,
            "repo_names_filter": repo_names,
            "exclude_repo_globs": globs,
        },
        "summary": {
            "repos_with_errors": len(repos_with_errors),
            "repos_with_errors_list": [r.repo_name for r in repos_with_errors],
            "repos_with_warnings": len(repos_with_warnings),
            "repos_with_warnings_list": [r.repo_name for r in repos_with_warnings],
            "total_findings": sum(len(r.findings) for r in results),
            "findings_by_check": sorted(check_counts.items(), key=lambda x: -x[1]),
            "total_errors": sum(1 for r in results for f in r.findings if f.severity == "error"),
            "total_warnings": sum(
                1 for r in results for f in r.findings if f.severity == "warning"
            ),
        },
        "repos": [
            {
                "repo_path": r.repo_path,
                "repo_name": r.repo_name,
                "is_public": r.is_public,
                "cargo_version": r.cargo_version,
                "latest_tag": r.latest_tag,
                "publish_enabled": r.publish_enabled,
                "has_workflows": r.has_workflows,
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity,
                        "message": f.message,
                        **({"detail": f.detail} if f.detail else {}),
                    }
                    for f in r.findings
                ],
            }
            for r in results
            if r.findings  # only include repos with findings
        ][:200],
        "clean_repos": [r.repo_name for r in results if not r.findings],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
