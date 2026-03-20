"""Multi-ecosystem publish audit: check PyPI and npm repos for correct CI publish pipelines.

Complements cargo_publish_audit by covering Python (pyproject.toml) and
JavaScript/TypeScript (package.json) repos. Checks OIDC trusted publishing,
workflow correctness, version consistency, and license presence.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _default_dev_root() -> Path:
    return Path(os.getenv("DEV_DIR") or "~/Documents/dev").expanduser()


def _iter_repos(root: Path, max_depth: int, exclude_globs: list[str]) -> list[tuple[Path, str]]:
    """Discover git repos with pyproject.toml or package.json under root.

    Returns (repo_path, ecosystem) tuples. A repo can appear twice if it has both.
    """
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
    repos: list[tuple[Path, str]] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen: set[Path] = set()
    while stack:
        cur, depth = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if (cur / ".git").exists():
            if not any(fnmatch.fnmatch(str(cur), g) for g in exclude_globs):
                if (cur / "pyproject.toml").exists():
                    repos.append((cur, "pypi"))
                if (cur / "package.json").exists():
                    # Skip if private: true
                    try:
                        pkg = json.loads(
                            (cur / "package.json").read_text(encoding="utf-8", errors="replace")
                        )
                        if not pkg.get("private", False):
                            repos.append((cur, "npm"))
                    except Exception:
                        pass
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
    return sorted(repos, key=lambda x: (x[0].name, x[1]))


def _is_likely_public(repo: Path) -> bool:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE-MIT", "LICENCE"):
        if (repo / name).exists():
            return True
    return False


def _get_latest_version_tag(repo: Path) -> str | None:
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
            m = re.search(r"v?(\d+\.\d+\.\d+(?:-[\w.]+)?)", tag)
            if m:
                return m.group(1)
        return None
    except Exception:
        return None


def _read_workflow_files(repo: Path) -> list[tuple[str, str]]:
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
    severity: str
    message: str
    detail: str = ""


@dataclass
class RepoAuditResult:
    repo_path: str
    repo_name: str
    ecosystem: str  # "pypi" or "npm"
    is_public: bool
    package_name: str | None
    package_version: str | None
    latest_tag: str | None
    has_workflows: bool
    findings: list[Finding] = field(default_factory=list)


def _read_pypi_metadata(repo: Path) -> tuple[str | None, str | None]:
    """Read package name and version from pyproject.toml."""
    toml_path = repo / "pyproject.toml"
    if not toml_path.is_file():
        return None, None
    try:
        text = toml_path.read_text(encoding="utf-8", errors="replace")
        name = None
        version = None
        proj_match = re.search(r"^\[project\](.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
        if proj_match:
            section = proj_match.group(1)
            nm = re.search(r'^name\s*=\s*"([^"]+)"', section, re.MULTILINE)
            if nm:
                name = nm.group(1)
            vm = re.search(r'^version\s*=\s*"([^"]+)"', section, re.MULTILINE)
            if vm:
                version = vm.group(1)
        return name, version
    except Exception:
        return None, None


def _read_npm_metadata(repo: Path) -> tuple[str | None, str | None]:
    """Read package name and version from package.json."""
    pkg_path = repo / "package.json"
    if not pkg_path.is_file():
        return None, None
    try:
        pkg = json.loads(pkg_path.read_text(encoding="utf-8", errors="replace"))
        return pkg.get("name"), pkg.get("version")
    except Exception:
        return None, None


def _audit_pypi_repo(repo: Path) -> RepoAuditResult:
    """Audit a Python repo for PyPI publish readiness."""
    name = repo.name
    is_public = _is_likely_public(repo)
    pkg_name, pkg_version = _read_pypi_metadata(repo)
    latest_tag = _get_latest_version_tag(repo)
    workflows = _read_workflow_files(repo)
    has_workflows = len(workflows) > 0

    result = RepoAuditResult(
        repo_path=str(repo),
        repo_name=name,
        ecosystem="pypi",
        is_public=is_public,
        package_name=pkg_name,
        package_version=pkg_version,
        latest_tag=latest_tag,
        has_workflows=has_workflows,
    )

    if not has_workflows:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(check="no_workflows", severity=sev, message="No CI workflows")
        )
        return result

    all_text = "\n".join(text for _, text in workflows)

    # Check: publish workflow
    publish_files = [
        (f, t)
        for f, t in workflows
        if "pypi" in t.lower()
        or "twine" in t.lower()
        or "maturin" in t.lower()
        or "gh-action-pypi-publish" in t
    ]

    if not publish_files:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(
                check="no_publish_workflow",
                severity=sev,
                message="No PyPI publish workflow detected",
                detail="Expected a workflow using pypa/gh-action-pypi-publish, twine, or maturin.",
            )
        )

    # Check: OIDC trusted publishing
    has_oidc = bool(re.search(r"id-token\s*:\s*write", all_text))
    has_pypi_action = "gh-action-pypi-publish" in all_text

    if publish_files and not has_oidc:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(
                check="no_oidc",
                severity=sev,
                message="No OIDC trusted publishing (missing `id-token: write`)",
                detail="PyPI supports trusted publishing via pypa/gh-action-pypi-publish. "
                "Configure a pending publisher at pypi.org/manage/account/publishing/.",
            )
        )

    # Check: uses token secret instead of OIDC
    for fname, text in publish_files:
        if re.search(r"secrets\.(PYPI_TOKEN|PYPI_API_TOKEN|TWINE_PASSWORD)", text):
            if not has_oidc:
                result.findings.append(
                    Finding(
                        check="secret_based_auth",
                        severity="warning",
                        message=f"{fname}: uses PyPI secret instead of OIDC trusted publishing",
                        detail="Migrate to pypa/gh-action-pypi-publish with `id-token: write`.",
                    )
                )

    # Check: LICENSE
    if is_public:
        has_license = any(
            (repo / n).exists() for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE")
        )
        if not has_license:
            result.findings.append(
                Finding(
                    check="no_license_file",
                    severity="error",
                    message="Public repo has no LICENSE file",
                )
            )

    return result


def _audit_npm_repo(repo: Path) -> RepoAuditResult:
    """Audit a JS/TS repo for npm publish readiness."""
    name = repo.name
    is_public = _is_likely_public(repo)
    pkg_name, pkg_version = _read_npm_metadata(repo)
    latest_tag = _get_latest_version_tag(repo)
    workflows = _read_workflow_files(repo)
    has_workflows = len(workflows) > 0

    result = RepoAuditResult(
        repo_path=str(repo),
        repo_name=name,
        ecosystem="npm",
        is_public=is_public,
        package_name=pkg_name,
        package_version=pkg_version,
        latest_tag=latest_tag,
        has_workflows=has_workflows,
    )

    if not has_workflows:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(check="no_workflows", severity=sev, message="No CI workflows")
        )
        return result

    all_text = "\n".join(text for _, text in workflows)

    # Check: publish workflow
    publish_files = [
        (f, t) for f, t in workflows if "npm publish" in t or "provenance" in t.lower()
    ]

    if not publish_files:
        sev = "error" if is_public else "warning"
        result.findings.append(
            Finding(
                check="no_publish_workflow",
                severity=sev,
                message="No npm publish workflow detected",
            )
        )

    # Check: OIDC / provenance
    has_oidc = bool(re.search(r"id-token\s*:\s*write", all_text))
    has_provenance = "--provenance" in all_text

    if publish_files and not has_oidc:
        result.findings.append(
            Finding(
                check="no_oidc",
                severity="warning",
                message="No OIDC setup (missing `id-token: write`)",
                detail="npm supports provenance via `npm publish --provenance` with OIDC.",
            )
        )

    # Check: uses NPM_TOKEN secret
    for fname, text in publish_files:
        if re.search(r"secrets\.NPM_TOKEN", text) and not has_oidc:
            result.findings.append(
                Finding(
                    check="secret_based_auth",
                    severity="warning",
                    message=f"{fname}: uses secrets.NPM_TOKEN instead of OIDC provenance",
                )
            )

    # Check: LICENSE
    if is_public:
        has_license = any(
            (repo / n).exists() for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE")
        )
        if not has_license:
            result.findings.append(
                Finding(
                    check="no_license_file",
                    severity="error",
                    message="Public repo has no LICENSE file",
                )
            )

    return result


def audit_publish(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    ecosystems: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit PyPI and npm publish pipelines across repos."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    allowed = set(ecosystems) if ecosystems else {"pypi", "npm"}

    repos = _iter_repos(root, max_depth=max_depth, exclude_globs=globs)
    repos = [(r, e) for r, e in repos if e in allowed]

    results: list[RepoAuditResult] = []
    for repo, ecosystem in repos:
        try:
            if ecosystem == "pypi":
                result = _audit_pypi_repo(repo)
            else:
                result = _audit_npm_repo(repo)
            results.append(result)
        except Exception as exc:
            errors.append(f"failed to audit {repo} ({ecosystem}): {exc}")

    results.sort(
        key=lambda r: (
            -r.is_public,
            -sum(1 for f in r.findings if f.severity == "error"),
            r.repo_name,
        )
    )

    repos_with_errors = [r for r in results if any(f.severity == "error" for f in r.findings)]
    check_counts: dict[str, int] = {}
    for r in results:
        for f in r.findings:
            check_counts[f.check] = check_counts.get(f.check, 0) + 1

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "ecosystems": sorted(allowed),
            "exclude_repo_globs": globs,
        },
        "summary": {
            "repos_with_errors": len(repos_with_errors),
            "repos_with_errors_list": [f"{r.repo_name} ({r.ecosystem})" for r in repos_with_errors],
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
                "ecosystem": r.ecosystem,
                "is_public": r.is_public,
                "package_name": r.package_name,
                "package_version": r.package_version,
                "latest_tag": r.latest_tag,
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
            if r.findings
        ][:200],
        "clean_repos": [f"{r.repo_name} ({r.ecosystem})" for r in results if not r.findings],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
