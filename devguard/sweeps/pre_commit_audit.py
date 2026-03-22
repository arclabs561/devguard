"""Pre-commit hook audit sweep: detect missing pre-commit configs and secret scanning hooks.

Scans git repos under a dev root and checks whether each repo has a
.pre-commit-config.yaml with at least one secret-scanning hook installed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos, utc_now as _utc_now

_DEFAULT_REQUIRED_HOOKS: list[str] = ["detect-secrets", "gitleaks", "trufflehog"]


def _has_pre_commit_hook_installed(repo: Path) -> bool:
    """Check if .git/hooks/pre-commit exists and references pre-commit."""
    hook = repo / ".git" / "hooks" / "pre-commit"
    if not hook.is_file():
        return False
    try:
        text = hook.read_text(encoding="utf-8", errors="replace")
        return "pre-commit" in text
    except Exception:
        return False


def _find_hook_ids(config_path: Path) -> set[str]:
    """Parse .pre-commit-config.yaml and return all hook IDs found."""
    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return set()
    if not isinstance(data, dict):
        return set()
    ids: set[str] = set()
    for repo_entry in data.get("repos", []) or []:
        if not isinstance(repo_entry, dict):
            continue
        for hook in repo_entry.get("hooks", []) or []:
            if isinstance(hook, dict) and "id" in hook:
                ids.add(hook["id"])
    return ids


def audit_pre_commit(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    required_hooks: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit pre-commit configs across repos and return a report."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    req_hooks = required_hooks if required_hooks is not None else _DEFAULT_REQUIRED_HOOKS

    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    repos = sorted(iter_git_repos(root, max_depth=max_depth, exclude_globs=globs))

    findings: list[dict[str, Any]] = []
    total_no_config = 0
    total_not_installed = 0
    total_no_secret_hook = 0

    for repo in repos:
        try:
            config_path = repo / ".pre-commit-config.yaml"
            repo_findings: list[dict[str, Any]] = []

            if not config_path.is_file():
                total_no_config += 1
                repo_findings.append({
                    "check_id": "no_pre_commit_config",
                    "severity": "warning",
                    "message": "Repo has no .pre-commit-config.yaml",
                })
            else:
                # Check if hook is installed in .git/hooks
                if not _has_pre_commit_hook_installed(repo):
                    total_not_installed += 1
                    repo_findings.append({
                        "check_id": "hook_not_installed",
                        "severity": "warning",
                        "message": (
                            "Config exists but .git/hooks/pre-commit is missing "
                            "or doesn't contain 'pre-commit'"
                        ),
                    })

                # Check for secret scanning hooks
                hook_ids = _find_hook_ids(config_path)
                has_secret_hook = any(h in hook_ids for h in req_hooks)
                if not has_secret_hook:
                    total_no_secret_hook += 1
                    repo_findings.append({
                        "check_id": "no_secret_scanning_hook",
                        "severity": "error",
                        "message": (
                            f"No secret scanning hook found. "
                            f"Expected at least one of: {req_hooks}. "
                            f"Found hooks: {sorted(hook_ids) if hook_ids else '(none)'}"
                        ),
                    })

            if repo_findings:
                findings.append({
                    "repo_path": str(repo),
                    "findings": repo_findings,
                })

        except Exception as exc:
            errors.append(f"failed to audit {repo}: {exc}")

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
            "required_hooks": req_hooks,
        },
        "summary": {
            "repos_without_config": total_no_config,
            "repos_hook_not_installed": total_not_installed,
            "repos_no_secret_scanning": total_no_secret_hook,
            "total_findings": total_no_config + total_not_installed + total_no_secret_hook,
            "repos_without_secret_hook": total_no_secret_hook,
        },
        "repos": findings[:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
