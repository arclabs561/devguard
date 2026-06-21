"""Git identity audit sweep.

Checks configured git author emails and, optionally, commit metadata for
domains that should not appear in this workspace.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now

_EMAIL_RE = re.compile(r"(?P<email>[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})", re.IGNORECASE)


def _normalize_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("@")


def _email_domain(email: str) -> str:
    if "@" not in email:
        return ""
    return email.rsplit("@", 1)[1].strip().lower()


def _extract_emails(value: str) -> list[str]:
    return [m.group("email").lower() for m in _EMAIL_RE.finditer(value or "")]


def _git_output(args: list[str], *, cwd: Path | None = None, timeout: int = 10) -> str | None:
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _finding(
    *,
    check_id: str,
    source: str,
    email: str,
    severity: str,
    message: str,
    repo_path: Path | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "check_id": check_id,
        "source": source,
        "email": email,
        "domain": _email_domain(email),
        "severity": severity,
        "message": message,
    }
    if repo_path is not None:
        data["repo_path"] = str(repo_path)
    if extra:
        data.update(extra)
    return data


def _check_email(
    *,
    email: str,
    source: str,
    repo_path: Path | None,
    forbidden_domains: set[str],
    forbidden_patterns: list[re.Pattern[str]],
    allowed_domains: set[str],
    extra: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    domain = _email_domain(email)
    if not domain:
        return findings

    if domain in forbidden_domains or any(p.search(email) for p in forbidden_patterns):
        findings.append(
            _finding(
                check_id="forbidden_git_email",
                source=source,
                email=email,
                severity="error",
                message=f"Git identity uses forbidden email domain: {domain}",
                repo_path=repo_path,
                extra=extra,
            )
        )
    elif allowed_domains and domain not in allowed_domains:
        findings.append(
            _finding(
                check_id="unexpected_git_email_domain",
                source=source,
                email=email,
                severity="warning",
                message=f"Git identity domain is outside the allowlist: {domain}",
                repo_path=repo_path,
                extra=extra,
            )
        )
    return findings


def _refs_containing_commit(repo: Path, commit: str) -> list[str]:
    value = _git_output(
        ["git", "-C", str(repo), "for-each-ref", "--contains", commit, "--format=%(refname)"],
        timeout=15,
    )
    if not value:
        return []
    return sorted(line for line in value.splitlines() if line.strip())


def _history_email_samples(value: str) -> dict[str, str]:
    samples: dict[str, str] = {}
    for line in value.splitlines():
        parts = line.split("\0")
        if len(parts) != 3:
            continue
        commit, author_email, committer_email = parts
        for email in _extract_emails(f"{author_email} {committer_email}"):
            samples.setdefault(email, commit)
    return samples


def audit_git_identity(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    forbidden_email_domains: list[str] | None = None,
    forbidden_email_patterns: list[str] | None = None,
    allowed_email_domains: list[str] | None = None,
    check_global_config: bool = True,
    check_repo_config: bool = True,
    check_environment: bool = True,
    check_history: bool = False,
    max_history_commits: int = 50_000,
    env: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit git identity settings and optional commit metadata."""
    root = dev_root if dev_root is not None else _default_dev_root()
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    repos = sorted(iter_git_repos(root, max_depth=max_depth, exclude_globs=globs))
    environment = env if env is not None else os.environ

    forbidden_domains = {_normalize_domain(d) for d in (forbidden_email_domains or []) if d.strip()}
    allowed_domains = {_normalize_domain(d) for d in (allowed_email_domains or []) if d.strip()}
    compiled_patterns: list[re.Pattern[str]] = []
    errors: list[str] = []
    for pattern in forbidden_email_patterns or []:
        if not pattern.strip():
            continue
        try:
            compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            errors.append(f"invalid forbidden_email_pattern {pattern!r}: {exc}")

    findings: list[dict[str, Any]] = []

    if check_global_config:
        value = _git_output(["git", "config", "--global", "--get", "user.email"])
        if value:
            for email in _extract_emails(value):
                findings.extend(
                    _check_email(
                        email=email,
                        source="git config --global user.email",
                        repo_path=None,
                        forbidden_domains=forbidden_domains,
                        forbidden_patterns=compiled_patterns,
                        allowed_domains=allowed_domains,
                        extra=None,
                    )
                )

    if check_environment:
        for key in ("GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"):
            value = environment.get(key, "")
            for email in _extract_emails(value):
                findings.extend(
                    _check_email(
                        email=email,
                        source=key,
                        repo_path=None,
                        forbidden_domains=forbidden_domains,
                        forbidden_patterns=compiled_patterns,
                        allowed_domains=allowed_domains,
                        extra=None,
                    )
                )

    repo_entries: list[dict[str, Any]] = []
    history_limit = max(0, int(max_history_commits))
    for repo in repos:
        repo_findings: list[dict[str, Any]] = []
        if check_repo_config:
            value = _git_output(
                ["git", "-C", str(repo), "config", "--local", "--get", "user.email"]
            )
            if value:
                for email in _extract_emails(value):
                    repo_findings.extend(
                        _check_email(
                            email=email,
                            source="git config --local user.email",
                            repo_path=repo,
                            forbidden_domains=forbidden_domains,
                            forbidden_patterns=compiled_patterns,
                            allowed_domains=allowed_domains,
                            extra=None,
                        )
                    )

        if check_history:
            cmd = ["git", "-C", str(repo), "log", "--all", "--format=%H%x00%aE%x00%cE"]
            if history_limit:
                cmd.insert(4, f"--max-count={history_limit}")
            value = _git_output(cmd, timeout=60)
            if value is None:
                errors.append(f"failed to read git history for {repo}")
            else:
                samples = _history_email_samples(value)
                for email, commit in samples.items():
                    containing_refs = _refs_containing_commit(repo, commit)
                    repo_findings.extend(
                        _check_email(
                            email=email,
                            source="git log --all author/committer email",
                            repo_path=repo,
                            forbidden_domains=forbidden_domains,
                            forbidden_patterns=compiled_patterns,
                            allowed_domains=allowed_domains,
                            extra={
                                "sample_commit": commit,
                                "containing_refs": containing_refs[:25],
                            },
                        )
                    )

        if repo_findings:
            findings.extend(repo_findings)
            repo_entries.append({"repo_path": str(repo), "findings": repo_findings})

    global_findings = [f for f in findings if "repo_path" not in f]
    history_findings = [f for f in findings if f["source"].startswith("git log")]
    repo_config_findings = [f for f in findings if f["source"] == "git config --local user.email"]
    env_findings = [f for f in findings if f["source"].startswith("GIT_")]

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
            "forbidden_email_domains": sorted(forbidden_domains),
            "forbidden_email_patterns": forbidden_email_patterns or [],
            "allowed_email_domains": sorted(allowed_domains),
            "check_global_config": check_global_config,
            "check_repo_config": check_repo_config,
            "check_environment": check_environment,
            "check_history": check_history,
            "max_history_commits": history_limit,
        },
        "summary": {
            "total_findings": len(findings),
            "global_findings": len(global_findings),
            "environment_findings": len(env_findings),
            "repo_config_findings": len(repo_config_findings),
            "history_findings": len(history_findings),
            "repos_with_findings": len(repo_entries),
            "errors_count": len(errors),
        },
        "findings": findings[:500],
        "repos": repo_entries[:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
