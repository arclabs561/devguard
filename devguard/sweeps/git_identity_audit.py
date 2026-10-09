"""Git identity audit sweep.

Checks configured git author emails and, optionally, commit metadata against
the email policy supplied by the sweep spec.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

from dotenv import dotenv_values

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


def _email_hash(email: str) -> str:
    return "sha256:" + sha256(email.lower().encode("utf-8")).hexdigest()[:16]


def _extract_emails(value: str) -> list[str]:
    return [m.group("email").lower() for m in _EMAIL_RE.finditer(value or "")]


def _split_env_values(value: str, *, split_whitespace: bool) -> list[str]:
    if split_whitespace:
        return [item for item in re.split(r"[\s,]+", value) if item]
    return [item.strip() for item in re.split(r"[\n,]+", value) if item.strip()]


def _env_values(
    environment: Mapping[str, str],
    env_var: str | None,
    *,
    split_whitespace: bool = True,
) -> list[str]:
    if not env_var:
        return []
    return _split_env_values(environment.get(env_var, ""), split_whitespace=split_whitespace)


def _environment_with_dotenv() -> dict[str, str]:
    dotenv_env: dict[str, str] = {}
    for path in (Path("../.env"), Path(".env")):
        if not path.exists():
            continue
        for key, value in dotenv_values(path).items():
            if value is not None:
                dotenv_env[key] = value
    return {**dotenv_env, **os.environ}


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
    redact_email: bool = True,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "check_id": check_id,
        "source": source,
        "email": "<redacted>" if redact_email else email,
        "domain": "<redacted>" if redact_email else _email_domain(email),
        "email_hash": _email_hash(email),
        "severity": severity,
        "message": message,
    }
    if repo_path is not None:
        data["repo_path"] = str(repo_path)
    if extra:
        data.update(extra)
    return data


# Consumer mail providers: an address here is personal, never an employer's.
PERSONAL_EMAIL_DOMAINS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "yahoo.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "fastmail.com",
        "fastmail.fm",
        "hey.com",
        "zoho.com",
        "aol.com",
        "gmx.com",
        "gmx.de",
        "mail.com",
        "duck.com",
        "tutanota.com",
        "qq.com",
        "163.com",
    }
)
# RFC 2606/6761 reserved names used by tests and docs.
_RESERVED_DOMAIN_RE = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|test|example|invalid|localhost)$"
)


def _is_exempt(email: str) -> bool:
    """GitHub noreply addresses and bots are never a person's work email."""
    e = email.lower()
    return (
        _email_domain(e).endswith("users.noreply.github.com")
        or e == "noreply@github.com"
        or "[bot]@" in e
    )


def _check_email(
    *,
    email: str,
    source: str,
    repo_path: Path | None,
    forbidden_domains: set[str],
    forbidden_patterns: list[re.Pattern[str]],
    allowed_domains: set[str],
    redact_emails: bool,
    extra: dict[str, Any] | None = None,
    allowed_emails: frozenset[str] = frozenset(),
    flag_employer_domains: bool = False,
    own_domains: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    domain = _email_domain(email)
    if not domain:
        return findings
    if email.lower() in allowed_emails or (_is_exempt(email) and domain not in forbidden_domains):
        return findings

    def warn(check_id: str, message: str) -> None:
        findings.append(
            _finding(
                check_id=check_id,
                source=source,
                email=email,
                severity="warning",
                message=message,
                repo_path=repo_path,
                redact_email=redact_emails,
                extra=extra,
            )
        )

    if domain in forbidden_domains or any(p.search(email) for p in forbidden_patterns):
        findings.append(
            _finding(
                check_id="forbidden_git_email",
                source=source,
                email=email,
                severity="error",
                message="Git identity matches forbidden email policy",
                repo_path=repo_path,
                redact_email=redact_emails,
                extra=extra,
            )
        )
    elif allowed_domains and domain not in allowed_domains:
        warn("unexpected_git_email_domain", "Git identity domain is outside the allowlist")
    elif allowed_emails and not allowed_domains:
        warn("unexpected_git_email", "Git identity email is not one of the allowed addresses")
    elif (
        flag_employer_domains
        and domain not in PERSONAL_EMAIL_DOMAINS
        and domain not in own_domains
        and not _RESERVED_DOMAIN_RE.search(domain)  # test fixtures, docs
    ):
        warn(
            "possible_employer_email",
            "Git identity uses a non-personal domain, possibly an employer's; add the "
            "address to allowed_emails if it is yours",
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


def _history_email_samples(value: str) -> dict[str, tuple[str, set[str]]]:
    """Map each author/committer email to (first commit seen, names used with it).

    Expects `git log --format=%H%x00%aN%x00%aE%x00%cN%x00%cE`.
    """
    samples: dict[str, tuple[str, set[str]]] = {}
    for line in value.splitlines():
        parts = line.split("\0")
        if len(parts) != 5:
            continue
        commit, author_name, author_email, committer_name, committer_email = parts
        for name, raw in ((author_name, author_email), (committer_name, committer_email)):
            for email in _extract_emails(raw):
                _, names = samples.setdefault(email, (commit, set()))
                names.add(name.strip().lower())
    return samples


def audit_git_identity(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    forbidden_email_domains: list[str] | None = None,
    forbidden_email_domains_env: str | None = None,
    forbidden_email_patterns: list[str] | None = None,
    forbidden_email_patterns_env: str | None = None,
    allowed_email_domains: list[str] | None = None,
    allowed_email_domains_env: str | None = None,
    check_global_config: bool = True,
    check_repo_config: bool = True,
    check_environment: bool = True,
    check_history: bool = False,
    redact_emails: bool = True,
    max_history_commits: int = 50_000,
    env: Mapping[str, str] | None = None,
    allowed_emails: list[str] | None = None,
    allowed_emails_env: str | None = None,
    flag_employer_domains: bool = False,
) -> tuple[dict[str, Any], list[str]]:
    """Audit git identity settings and optional commit metadata."""
    root = dev_root if dev_root is not None else _default_dev_root()
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    repos = sorted(iter_git_repos(root, max_depth=max_depth, exclude_globs=globs))
    environment = env if env is not None else _environment_with_dotenv()

    configured_forbidden_domains = [
        *(forbidden_email_domains or []),
        *_env_values(environment, forbidden_email_domains_env),
    ]
    configured_forbidden_patterns = [
        *(forbidden_email_patterns or []),
        *_env_values(environment, forbidden_email_patterns_env, split_whitespace=False),
    ]
    configured_allowed_domains = [
        *(allowed_email_domains or []),
        *_env_values(environment, allowed_email_domains_env),
    ]

    forbidden_domains = {_normalize_domain(d) for d in configured_forbidden_domains if d.strip()}
    allowed_domains = {_normalize_domain(d) for d in configured_allowed_domains if d.strip()}
    compiled_patterns: list[re.Pattern[str]] = []
    errors: list[str] = []
    for pattern in configured_forbidden_patterns:
        if not pattern.strip():
            continue
        try:
            compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
        except re.error as exc:
            errors.append(f"invalid forbidden_email_pattern: {exc}")

    findings: list[dict[str, Any]] = []
    allowed_email_set = frozenset(
        e.strip().lower()
        for e in [*(allowed_emails or []), *_env_values(environment, allowed_emails_env)]
        if e.strip()
    )
    global_email = _git_output(["git", "config", "--global", "--get", "user.email"]) or ""
    global_name = _git_output(["git", "config", "--global", "--get", "user.name"]) or ""
    # The employer heuristic applies only when no explicit policy says otherwise.
    heuristic = flag_employer_domains and not (allowed_domains or allowed_email_set)
    policy: dict[str, Any] = {
        "allowed_emails": allowed_email_set,
        "flag_employer_domains": heuristic,
        # The user's own configured address and allowlisted addresses define "personal".
        "own_domains": frozenset(
            _email_domain(e) for e in [*_extract_emails(global_email), *allowed_email_set]
        ),
    }

    if check_global_config:
        for email in _extract_emails(global_email):
            findings.extend(
                _check_email(
                    email=email,
                    source="git config --global user.email",
                    repo_path=None,
                    forbidden_domains=forbidden_domains,
                    forbidden_patterns=compiled_patterns,
                    allowed_domains=allowed_domains,
                    redact_emails=redact_emails,
                    **policy,
                    extra=None,
                )
            )

    value: str | None
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
                        redact_emails=redact_emails,
                        **policy,
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
                            redact_emails=redact_emails,
                            **policy,
                            extra=None,
                        )
                    )

        if check_history:
            cmd = [
                "git",
                "-C",
                str(repo),
                "log",
                "--all",
                "--format=%H%x00%aN%x00%aE%x00%cN%x00%cE",
            ]
            if history_limit:
                cmd.insert(4, f"--max-count={history_limit}")
            value = _git_output(cmd, timeout=60)
            if value is None:
                errors.append(f"failed to read git history for {repo}")
            else:
                samples = _history_email_samples(value)
                # The employer heuristic is about the user's own identity: names
                # from global user.name or used with one of the user's addresses.
                # Other contributors (e.g. upstream authors in a fork) are left to
                # explicit policy.
                own_emails = {*_extract_emails(global_email), *allowed_email_set}
                user_names = {n for n in (global_name.strip().lower(),) if n}
                for email, (_, names) in samples.items():
                    if email.lower() in own_emails:
                        user_names |= names
                for email, (commit, names) in samples.items():
                    # With no known identity, every commit is a candidate.
                    if policy["flag_employer_domains"] and user_names and not (names & user_names):
                        continue_policy: dict[str, Any] = {**policy, "flag_employer_domains": False}
                    else:
                        continue_policy = policy
                    containing_refs = _refs_containing_commit(repo, commit)
                    repo_findings.extend(
                        _check_email(
                            email=email,
                            source="git log --all author/committer email",
                            repo_path=repo,
                            forbidden_domains=forbidden_domains,
                            forbidden_patterns=compiled_patterns,
                            allowed_domains=allowed_domains,
                            redact_emails=redact_emails,
                            **continue_policy,
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
            "forbidden_email_domains_count": len(forbidden_domains),
            "forbidden_email_patterns_count": len(compiled_patterns),
            "allowed_email_domains_count": len(allowed_domains),
            "forbidden_email_domains_env": forbidden_email_domains_env,
            "forbidden_email_patterns_env": forbidden_email_patterns_env,
            "allowed_email_domains_env": allowed_email_domains_env,
            "check_global_config": check_global_config,
            "check_repo_config": check_repo_config,
            "check_environment": check_environment,
            "check_history": check_history,
            "redact_emails": redact_emails,
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
