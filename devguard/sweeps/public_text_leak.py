"""Public text leak sweep: coordination or private context in public repo text.

Scans recent commit messages in local clones of public GitHub repos and,
optionally, PR and issue bodies and comments fetched with `gh`. Tracked file
content is covered separately by repo_hygiene's public text policy.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from devguard.sweeps._common import iter_git_repos, utc_now

DEFAULT_PATTERNS: list[str] = [
    r"\bses_[A-Za-z0-9]{10,}",
    r"(?i)\bclaude[ _]session\b",
    r"(?i)\bopencode\b",
    r"(?i)\bsub-?agents?\b",
    # Bare "lane" is common in SIMD and CI wording; only the record form is flagged.
    r"(?i)\blane record\b",
    r"(?<![\w/-])claim-[a-z0-9]+(?:-[a-z0-9]+)+",
    r"(?i)\bhand-?off\b",
    r"(?i)\bpeer sessions?\b",
]

# Attribution forms that are allowed in public text.
_TRAILER_RE = re.compile(r"^\s*Claude-Session:\s*https://claude\.ai/code/session_[A-Za-z0-9]+\s*$")
_BARE_SESSION_URL_RE = re.compile(r"^\s*https://claude\.ai/code/session_[A-Za-z0-9]+\s*$")

_GITHUB_REMOTE_RE = re.compile(
    r"^(?:https?://(?:[^@/]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)"
    r"(?P<owner>[^/]+)/(?P<name>[^/]+?)(?:\.git)?/?$"
)


def parse_github_remote(url: str) -> tuple[str, str] | None:
    """Return (owner, name) for a GitHub remote URL, else None."""
    m = _GITHUB_REMOTE_RE.match(url.strip())
    return (m["owner"], m["name"]) if m else None


def _run(cmd: list[str], timeout_s: int, cwd: Path | None = None) -> str:
    proc = subprocess.run(
        cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout_s, check=False
    )
    if proc.returncode != 0:
        raise RuntimeError(f"{cmd[0]} {cmd[1]} failed (exit {proc.returncode})")
    return proc.stdout


def compile_patterns(
    patterns: list[str] | None, private_names: list[str]
) -> tuple[list[re.Pattern[str]], list[str]]:
    compiled: list[re.Pattern[str]] = []
    errors: list[str] = []
    for idx, raw in enumerate(DEFAULT_PATTERNS if patterns is None else patterns, 1):
        try:
            compiled.append(re.compile(raw))
        except re.error as exc:
            errors.append(f"patterns[{idx}] failed to compile: {exc}")
    for name in private_names:
        compiled.append(re.compile(r"(?i)(?<![\w-])" + re.escape(name) + r"(?![\w-])"))
    return compiled, errors


def strip_allowed(
    text: str, *, pr_body: bool = False, allow: list[re.Pattern[str]] | None = None
) -> str:
    """Drop allowed attribution lines before matching.

    The `Claude-Session:` trailer is allowed anywhere. A bare session URL is
    allowed only as the last non-empty line of a PR body. Lines matching any
    configured allow pattern are dropped too.
    """
    extra = allow or []
    lines = [
        ln
        for ln in text.splitlines()
        if not _TRAILER_RE.match(ln) and not any(a.search(ln) for a in extra)
    ]
    if pr_body:
        while lines and not lines[-1].strip():
            lines.pop()
        if lines and _BARE_SESSION_URL_RE.match(lines[-1]):
            lines.pop()
    return "\n".join(lines)


def _redact_excerpt(line: str, match: re.Match[str], width: int = 40) -> str:
    """Short excerpt around the match; the match itself keeps 3 characters."""
    start, end = match.span()
    token = match.group(0)
    shown = token[:3] + "*" * max(0, len(token) - 3) if len(token) > 6 else token
    before = line[max(0, start - width) : start]
    after = line[end : end + width]
    return " ".join(f"{before}{shown}{after}".split())


def scan_text(
    text: str,
    patterns: list[re.Pattern[str]],
    *,
    pr_body: bool = False,
    allow: list[re.Pattern[str]] | None = None,
) -> list[dict[str, str]]:
    """Return one hit per (line, pattern)."""
    hits: list[dict[str, str]] = []
    for line in strip_allowed(text, pr_body=pr_body, allow=allow).splitlines():
        for pat in patterns:
            m = pat.search(line)
            if m:
                hits.append({"pattern": pat.pattern, "excerpt": _redact_excerpt(line, m)})
    return hits


def _commits(repo: Path, since_days: int, limit: int, timeout_s: int) -> list[tuple[str, str]]:
    out = _run(
        [
            "git",
            "-C",
            str(repo),
            "log",
            "HEAD",
            "--remotes=origin",
            f"--since={since_days}.days",
            f"--max-count={limit}",
            "--format=%H%x00%B%x1e",
        ],
        timeout_s,
    )
    commits = []
    for rec in out.split("\x1e"):
        rec = rec.strip("\n")
        if "\x00" in rec:
            sha, body = rec.split("\x00", 1)
            commits.append((sha.strip(), body))
    return commits


def _gh_items(
    full_name: str, kind: str, since_days: int, limit: int, timeout_s: int
) -> list[dict[str, Any]]:
    since = (datetime.now(UTC) - timedelta(days=since_days)).date().isoformat()
    out = _run(
        [
            "gh",
            kind,
            "list",
            "-R",
            full_name,
            "--state",
            "all",
            "--search",
            f"updated:>={since}",
            "--limit",
            str(limit),
            "--json",
            "number,body,comments",
        ],
        timeout_s,
    )
    data = json.loads(out)
    return data if isinstance(data, list) else []


def _public_repos_for_owner(owner: str, timeout_s: int) -> set[str]:
    out = _run(
        [
            "gh",
            "repo",
            "list",
            owner,
            "--visibility",
            "public",
            "--limit",
            "1000",
            "--json",
            "nameWithOwner",
        ],
        timeout_s,
    )
    return {r["nameWithOwner"].lower() for r in json.loads(out) if r.get("nameWithOwner")}


def _origin(repo: Path) -> tuple[str, str] | None:
    try:
        url = _run(["git", "-C", str(repo), "remote", "get-url", "origin"], 10).strip()
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return None
    return parse_github_remote(url)


def _split_names(value: str) -> list[str]:
    return [v.strip() for v in re.split(r"[\n,]+", value) if v.strip()]


def scan_public_text_leaks(
    *,
    dev_root: Path,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    owners: list[str] | None = None,
    since_days: int = 30,
    max_commits_per_repo: int = 500,
    include_prs: bool = False,
    include_issues: bool = False,
    max_prs_per_repo: int = 50,
    patterns: list[str] | None = None,
    private_names: list[str] | None = None,
    private_names_env: str | None = None,
    allow_patterns: list[str] | None = None,
    timeout_s: int = 60,
    public_repo_lister: Any = None,
) -> tuple[dict[str, Any], list[str]]:
    """Return (report, errors). Errors include coverage gaps, never silently skipped."""
    names = list(private_names or [])
    if private_names_env:
        names.extend(_split_names(os.environ.get(private_names_env, "")))
    compiled, errors = compile_patterns(patterns, names)
    allow: list[re.Pattern[str]] = []
    for idx, raw in enumerate(allow_patterns or [], 1):
        try:
            allow.append(re.compile(raw))
        except re.error as exc:
            errors.append(f"allow_patterns[{idx}] failed to compile: {exc}")
    lister = public_repo_lister or _public_repos_for_owner

    globs = exclude_repo_globs or []
    local: dict[str, Path] = {}
    for repo in sorted(iter_git_repos(dev_root, max_depth=max_depth)):
        if any(fnmatch.fnmatch(str(repo), g) for g in globs):
            continue
        origin = _origin(repo)
        if origin:
            local.setdefault(f"{origin[0]}/{origin[1]}".lower(), repo)

    wanted_owners = sorted(
        {o.lower() for o in owners} if owners else {k.split("/")[0] for k in local}
    )
    public: set[str] = set()
    for owner in wanted_owners:
        try:
            public |= lister(owner, timeout_s)
        except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
            errors.append(f"visibility lookup failed for owner {owner}: {exc}")

    selected = {k: v for k, v in local.items() if k in public}
    repos_out: list[dict[str, Any]] = []
    total = 0
    for full_name, repo in sorted(selected.items()):
        findings: list[dict[str, Any]] = []

        def add(location: str, text: str, *, pr_body: bool = False) -> None:
            for hit in scan_text(text, compiled, pr_body=pr_body, allow=allow):
                findings.append(
                    {
                        "check": "public_text_leak",
                        "severity": "medium",
                        "location": location,
                        "pattern": hit["pattern"],
                        "excerpt": hit["excerpt"],
                        "message": f'{location}: /{hit["pattern"]}/ in "{hit["excerpt"]}"',
                    }
                )

        try:
            for sha, body in _commits(repo, since_days, max_commits_per_repo, timeout_s):
                add(f"commit {sha[:12]}", body)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{full_name}: commit scan failed: {exc}")

        for kind, enabled in (("pr", include_prs), ("issue", include_issues)):
            if not enabled:
                continue
            try:
                items = _gh_items(full_name, kind, since_days, max_prs_per_repo, timeout_s)
            except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
                errors.append(f"{full_name}: {kind} scan failed: {exc}")
                continue
            for item in items:
                num = item.get("number")
                add(f"{kind} #{num}", item.get("body") or "", pr_body=kind == "pr")
                for c in item.get("comments") or []:
                    cid = c.get("id") or c.get("url") or "?"
                    add(f"{kind} #{num} comment {cid}", c.get("body") or "")

        total += len(findings)
        if findings:
            repos_out.append(
                {"repo_path": str(repo), "repo": full_name, "findings": findings[:200]}
            )

    repos_out.sort(key=lambda r: (-len(r["findings"]), r["repo"]))
    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "scope": {
            "dev_root": str(dev_root),
            "owners": wanted_owners,
            "local_github_repos": len(local),
            "public_repos_scanned": len(selected),
            "since_days": since_days,
            "include_prs": include_prs,
            "include_issues": include_issues,
            "patterns": len(compiled),
        },
        "summary": {
            "repos_with_findings": len(repos_out),
            "total_findings": total,
            "errors_count": len(errors),
        },
        "repos": repos_out,
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
