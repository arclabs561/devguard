from __future__ import annotations

import fnmatch
import json
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _run(cmd: list[str], timeout_s: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        env=os.environ.copy(),
    )


def _match_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def _list_public_repos(owner: str, include_forks: bool, timeout_s: int = 30) -> tuple[list[str], list[str]]:
    """List public repos for a GitHub owner via `gh repo list`."""
    errors: list[str] = []
    cmd = [
        "gh",
        "repo",
        "list",
        owner,
        "--visibility",
        "public",
        "--limit",
        "1000",
        "--json",
        "nameWithOwner,isFork",
    ]
    try:
        res = _run(cmd, timeout_s=timeout_s)
    except Exception as e:
        return [], [f"gh repo list failed for {owner}: {e}"]

    if res.returncode != 0:
        errors.append(f"gh repo list failed for {owner}: exit={res.returncode} stderr={res.stderr.strip()[:300]}")
        return [], errors

    try:
        data = json.loads(res.stdout)
    except Exception as e:
        errors.append(f"gh repo list JSON parse failed for {owner}: {e}")
        return [], errors

    repos: list[str] = []
    for r in data or []:
        try:
            full = r.get("nameWithOwner")
            is_fork = bool(r.get("isFork"))
            if not full:
                continue
            if is_fork and not include_forks:
                continue
            repos.append(full)
        except Exception:
            continue

    return sorted(set(repos)), errors


@dataclass
class RedactedFinding:
    repo: str
    type: str
    verified: bool | None
    file: str | None
    commit: str | None
    line: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo": self.repo,
            "type": self.type,
            "verified": self.verified,
            "file": self.file,
            "commit": self.commit,
            "line": self.line,
        }


def _extract_finding(obj: dict[str, Any], repo: str) -> RedactedFinding | None:
    """Extract a safe/redacted finding from TruffleHog JSON."""
    if not isinstance(obj, dict):
        return None

    detector = obj.get("DetectorName") or obj.get("Detector") or obj.get("DetectorType") or "unknown"
    verified = obj.get("Verified")
    if verified is not None:
        verified = bool(verified)

    file_path = None
    commit = None
    line = None

    # Common v3 layout: SourceMetadata.Data.Git
    sm = obj.get("SourceMetadata") or {}
    data = sm.get("Data") if isinstance(sm, dict) else {}
    git = data.get("Git") if isinstance(data, dict) else {}
    if isinstance(git, dict):
        file_path = git.get("file") or git.get("path")
        commit = git.get("commit")
        line_val = git.get("line")
        if isinstance(line_val, int):
            line = line_val
        elif isinstance(line_val, str):
            try:
                line = int(line_val)
            except Exception:
                line = None

    # Fallbacks (older layouts)
    if file_path is None and isinstance(obj.get("File"), str):
        file_path = obj.get("File")
    if commit is None and isinstance(obj.get("Commit"), str):
        commit = obj.get("Commit")

    if isinstance(commit, str) and len(commit) > 8:
        commit = commit[:8]

    return RedactedFinding(
        repo=repo,
        type=str(detector),
        verified=verified,
        file=str(file_path) if file_path is not None else None,
        commit=str(commit) if commit is not None else None,
        line=line,
    )


def scan_public_github_repos(
    *,
    owners: list[str],
    include_repos: list[str],
    exclude_repos: list[str],
    include_forks: bool,
    max_repos: int,
    timeout_s: int = 900,
) -> tuple[dict[str, Any], list[str]]:
    """Scan public repos for the given owners and return a redacted report."""
    errors: list[str] = []

    # 1) Discover repos.
    repos: list[str] = []
    for owner in owners:
        rs, es = _list_public_repos(owner, include_forks=include_forks)
        repos.extend(rs)
        errors.extend(es)

    repos = sorted(set(repos))
    if include_repos:
        repos = [r for r in repos if _match_any(r, include_repos)]
    if exclude_repos:
        repos = [r for r in repos if not _match_any(r, exclude_repos)]
    if max_repos and len(repos) > max_repos:
        repos = repos[:max_repos]

    # 2) Run TruffleHog github scan for explicit repos.
    token = os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN")
    if not token:
        errors.append("Missing GITHUB_TOKEN (or GH_TOKEN) for trufflehog github scan.")

    findings: list[RedactedFinding] = []
    if repos and token:
        cmd = [
            "trufflehog",
            "github",
            "--token",
            token,
            "--json",
            "--no-update",
            "--results",
            "verified,unverified,unknown",
            "--filter-unverified",
        ]
        for r in repos:
            cmd.extend(["--repo", f"https://github.com/{r}"])

        try:
            res = _run(cmd, timeout_s=timeout_s)
        except Exception as e:
            errors.append(f"trufflehog github failed: {e}")
            res = None

        if res is not None and res.returncode not in (0, 183):
            # Trufflehog uses 183 when findings exist (with --fail),
            # but we don't use --fail; treat non-zero as scan error.
            errors.append(
                f"trufflehog github non-zero exit={res.returncode} stderr={res.stderr.strip()[:400]}"
            )

        if res is not None and res.stdout:
            for line in res.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                repo = obj.get("SourceMetadata", {}).get("Data", {}).get("Git", {}).get("repository", None)
                repo = repo if isinstance(repo, str) and repo else None
                # If trufflehog doesn't include repository, fall back to "unknown" bucket.
                # (We still keep the scan scoped by passing explicit --repo values.)
                repo_name = repo or "unknown"
                f = _extract_finding(obj, repo=repo_name)
                if f:
                    findings.append(f)

    # Summaries
    verified = sum(1 for f in findings if f.verified is True)
    unverified = sum(1 for f in findings if f.verified is False)
    unknown = sum(1 for f in findings if f.verified is None)

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "owners": owners,
            "repos_scanned": repos,
            "repos_scanned_count": len(repos),
            "max_repos": max_repos,
            "include_repos": include_repos,
            "exclude_repos": exclude_repos,
            "include_forks": include_forks,
        },
        "engine": {
            "name": "trufflehog",
            "mode": "github",
            "results": "verified,unverified,unknown",
        },
        # Redacted: no secret values/snippets included.
        "findings": [f.to_dict() for f in findings[:500]],
        "summary": {
            "findings_total": len(findings),
            "verified": verified,
            "unverified": unverified,
            "unknown": unknown,
        },
        "errors": errors,
    }

    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
