from __future__ import annotations

import fnmatch
import json
import logging
import os
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

logging.getLogger("httpx").setLevel(logging.WARNING)


_LOCK_FILE_BASENAMES: frozenset[str] = frozenset({
    "uv.lock", "Cargo.lock", "package-lock.json", "pnpm-lock.yaml",
    "yarn.lock", "poetry.lock", "Gemfile.lock", "composer.lock",
    "Pipfile.lock", "requirements.lock",
})


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


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


def _list_public_repos_via_api(owner: str, include_forks: bool, token: str | None) -> tuple[list[str], list[str]]:
    """List public repos via GitHub REST API (token-only; no gh required)."""
    errors: list[str] = []
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Try orgs endpoint first; fall back to users endpoint.
    endpoints = [
        f"https://api.github.com/orgs/{owner}/repos",
        f"https://api.github.com/users/{owner}/repos",
    ]

    repos: list[str] = []
    with httpx.Client(timeout=20.0, headers=headers) as client:
        for base_url in endpoints:
            repos.clear()
            try:
                page = 1
                while True:
                    resp = client.get(
                        base_url,
                        params={
                            "type": "public",
                            "per_page": 100,
                            "page": page,
                            "sort": "full_name",
                            "direction": "asc",
                        },
                    )
                    # If org endpoint doesn't match, it commonly returns 404.
                    if resp.status_code == 404 and "orgs/" in base_url:
                        raise RuntimeError("not an org")
                    resp.raise_for_status()
                    data = resp.json()
                    if not isinstance(data, list) or not data:
                        break
                    for r in data:
                        if not isinstance(r, dict):
                            continue
                        full = r.get("full_name")
                        if not isinstance(full, str) or not full:
                            continue
                        if r.get("fork") and not include_forks:
                            continue
                        repos.append(full)
                    if len(data) < 100:
                        break
                    page += 1
                # success for this endpoint
                return sorted(set(repos)), errors
            except Exception as e:
                # try next endpoint
                errors.append(f"github api list repos failed for {owner} via {base_url}: {e}")
                continue

    return [], errors


def _get_github_token() -> tuple[str | None, list[str]]:
    """Best-effort token retrieval.

    Priority:
    1) GITHUB_TOKEN env
    2) GH_TOKEN env
    3) `gh auth token` (requires prior gh login; non-interactive)
    """
    errors: list[str] = []
    token = (os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN") or "").strip()
    if token:
        return token, errors

    # Best effort: derive from gh if logged in.
    try:
        if subprocess.run(
            ["gh", "auth", "status"],
            capture_output=True,
            text=True,
            timeout=5,
            env=os.environ.copy(),
        ).returncode == 0:
            res = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=10,
                env=os.environ.copy(),
            )
            t = (res.stdout or "").strip()
            if t:
                return t, errors
    except FileNotFoundError:
        # gh not installed
        pass
    except Exception as e:
        errors.append(f"gh auth token failed: {e}")

    return None, errors


def _github_api_get_json(url: str, token: str | None) -> tuple[Any | None, str | None]:
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with httpx.Client(timeout=20.0, headers=headers) as client:
            r = client.get(url)
            r.raise_for_status()
            return r.json(), None
    except Exception as e:
        return None, str(e)


def _expand_owners(owners: list[str], token: str | None) -> tuple[list[str], list[str]]:
    """Expand sentinel owners into real owners.

    Supported sentinels:
    - "@me": current authenticated user
    - "@orgs": all orgs for current user
    - "@all": @me + @orgs
    """
    errs: list[str] = []

    requested = [o.strip() for o in owners if o and o.strip()]
    if not requested:
        requested = ["@me"]

    want_me = "@all" in requested or "@me" in requested
    want_orgs = "@all" in requested or "@orgs" in requested

    # Keep explicit owners too (anything not a sentinel).
    expanded: list[str] = [o for o in requested if not o.startswith("@")]

    # If a token isn't available, don't even try to resolve @me/@orgs via API.
    # This avoids noisy 401s and makes the failure mode clearer.
    if (want_me or want_orgs) and not token:
        errs.append("cannot expand @me/@orgs without a GitHub token (set GITHUB_TOKEN or GH_TOKEN)")
        return sorted(set(expanded)), errs

    me_login: str | None = None
    if want_me or want_orgs:
        user_obj, err = _github_api_get_json("https://api.github.com/user", token)
        if isinstance(user_obj, dict) and isinstance(user_obj.get("login"), str):
            me_login = user_obj["login"]
        else:
            if err:
                errs.append(f"failed to resolve @me via GitHub API: {err}")

    if want_me and me_login:
        expanded.append(me_login)

    if want_orgs and me_login:
        # /user/orgs returns orgs for the authenticated user.
        orgs = []
        page = 1
        with httpx.Client(
            timeout=20.0,
            headers={
                "Accept": "application/vnd.github+json",
                **({"Authorization": f"Bearer {token}"} if token else {}),
            },
        ) as client:
            while True:
                try:
                    r = client.get("https://api.github.com/user/orgs", params={"per_page": 100, "page": page})
                    r.raise_for_status()
                    data = r.json()
                    if not isinstance(data, list) or not data:
                        break
                    for o in data:
                        if isinstance(o, dict) and isinstance(o.get("login"), str):
                            orgs.append(o["login"])
                    if len(data) < 100:
                        break
                    page += 1
                except Exception as e:
                    errs.append(f"failed to resolve @orgs via GitHub API: {e}")
                    break

        expanded.extend(orgs)

    # Dedup, preserve readability.
    expanded = sorted(set(expanded))
    return expanded, errs


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
    engines: list[str] | None = None,
    timeout_s: int = 900,
    max_concurrency: int = 4,
) -> tuple[dict[str, Any], list[str]]:
    """Scan public repos for the given owners and return a redacted report."""
    errors: list[str] = []

    # 0) Token + owner expansion.
    repos: list[str] = []
    discovery_errors: list[str] = []
    discovery_method = "gh"

    token, token_errors = _get_github_token()
    errors.extend(token_errors)

    expanded_owners, owner_errs = _expand_owners(owners, token)
    discovery_errors.extend(owner_errs)

    # 1) Discover repos.
    for owner in expanded_owners:
        # Prefer `gh` if available because it respects local auth and avoids rate limits,
        # but fall back to token-only GitHub API when `gh` isn't usable.
        rs, es = _list_public_repos(owner, include_forks=include_forks)
        if rs:
            repos.extend(rs)
        else:
            discovery_method = "github_api"
            rs2, es2 = _list_public_repos_via_api(owner, include_forks=include_forks, token=token)
            repos.extend(rs2)
            discovery_errors.extend(es + es2)

    repos = sorted(set(repos))
    if include_repos:
        repos = [r for r in repos if _match_any(r, include_repos)]
    if exclude_repos:
        repos = [r for r in repos if not _match_any(r, exclude_repos)]
    if max_repos and len(repos) > max_repos:
        repos = repos[:max_repos]

    requested_engines = [e.strip().lower() for e in (engines or ["trufflehog"]) if e and e.strip()]
    # Dedup while preserving order.
    seen: set[str] = set()
    requested_engines = [e for e in requested_engines if not (e in seen or seen.add(e))]
    supported = {"trufflehog", "kingfisher"}
    unknown = [e for e in requested_engines if e not in supported]
    if unknown:
        errors.append(f"Unknown engines: {unknown}. Supported: {sorted(supported)}")
        requested_engines = [e for e in requested_engines if e in supported]
    if not requested_engines:
        requested_engines = ["trufflehog"]

    # Clamp concurrency to a safe range.
    try:
        max_concurrency = int(max_concurrency)
    except Exception:
        max_concurrency = 4
    max_concurrency = max(1, min(max_concurrency, 12))

    # 2) Run scan engines per repo.
    if not token and any(e in ("trufflehog", "kingfisher") for e in requested_engines):
        errors.append(
            "Missing GitHub token for public GitHub scans. "
            "Set GITHUB_TOKEN/GH_TOKEN or run `gh auth login` then rerun."
        )

    findings: list[RedactedFinding] = []
    engine_summaries: dict[str, Any] = {}

    if repos and token:
        # Avoid passing tokens on argv (shows up in process lists).
        env = os.environ.copy()
        env["GITHUB_TOKEN"] = token
        env["KF_GITHUB_TOKEN"] = token

        # Interpret `timeout_s` as a *per-repo* timeout upper bound (not total),
        # but clamp it so CI doesn't get stuck.
        per_repo_timeout = max(30, min(int(timeout_s), 600))

        def _scan_one_repo_trufflehog(repo_full: str) -> tuple[str, list[RedactedFinding], list[str]]:
            repo_errors: list[str] = []
            repo_findings: list[RedactedFinding] = []

            cmd = [
                "trufflehog",
                "github",
                "--json",
                "--no-update",
                "--results",
                "verified,unverified,unknown",
                "--filter-unverified",
                "--no-fail-on-scan-errors",
                "--repo",
                f"https://github.com/{repo_full}",
            ]
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=per_repo_timeout,
                    env=env,
                )
            except Exception as e:
                return repo_full, [], [f"trufflehog github failed for {repo_full}: {e}"]

            # Some orgs enforce SAML SSO on tokens, which can block even public repo API
            # access. For public repos, retry once without auth (best-effort).
            if res.returncode not in (0, 183):
                stderr = (res.stderr or "").strip()
                if "Resource protected by organization SAML" in stderr:
                    env_no_token = os.environ.copy()
                    env_no_token.pop("GITHUB_TOKEN", None)
                    retry_cmd = [
                        "trufflehog",
                        "github",
                        "--json",
                        "--no-update",
                        "--results",
                        "verified,unverified,unknown",
                        "--filter-unverified",
                        "--no-fail-on-scan-errors",
                        "--no-verification",
                        "--repo",
                        f"https://github.com/{repo_full}",
                    ]
                    try:
                        retry = subprocess.run(
                            retry_cmd,
                            capture_output=True,
                            text=True,
                            timeout=per_repo_timeout,
                            env=env_no_token,
                        )
                        if retry.returncode in (0, 183):
                            res = retry
                        else:
                            repo_errors.append(
                                f"trufflehog github scan error for {repo_full}: exit={res.returncode} "
                                f"stderr={stderr[:600]}"
                            )
                    except Exception:
                        repo_errors.append(
                            f"trufflehog github scan error for {repo_full}: exit={res.returncode} "
                            f"stderr={stderr[:600]}"
                        )
                else:
                    repo_errors.append(
                        f"trufflehog github scan error for {repo_full}: exit={res.returncode} "
                        f"stderr={stderr[:600]}"
                    )

            if res.stdout:
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    repo_name = (
                        obj.get("SourceMetadata", {})
                        .get("Data", {})
                        .get("Git", {})
                        .get("repository", None)
                    )
                    repo_name = repo_name if isinstance(repo_name, str) and repo_name else repo_full
                    f = _extract_finding(obj, repo=repo_name)
                    if f:
                        # Skip lock file false positives (dependency hashes).
                        if f.file and Path(f.file).name in _LOCK_FILE_BASENAMES:
                            continue
                        # Encode engine in the type for now to keep output schema stable.
                        f.type = f"trufflehog:{f.type}"
                        repo_findings.append(f)

            return repo_full, repo_findings, repo_errors

        def _scan_one_repo_kingfisher(repo_full: str) -> tuple[str, list[RedactedFinding], list[str]]:
            repo_errors: list[str] = []
            repo_findings: list[RedactedFinding] = []

            # Use --git-url so we can keep our own repo enumeration/filtering.
            # Use --redact so output never includes plaintext secrets.
            cmd = [
                "kingfisher",
                "scan",
                "--git-url",
                f"https://github.com/{repo_full}.git",
                "--format",
                "jsonl",
                "--redact",
                "--no-update-check",
                "--no-validate",
            ]
            try:
                res = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=per_repo_timeout,
                    env=env,
                )
            except Exception as e:
                return repo_full, [], [f"kingfisher failed for {repo_full}: {e}"]

            # Kingfisher writes logs + JSONL to stdout. Parse JSON objects from lines.
            summary_obj: dict[str, Any] | None = None
            for line in (res.stdout or "").splitlines():
                s = line.strip()
                if not s.startswith("{"):
                    continue
                try:
                    obj = json.loads(s)
                except Exception:
                    continue
                if isinstance(obj, dict) and "scan_date" in obj and "findings" in obj:
                    summary_obj = obj
                    continue
                if not isinstance(obj, dict):
                    continue
                rule = obj.get("rule") or obj.get("rule_id") or obj.get("id")
                path = obj.get("path") or obj.get("file") or obj.get("Path") or obj.get("File")
                # Require at least a rule or path to distinguish findings from log lines.
                if not rule and not path:
                    continue
                rule = rule or "kingfisher"
                line_val = obj.get("line") or obj.get("line_num") or obj.get("line_number")
                commit = obj.get("commit") or obj.get("Commit")
                try:
                    line_i = int(line_val) if line_val is not None else None
                except Exception:
                    line_i = None
                if isinstance(commit, str) and len(commit) > 8:
                    commit = commit[:8]
                file_str = str(path) if path is not None else None
                # Skip lock file false positives.
                if file_str and Path(file_str).name in _LOCK_FILE_BASENAMES:
                    continue
                repo_findings.append(
                    RedactedFinding(
                        repo=repo_full,
                        type=f"kingfisher:{rule}",
                        verified=None,
                        file=file_str,
                        commit=str(commit) if commit is not None else None,
                        line=line_i,
                    )
                )

            # If we couldn't parse anything, surface stderr to make it debuggable.
            if summary_obj is None and not repo_findings:
                stderr = (res.stderr or "").strip()
                repo_errors.append(
                    f"kingfisher produced no parseable JSON for {repo_full}: exit={res.returncode} stderr={stderr[:600]}"
                )

            return repo_full, repo_findings, repo_errors

        def _run_engine(
            engine: str,
            scan_one_repo,
        ) -> None:
            per_engine_findings: list[RedactedFinding] = []
            per_engine_errors: list[str] = []
            with ThreadPoolExecutor(max_workers=max_concurrency) as ex:
                futures = [ex.submit(scan_one_repo, r) for r in repos]
                for fut in as_completed(futures):
                    _repo_full, repo_findings, repo_errors = fut.result()
                    if repo_errors:
                        per_engine_errors.extend(repo_errors)
                    if repo_findings:
                        per_engine_findings.extend(repo_findings)
            findings.extend(per_engine_findings)
            errors.extend(per_engine_errors)
            engine_summaries[engine] = {
                "findings_total": len(per_engine_findings),
                "errors_total": len(per_engine_errors),
            }

        if "trufflehog" in requested_engines:
            _run_engine("trufflehog", _scan_one_repo_trufflehog)
        if "kingfisher" in requested_engines:
            _run_engine("kingfisher", _scan_one_repo_kingfisher)

    # Summaries
    verified = sum(1 for f in findings if f.verified is True)
    unverified = sum(1 for f in findings if f.verified is False)
    unknown = sum(1 for f in findings if f.verified is None)

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "owners": owners,
            "owners_expanded": expanded_owners,
            "repos_scanned": repos,
            "repos_scanned_count": len(repos),
            "max_repos": max_repos,
            "include_repos": include_repos,
            "exclude_repos": exclude_repos,
            "include_forks": include_forks,
        },
        "discovery": {
            "method": discovery_method,
            "errors": discovery_errors,
        },
        "engine": {
            "requested_engines": requested_engines,
            "max_concurrency": max_concurrency,
            "per_repo_timeout_s": per_repo_timeout if repos and token else None,
            "summaries": engine_summaries,
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
