"""Sweep all public GitHub repos for "unwanted personal uploads".

This is intentionally a *policy* sweep (file names / extensions / sizes), not a
secret scanner. Secret scanners are handled separately (e.g. TruffleHog).

It uses the GitHub API `git/trees?recursive=1` endpoint to avoid cloning.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_DENY_GLOBS = [
    "**/.env",
    "**/.env.*",
    "**/*.pem",
    "**/*.key",
    "**/*.p12",
    "**/*.pfx",
    "**/*.kdbx",
    "**/*.ovpn",
    "**/*.mobileprovision",
    "**/*.keystore",
    "**/*.jks",
    "**/*.pkcs12",
    "**/id_rsa",
    "**/id_rsa.*",
    "**/.npmrc",
    "**/.aws/credentials",
    "**/.ssh/**",
    "**/.gnupg/**",
]

DEFAULT_MAX_BLOB_BYTES = 5 * 1024 * 1024  # 5 MiB


@dataclass(frozen=True)
class Hit:
    repo: str
    path: str
    size: int | None
    reason: str


def _gh_headers(token: str | None) -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "devguard-sweeper",
    }
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _sleep_on_rate_limit(resp: httpx.Response) -> None:
    # If we hit rate limits, GitHub returns 403 with rate limit headers.
    if resp.status_code != 403:
        return
    remaining = resp.headers.get("x-ratelimit-remaining")
    reset = resp.headers.get("x-ratelimit-reset")
    if remaining == "0" and reset and reset.isdigit():
        wait = max(0, int(reset) - int(time.time()) + 2)
        if wait:
            print(f"[rate-limit] sleeping {wait}s", file=sys.stderr)
            time.sleep(wait)


def list_public_repos(client: httpx.Client, owner: str) -> list[str]:
    repos: list[str] = []
    page = 1
    while True:
        url = f"https://api.github.com/users/{owner}/repos"
        r = client.get(url, params={"type": "public", "per_page": 100, "page": page})
        _sleep_on_rate_limit(r)
        r.raise_for_status()
        items = r.json()
        if not items:
            break
        repos.extend([i["name"] for i in items])
        page += 1
    return repos


def get_default_branch_sha(client: httpx.Client, owner: str, repo: str) -> tuple[str, str]:
    r = client.get(f"https://api.github.com/repos/{owner}/{repo}")
    _sleep_on_rate_limit(r)
    r.raise_for_status()
    j = r.json()
    branch = j.get("default_branch") or "main"

    ref = client.get(f"https://api.github.com/repos/{owner}/{repo}/git/refs/heads/{branch}")
    _sleep_on_rate_limit(ref)
    ref.raise_for_status()
    sha = ref.json()["object"]["sha"]
    return branch, sha


def get_tree(client: httpx.Client, owner: str, repo: str, sha: str) -> list[dict[str, Any]]:
    r = client.get(
        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}",
        params={"recursive": "1"},
    )
    _sleep_on_rate_limit(r)
    r.raise_for_status()
    j = r.json()
    return j.get("tree", [])


def matches(globs: list[str], path: str) -> str | None:
    # Normalize to allow ** patterns via fnmatch
    p = path.lstrip("/")
    for g in globs:
        if fnmatch.fnmatch(p, g.replace("**/", "*")) or fnmatch.fnmatch(p, g):
            return g
    return None


def sweep_repo(
    client: httpx.Client,
    owner: str,
    repo: str,
    deny_globs: list[str],
    max_blob_bytes: int,
) -> list[Hit]:
    _branch, sha = get_default_branch_sha(client, owner, repo)
    tree = get_tree(client, owner, repo, sha)

    hits: list[Hit] = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        path = item.get("path")
        if not isinstance(path, str):
            continue
        size = item.get("size")

        g = matches(deny_globs, path)
        if g:
            hits.append(
                Hit(
                    repo=f"{owner}/{repo}",
                    path=path,
                    size=size if isinstance(size, int) else None,
                    reason=f"deny_glob:{g}",
                )
            )
            continue

        if isinstance(size, int) and size > max_blob_bytes:
            hits.append(
                Hit(
                    repo=f"{owner}/{repo}",
                    path=path,
                    size=size,
                    reason=f"blob_too_large>{max_blob_bytes}",
                )
            )

    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--owner", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--max-blob-bytes", type=int, default=DEFAULT_MAX_BLOB_BYTES)
    ap.add_argument("--deny", action="append", default=[])
    args = ap.parse_args()

    token = os.environ.get("GUARDIAN_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")

    deny_globs = DEFAULT_DENY_GLOBS + list(args.deny)

    report: dict[str, Any] = {
        "owner": args.owner,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "max_blob_bytes": args.max_blob_bytes,
        "deny_globs": deny_globs,
        "hits": [],
    }

    with httpx.Client(headers=_gh_headers(token), timeout=30.0) as client:
        repos = list_public_repos(client, args.owner)
        all_hits: list[Hit] = []
        for name in repos:
            try:
                hits = sweep_repo(client, args.owner, name, deny_globs, args.max_blob_bytes)
                all_hits.extend(hits)
            except Exception as e:
                all_hits.append(
                    Hit(repo=f"{args.owner}/{name}", path="", size=None, reason=f"error:{e}")
                )

    report["hits"] = [h.__dict__ for h in all_hits]

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    bad = [h for h in all_hits if not h.reason.startswith("error:")]
    errors = [h for h in all_hits if h.reason.startswith("error:")]

    print(f"repos_scanned={len(set(h.repo for h in all_hits))}")
    print(f"policy_hits={len(bad)}")
    print(f"errors={len(errors)}")

    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
