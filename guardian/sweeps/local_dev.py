"""Local dev workspace sweep for "blunders" (policy-based).

This sweep is meant to catch accidental committed artifacts such as:
- .env files
- private keys / cert bundles
- sqlite/db dumps
- large blobs
- known generated reports (e.g., guardian email history/report outputs)

It is intentionally conservative and *non-destructive*:
- it does not rewrite git history
- it does not upload anything
"""

from __future__ import annotations

import fnmatch
import json
import os
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


DEFAULT_DENY_GLOBS: list[str] = [
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
    "**/*.sqlite",
    "**/*.sqlite3",
    "**/*.db",
    "**/*.db-wal",
    "**/*.db-shm",
    # Known Guardian "oops outputs"
    "**/.guardian-email-history.json",
    "**/.guardian-email-thread",
    "**/repo_review_results.json",
    "**/npm_security_report.json",
    "**/npm_security_report.md",
]


@dataclass(frozen=True, slots=True)
class Hit:
    repo_path: str
    file_path: str
    reason: str
    size_bytes: int | None = None


def _utc_now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _matches_any(path: str, globs: list[str]) -> str | None:
    p = path.lstrip("/")
    # Allow common "example" env files (these are typically safe to commit).
    # We still flag the real `.env` and other patterns.
    env_allow = {".env.example", ".env.template", ".env.sample", ".env.dist"}
    if Path(p).name in env_allow:
        # If the only match would be the broad `.env.*` pattern, treat as allowed.
        pass
    for g in globs:
        if Path(p).name in env_allow and (g.endswith("/.env.*") or g.endswith("**/.env.*")):
            continue
        # fnmatch's "*" matches "/" too; keep both patterns for readability
        if fnmatch.fnmatch(p, g) or fnmatch.fnmatch(p, g.replace("**/", "")):
            return g
    return None


def _git_ls_files(repo: Path) -> list[str]:
    # Use -z to handle weird filenames.
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    if proc.returncode != 0:
        return []
    out = proc.stdout.decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]


def _discover_git_repos(dev_root: Path, max_depth: int = 2) -> list[Path]:
    """Discover git repos under dev_root, bounded by max_depth.

    We avoid an unbounded recursive walk by limiting to max_depth directory levels.
    """
    repos: list[Path] = []
    dev_root = dev_root.expanduser().resolve()
    if not dev_root.exists():
        return repos

    # Depth 0: dev_root itself
    if (dev_root / ".git").exists():
        repos.append(dev_root)

    # Depth-limited breadth walk
    frontier: list[tuple[Path, int]] = [(dev_root, 0)]
    while frontier:
        cur, depth = frontier.pop()
        if depth >= max_depth:
            continue
        try:
            children = list(cur.iterdir())
        except (OSError, PermissionError):
            continue
        for child in children:
            if not child.is_dir():
                continue
            name = child.name
            # Avoid obvious heavy dirs.
            #
            # Important: the workspace root under ~/Documents/dev often contains
            # very large scratch/backup directories. Scanning into them can take
            # minutes and isn't useful for "repo blunder" detection.
            if name in {
                ".git",
                ".venv",
                "venv",
                "node_modules",
                "target",
                ".cache",
                ".pytest_cache",
                ".ruff_cache",
            }:
                continue
            if depth == 0:
                # Skip top-level junk roots unless explicitly allowed.
                if (name.startswith("_") or name.startswith(".")) and name not in {"_infra"}:
                    continue
                if name in {"evals", "integration_test_tmp"}:
                    continue
            if (child / ".git").exists():
                repos.append(child)
                # Don't recurse into a repo unless user explicitly sets higher max_depth.
                continue
            frontier.append((child, depth + 1))

    # De-dupe while preserving order
    seen: set[Path] = set()
    out: list[Path] = []
    for r in repos:
        rr = r.resolve()
        if rr in seen:
            continue
        seen.add(rr)
        out.append(rr)
    return out


def sweep_dev_repos(
    dev_root: Path,
    deny_globs: list[str] | None = None,
    max_blob_bytes: int = 5 * 1024 * 1024,
    max_depth: int = 2,
) -> tuple[list[Hit], dict]:
    """Sweep discovered git repos under dev_root.

    Returns:
        (hits, metadata) where metadata is a small dict safe to serialize.
    """
    globs = deny_globs or list(DEFAULT_DENY_GLOBS)
    repos = _discover_git_repos(dev_root, max_depth=max_depth)

    hits: list[Hit] = []
    for repo in repos:
        tracked = _git_ls_files(repo)
        for rel in tracked:
            pat = _matches_any(rel, globs)
            if pat:
                size = None
                try:
                    p = repo / rel
                    if p.exists() and p.is_file():
                        size = p.stat().st_size
                except OSError:
                    size = None
                hits.append(
                    Hit(
                        repo_path=str(repo),
                        file_path=rel,
                        reason=f"deny_glob:{pat}",
                        size_bytes=size,
                    )
                )
                continue

            # Large blobs (current working tree size, not historical blob size)
            try:
                p = repo / rel
                if p.exists() and p.is_file():
                    sz = p.stat().st_size
                    if sz > max_blob_bytes:
                        hits.append(
                            Hit(
                                repo_path=str(repo),
                                file_path=rel,
                                reason=f"blob_too_large>{max_blob_bytes}",
                                size_bytes=sz,
                            )
                        )
            except OSError:
                continue

    meta = {
        "generated_at": _utc_now_iso(),
        "dev_root": str(dev_root.expanduser()),
        "repos_scanned": len(repos),
        "max_depth": max_depth,
        "max_blob_bytes": max_blob_bytes,
        "deny_globs": globs,
    }
    return hits, meta


def write_report(path: Path, hits: Iterable[Hit], meta: dict) -> None:
    payload = {
        **meta,
        "hits": [asdict(h) for h in hits],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def default_dev_root() -> Path:
    return Path(os.environ.get("DEV_DIR", str(Path.home() / "Documents" / "dev")))

