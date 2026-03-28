"""Shared utilities for sweep modules."""

from __future__ import annotations

import fnmatch
import os
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

# Comprehensive set of directories to skip during repo discovery.
_JUNK_DIRS: frozenset[str] = frozenset(
    {
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
        ".pytest_cache",
        ".ruff_cache",
    }
)


def default_dev_root() -> Path:
    """Return the dev workspace root from $DEV_DIR, well-known path, or CWD.

    Priority: $DEV_DIR env var > ~/Documents/dev (if it exists) > CWD.
    """
    env = os.getenv("DEV_DIR")
    if env:
        return Path(env).expanduser()
    well_known = Path.home() / "Documents" / "dev"
    if well_known.is_dir():
        return well_known
    return Path.cwd()


def utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string with Z suffix."""
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def iter_git_repos(
    root: Path,
    max_depth: int = 3,
    exclude_globs: list[str] | None = None,
    single_repo: Path | None = None,
) -> Iterator[Path]:
    """Discover git repos under *root*, bounded by *max_depth*.

    If *single_repo* is given, yield only that path (if it is a git repo)
    and skip the full discovery walk.  This enables single-repo mode for CI.

    Skips known junk directories and hidden directories (except at depth 0
    where only junk dirs are skipped). Repos matching any of *exclude_globs*
    are omitted.
    """
    if single_repo is not None:
        single = single_repo.resolve()
        if (single / ".git").exists():
            yield single
        return

    root = root.resolve()
    max_depth = max(0, min(int(max_depth), 6))
    globs = exclude_globs or []

    stack: list[tuple[Path, int]] = [(root, 0)]
    seen: set[Path] = set()

    while stack:
        cur, depth = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)

        if (cur / ".git").exists():
            if not any(fnmatch.fnmatch(str(cur), g) for g in globs):
                yield cur
            continue

        if depth >= max_depth:
            continue

        try:
            for child in cur.iterdir():
                if not child.is_dir():
                    continue
                name = child.name
                if name in _JUNK_DIRS:
                    continue
                if name.startswith("."):
                    continue
                stack.append((child, depth + 1))
        except Exception:
            continue
