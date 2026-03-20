"""Gitignore audit sweep: detect missing .gitignore patterns across local repos.

Scans git repos under a dev root and checks whether common hygiene patterns
(.env, .state/, *.log, etc.) are present in .gitignore. Repos with a LICENSE
file are flagged as likely public and get higher severity.
"""

from __future__ import annotations

import fnmatch
import json
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _default_dev_root() -> Path:
    return Path(os.getenv("DEV_DIR") or "~/Documents/dev").expanduser()


# Patterns to check, grouped by relevance.
# Each tuple: (pattern_name, gitignore_lines_that_satisfy_it, languages_where_relevant)
# languages_where_relevant: None = always, otherwise set of {"rust", "python", "js", "go", ...}
REQUIRED_PATTERNS: list[tuple[str, list[str], set[str] | None]] = [
    (".env files", [".env", ".env.*", ".env.local", ".env.*.local"], None),
    (".state/ dir", [".state", ".state/"], None),
    (".claude/ dir", [".claude", ".claude/"], None),
    ("*.log files", ["*.log"], None),
    (".DS_Store", [".DS_Store"], None),
    ("*.sqlite/db", ["*.sqlite", "*.sqlite3", "*.db"], None),
    ("node_modules/", ["node_modules", "node_modules/"], {"js", "ts"}),
    ("target/", ["target", "target/"], {"rust"}),
    (".venv/", [".venv", ".venv/", "venv", "venv/"], {"python"}),
    ("dist/", ["dist", "dist/"], {"js", "ts", "python"}),
    ("build/", ["build", "build/"], {"js", "ts", "python", "go"}),
    ("__pycache__/", ["__pycache__", "__pycache__/"], {"python"}),
]


def _detect_languages(repo: Path) -> set[str]:
    """Detect project languages from manifest files."""
    langs: set[str] = set()
    if (repo / "Cargo.toml").exists():
        langs.add("rust")
    if (repo / "pyproject.toml").exists() or (repo / "setup.py").exists():
        langs.add("python")
    if (repo / "package.json").exists():
        langs.add("js")
        langs.add("ts")
    if (repo / "go.mod").exists():
        langs.add("go")
    return langs


def _is_likely_public(repo: Path) -> bool:
    """Heuristic: repo has a LICENSE file -> likely public."""
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"):
        if (repo / name).exists():
            return True
    return False


def _read_gitignore_lines(repo: Path) -> list[str]:
    """Read .gitignore and return non-empty, non-comment lines."""
    gi = repo / ".gitignore"
    if not gi.is_file():
        return []
    return _read_gitignore_lines_from(gi)


def _pattern_satisfied(gitignore_lines: list[str], required_variants: list[str]) -> bool:
    """Check if any variant of a required pattern appears in .gitignore.

    Handles leading `/` and trailing `/` normalization.
    """
    normalized = set()
    for line in gitignore_lines:
        # Strip negation prefix
        if line.startswith("!"):
            continue
        clean = line.lstrip("/").rstrip("/").strip()
        if clean:
            normalized.add(clean)
            # "**/" prefix in gitignore means "at any depth", which covers root.
            # e.g. **/*.log covers *.log, **/dist covers dist
            if clean.startswith("**/"):
                normalized.add(clean[3:])
    for variant in required_variants:
        clean = variant.lstrip("/").rstrip("/").strip()
        if clean in normalized:
            return True
        # Check if any existing pattern would match this variant via fnmatch
        for existing in normalized:
            if fnmatch.fnmatch(clean, existing):
                return True
    return False


@dataclass(frozen=True)
class GitignoreGap:
    repo_path: str
    pattern_name: str
    is_public: bool


@dataclass
class RepoAuditResult:
    repo_path: str
    has_gitignore: bool
    is_public: bool
    languages: list[str]
    missing_patterns: list[str] = field(default_factory=list)
    case_warnings: list[str] = field(default_factory=list)


# Files that must have exact casing for Claude Code to find them.
# (expected_name, parent_relative_to_repo)
_CASE_SENSITIVE_FILES: list[tuple[str, str]] = [
    ("CLAUDE.md", "."),
    ("CLAUDE.md", ".claude"),
]


def _check_case_sensitive_files(repo: Path) -> list[str]:
    """Check for case-sensitive file naming issues (e.g. claude.md vs CLAUDE.md).

    On case-insensitive filesystems (macOS), wrong-cased files still "exist"
    but git tracks the original case, which breaks on Linux/CI.
    """
    import subprocess as _sp

    warnings: list[str] = []
    for expected, parent_rel in _CASE_SENSITIVE_FILES:
        parent = repo / parent_rel
        if not parent.is_dir():
            continue
        # Check if any case variant exists
        target = parent / expected
        if not target.exists():
            continue
        # Ask git what case it actually tracks
        try:
            res = _sp.run(
                ["git", "ls-files", str(Path(parent_rel) / expected)],
                cwd=str(repo), capture_output=True, text=True, timeout=5,
            )
            tracked = res.stdout.strip()
            if not tracked:
                # Try lowercase
                res2 = _sp.run(
                    ["git", "ls-files", str(Path(parent_rel) / expected.lower())],
                    cwd=str(repo), capture_output=True, text=True, timeout=5,
                )
                tracked = res2.stdout.strip()
            if tracked and tracked != str(Path(parent_rel) / expected):
                warnings.append(
                    f"git tracks '{tracked}' but Claude Code expects '{Path(parent_rel) / expected}'"
                )
        except Exception:
            continue
    return warnings


def _iter_git_repos(root: Path, max_depth: int) -> list[Path]:
    """Discover git repos under root, bounded by max_depth."""
    root = root.resolve()
    max_depth = max(0, min(int(max_depth), 6))
    junk = {
        "node_modules", ".venv", "venv", "dist", "build", ".git",
        ".cache", ".state", "__pycache__", "_trash", "_scratch",
        "_external", "_archive", "_forks",
    }
    repos: list[Path] = []
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen: set[Path] = set()
    while stack:
        cur, depth = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        if (cur / ".git").exists():
            repos.append(cur)
            continue
        if depth >= max_depth:
            continue
        try:
            for child in cur.iterdir():
                if not child.is_dir():
                    continue
                name = child.name
                if depth == 0 and name in junk:
                    continue
                if name.startswith("."):
                    continue
                stack.append((child, depth + 1))
        except Exception:
            continue
    return sorted(repos)


def _read_global_gitignore_lines() -> list[str]:
    """Read the global gitignore (core.excludesFile) and return non-empty, non-comment lines."""
    import subprocess as _sp

    try:
        res = _sp.run(
            ["git", "config", "--global", "core.excludesFile"],
            capture_output=True, text=True, timeout=5,
        )
        path_str = res.stdout.strip()
        if not path_str:
            return []
        p = Path(path_str).expanduser()
        if not p.is_file():
            return []
        return _read_gitignore_lines_from(p)
    except Exception:
        return []


def _read_gitignore_lines_from(path: Path) -> list[str]:
    """Read a gitignore file and return non-empty, non-comment lines."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []
    return [s for line in text.splitlines() if (s := line.strip()) and not s.startswith("#")]


def audit_gitignores(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit .gitignore files across repos and return a report."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()

    repos = _iter_git_repos(root, max_depth=max_depth)
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    if globs:
        repos = [r for r in repos if not any(fnmatch.fnmatch(str(r), g) for g in globs)]

    # Read global gitignore once -- patterns there apply to all repos.
    global_gi_lines = _read_global_gitignore_lines()

    results: list[RepoAuditResult] = []
    gap_counter: Counter[str] = Counter()
    repos_without_gitignore: list[str] = []
    public_repos_with_gaps: list[str] = []

    for repo in repos:
        try:
            langs = _detect_languages(repo)
            is_public = _is_likely_public(repo)
            repo_gi_lines = _read_gitignore_lines(repo)
            gi_lines = global_gi_lines + repo_gi_lines
            has_gitignore = (repo / ".gitignore").is_file()
        except Exception as exc:
            errors.append(f"failed to read {repo}: {exc}")
            continue

        missing: list[str] = []
        for pattern_name, variants, relevant_langs in REQUIRED_PATTERNS:
            # Skip language-specific patterns if not relevant
            if relevant_langs and not (langs & relevant_langs):
                continue
            if not _pattern_satisfied(gi_lines, variants):
                missing.append(pattern_name)
                gap_counter[pattern_name] += 1

        case_warns = _check_case_sensitive_files(repo)

        result = RepoAuditResult(
            repo_path=str(repo),
            has_gitignore=has_gitignore,
            is_public=is_public,
            languages=sorted(langs),
            missing_patterns=missing,
            case_warnings=case_warns,
        )
        results.append(result)

        if not has_gitignore:
            repos_without_gitignore.append(str(repo))
        if is_public and missing:
            public_repos_with_gaps.append(str(repo))

    # Sort: public repos with gaps first, then by gap count
    results.sort(key=lambda r: (-r.is_public, -len(r.missing_patterns), r.repo_path))

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
        },
        "summary": {
            "repos_without_gitignore": len(repos_without_gitignore),
            "repos_without_gitignore_list": repos_without_gitignore[:50],
            "public_repos_with_gaps": len(public_repos_with_gaps),
            "public_repos_with_gaps_list": public_repos_with_gaps[:50],
            "total_gaps": sum(len(r.missing_patterns) for r in results),
            "gap_frequency": gap_counter.most_common(20),
            "total_case_warnings": sum(len(r.case_warnings) for r in results),
        },
        "repos": [
            {
                "repo_path": r.repo_path,
                "has_gitignore": r.has_gitignore,
                "is_public": r.is_public,
                "languages": r.languages,
                "missing_patterns": r.missing_patterns,
                **({"case_warnings": r.case_warnings} if r.case_warnings else {}),
            }
            for r in results
            if r.missing_patterns or not r.has_gitignore or r.case_warnings
        ][:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
