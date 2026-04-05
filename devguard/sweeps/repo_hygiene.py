"""Repo hygiene sweep: detect structural problems across local git repos.

Checks each repo for scattered doc dirs, committed generated data, hardcoded
absolute paths in shell scripts, stale .gitkeep files, tracked editor/cache
directories, internal documents in public repos, and stale rename references.
"""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass
class HygieneFinding:
    repo_path: str
    check: str
    severity: str  # "low" or "medium"
    message: str
    files: list[str] = field(default_factory=list)


@dataclass
class RepoHygieneResult:
    repo_path: str
    is_public: bool
    findings: list[HygieneFinding] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_likely_public(repo: Path) -> bool:
    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "LICENCE"):
        if (repo / name).exists():
            return True
    return False


def _git_ls_files(repo: Path) -> list[str]:
    """Return all tracked file paths (relative) for a repo."""
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        timeout=60,
    )
    if proc.returncode != 0:
        return []
    out = proc.stdout.decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p]


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_scattered_docs(repo: Path) -> HygieneFinding | None:
    """A: Both doc/ and docs/ exist at repo root."""
    has_doc = (repo / "doc").is_dir()
    has_docs = (repo / "docs").is_dir()
    if has_doc and has_docs:
        return HygieneFinding(
            repo_path=str(repo),
            check="scattered_docs",
            severity="low",
            message="Both doc/ and docs/ exist at repo root -- consolidate into one.",
            files=["doc/", "docs/"],
        )
    return None


# Glob patterns for generated data that shouldn't normally be committed.
_GENERATED_DATA_GLOBS: list[str] = [
    "data/**/*.json",
    "data/**/*.jsonl",
    "data/**/*.csv",
    "data/**/*.bin",
    "data/**/*.hdf5",
    "results/**/*.json",
    "output/**/*.json",
    ".hypothesis/constants/*",
]

# Directories that signal data/ is intentional (contains project manifests).
_DATA_INTENTIONAL_MARKERS: tuple[str, ...] = ("Cargo.toml", "package.json", "pyproject.toml")


def _data_dir_is_intentional(repo: Path) -> bool:
    data = repo / "data"
    if not data.is_dir():
        return False
    for marker in _DATA_INTENTIONAL_MARKERS:
        if (data / marker).exists():
            return True
    return False


def _check_committed_generated_data(
    repo: Path, tracked: list[str]
) -> HygieneFinding | None:
    """B: Tracked files matching generated-data patterns."""
    if _data_dir_is_intentional(repo):
        # data/ is a source tree; only check non-data patterns
        active_globs = [g for g in _GENERATED_DATA_GLOBS if not g.startswith("data/")]
    else:
        active_globs = _GENERATED_DATA_GLOBS

    matched: list[str] = []
    for rel in tracked:
        for g in active_globs:
            if fnmatch.fnmatch(rel, g):
                matched.append(rel)
                break

    if not matched:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="committed_generated_data",
        severity="medium",
        message=f"{len(matched)} tracked file(s) look like generated/data artifacts.",
        files=matched[:20],
    )


_HARDCODED_PATH_RE = re.compile(r"(/Users/|/home/)\S+")


def _check_hardcoded_paths(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """C: Tracked .sh files with hardcoded /Users/ or /home/ absolute paths."""
    sh_files = [rel for rel in tracked if rel.endswith(".sh")]
    hits: list[str] = []
    for rel in sh_files:
        path = repo / rel
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            # Skip comment lines
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if _HARDCODED_PATH_RE.search(line):
                hits.append(f"{rel}:{lineno}")
                if len(hits) >= 10:
                    break
        if len(hits) >= 10:
            break

    if not hits:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="hardcoded_absolute_paths",
        severity="medium",
        message=f"Hardcoded absolute path (/Users/ or /home/) in {len(hits)} tracked shell script location(s).",
        files=hits,
    )


def _check_stale_gitkeep(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """D: .gitkeep file in a directory that also has other tracked files."""
    # Build a map from directory -> tracked file count (excluding .gitkeep itself)
    dir_other: dict[str, int] = {}
    gitkeep_dirs: list[str] = []

    for rel in tracked:
        p = Path(rel)
        parent = str(p.parent)
        if p.name == ".gitkeep":
            gitkeep_dirs.append(parent)
        else:
            dir_other[parent] = dir_other.get(parent, 0) + 1

    stale: list[str] = []
    for d in gitkeep_dirs:
        if dir_other.get(d, 0) > 0:
            stale.append(f"{d}/.gitkeep")

    if not stale:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="stale_gitkeep",
        severity="low",
        message=f"{len(stale)} .gitkeep file(s) in directories that have other tracked files.",
        files=stale,
    )


_TRACKED_EDITOR_DIRS: tuple[str, ...] = (
    ".vscode/",
    ".idea/",
    ".ruff_cache/",
    ".hypothesis/",
)


def _check_tracked_editor_dirs(repo: Path, tracked: list[str]) -> HygieneFinding | None:
    """E: Editor/cache directories tracked in git."""
    found: set[str] = set()
    for rel in tracked:
        for prefix in _TRACKED_EDITOR_DIRS:
            if rel.startswith(prefix) or ("/" + prefix) in rel:
                found.add(prefix.rstrip("/"))
                break

    if not found:
        return None
    dirs = sorted(found)
    return HygieneFinding(
        repo_path=str(repo),
        check="tracked_editor_dirs",
        severity="low",
        message=f"Editor/cache directory tracked in git: {', '.join(dirs)}.",
        files=[d + "/" for d in dirs],
    )


_INTERNAL_DOC_PATTERNS: list[str] = [
    "*AUDIT*.md",
    "*_REVIEW*.md",
    ".claude/*session*.json",
    ".trainctl/*session*.json",
]


def _check_internal_docs_in_public(
    repo: Path, tracked: list[str], is_public: bool
) -> HygieneFinding | None:
    """F: Internal documents committed in a public repo."""
    if not is_public:
        return None

    matched: list[str] = []
    for rel in tracked:
        for pat in _INTERNAL_DOC_PATTERNS:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(Path(rel).name, pat):
                matched.append(rel)
                break

    if not matched:
        return None
    return HygieneFinding(
        repo_path=str(repo),
        check="internal_docs_in_public_repo",
        severity="low",
        message=f"{len(matched)} internal document(s) committed in a public repo.",
        files=matched,
    )


def _check_stale_rename_refs(
    repo: Path, tracked: list[str]
) -> HygieneFinding | None:
    """G: Cargo.toml name differs from directory name; old name still appears as env var prefix."""
    cargo = repo / "Cargo.toml"
    if not cargo.is_file():
        return None

    dir_name = repo.name

    try:
        cargo_text = cargo.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None

    # Extract package name from [package] name = "..."
    name_match = re.search(r'^\s*name\s*=\s*"([^"]+)"', cargo_text, re.MULTILINE)
    if not name_match:
        return None
    crate_name = name_match.group(1)

    # Only flag when crate name and directory name differ
    # (normalize hyphens to underscores for comparison)
    crate_norm = crate_name.replace("-", "_")
    dir_norm = dir_name.replace("-", "_")
    if crate_norm == dir_norm:
        return None

    # The old name candidate is the directory name (the one that changed)
    old_prefix = dir_norm.upper()
    pattern = re.compile(r"\b" + re.escape(old_prefix) + r"_\w+")

    hits: list[str] = []
    count = 0
    for rel in tracked:
        path = repo / rel
        if not path.is_file():
            continue
        # Only scan text-like files; skip binaries by extension
        suffix = path.suffix.lower()
        if suffix in (".png", ".jpg", ".jpeg", ".gif", ".bin", ".wasm", ".so", ".dylib"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        matches = pattern.findall(text)
        if matches:
            count += len(matches)
            hits.append(f"{rel} ({len(matches)} ref(s))")

    # Heuristic threshold: only flag if more than 3 references remain
    if count <= 3:
        return None

    return HygieneFinding(
        repo_path=str(repo),
        check="stale_rename_refs",
        severity="medium",
        message=(
            f"Cargo.toml name={crate_name!r} differs from dir={dir_name!r}; "
            f"{count} reference(s) to old env var prefix {old_prefix!r} remain."
        ),
        files=hits[:10],
    )


# ---------------------------------------------------------------------------
# Main sweep function
# ---------------------------------------------------------------------------


def sweep_repo_hygiene(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Check repos for structural hygiene problems and return a report."""
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()

    repos = sorted(iter_git_repos(root, max_depth=max_depth))
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    if globs:
        repos = [r for r in repos if not any(fnmatch.fnmatch(str(r), g) for g in globs)]

    results: list[RepoHygieneResult] = []
    total_findings = 0

    for repo in repos:
        try:
            is_public = _is_likely_public(repo)
            tracked = _git_ls_files(repo)
        except Exception as exc:
            errors.append(f"failed to read {repo}: {exc}")
            continue

        result = RepoHygieneResult(repo_path=str(repo), is_public=is_public)

        for check_fn in (
            lambda r: _check_scattered_docs(r),
            lambda r: _check_committed_generated_data(r, tracked),
            lambda r: _check_hardcoded_paths(r, tracked),
            lambda r: _check_stale_gitkeep(r, tracked),
            lambda r: _check_tracked_editor_dirs(r, tracked),
            lambda r: _check_internal_docs_in_public(r, tracked, is_public),
            lambda r: _check_stale_rename_refs(r, tracked),
        ):
            try:
                finding = check_fn(repo)
            except Exception as exc:
                errors.append(f"{repo}: check error: {exc}")
                continue
            if finding is not None:
                result.findings.append(finding)
                total_findings += 1

        results.append(result)

    # Sort: most findings first, then by path
    results.sort(key=lambda r: (-len(r.findings), r.repo_path))

    severity_counts: dict[str, int] = {"medium": 0, "low": 0}
    for r in results:
        for f in r.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
        },
        "summary": {
            "repos_with_findings": sum(1 for r in results if r.findings),
            "total_findings": total_findings,
            "severity_counts": severity_counts,
        },
        "repos": [
            {
                "repo_path": r.repo_path,
                "is_public": r.is_public,
                "findings": [
                    {
                        "check": f.check,
                        "severity": f.severity,
                        "message": f.message,
                        "files": f.files,
                    }
                    for f in r.findings
                ],
            }
            for r in results
            if r.findings
        ][:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
