"""Scan the full git history of every local repo for committed secrets.

A secret that was committed and later deleted is still in history and still
needs rotating. This sweep scans each discovered repo whether its worktree is
clean or dirty, using the first available engine:

1. gitleaks (`gitleaks git`)
2. trufflehog (`trufflehog git --no-verification`)
3. devguard's built-in regex over `git log -p`

Secret values never enter the report. A repo that no engine could scan is
reported as `not_scanned`, never as clean.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from devguard.checkers.secret import SecretChecker
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now
from devguard.sweeps.local_dirty_worktree_secrets import LOCK_FILE_BASENAMES

ENGINES = ("gitleaks", "trufflehog", "regex")

# Paths whose hits are almost always false positives: lockfile hashes, minified
# bundles, rustdoc search indexes and build output.
_SKIP_PATH_GLOBS = ("*.min.*", "*search-index*.js", "*.rlib", "*.o", "*.so", "*.dylib")
_SKIP_DIR_PARTS = frozenset({"target", "node_modules", "dist", "build"})
# Hits here are usually test fixtures: still reported, at low severity.
_FIXTURE_DIR_PARTS = frozenset({"tests", "test", "fixtures", "testdata", "examples"})
# Test files kept beside the code they test (test_x.py, test-x.sh, x.test.ts, x_test.go).
_TEST_FILE_RE = re.compile(r"^test[_-]|[._-]test\.[^.]+$|[._]spec\.[^.]+$")
# Entropy-only rules: on an 80-repo workspace gitleaks' generic-api-key made up
# 369 of 443 high findings, nearly all dataset strings and doc examples.
_HEURISTIC_RULES = frozenset({"generic-api-key", "Generic API Key"})

_REGEX_PATTERNS = [
    (re.compile(p), name)
    for p, name in SecretChecker.FALLBACK_PATTERNS
    # The generic api_key=... rule is too noisy across a whole history.
    if name != "Generic API Key"
]


@dataclass(frozen=True)
class HistoryFinding:
    repo_path: str
    engine: str
    rule: str
    file: str
    commit: str | None
    line: int | None
    in_head: bool
    severity: str
    message: str


def _skip_path(path: str) -> bool:
    p = PurePosixPath(path)
    if p.name in LOCK_FILE_BASENAMES:
        return True
    if _SKIP_DIR_PARTS.intersection(p.parts[:-1]):
        return True
    return any(fnmatch.fnmatch(p.name, g) for g in _SKIP_PATH_GLOBS)


def _finding(
    repo: Path,
    engine: str,
    rule: str,
    file: str,
    commit: str | None,
    line: int | None,
    head_paths: set[str],
) -> HistoryFinding:
    in_head = file in head_paths
    p = PurePosixPath(file)
    fixture = bool(_FIXTURE_DIR_PARTS.intersection(p.parts[:-1])) or bool(
        _TEST_FILE_RE.search(p.name)
    )
    fixture = fixture or rule in _HEURISTIC_RULES
    if in_head:
        message = f"{rule} in {file}: remove it from the tree and rotate the credential"
    else:
        message = (
            f"{rule} in {file} at {commit or 'an earlier commit'}: no longer in HEAD but "
            "still in history; rotate the credential and purge history if it is real"
        )
    return HistoryFinding(
        repo_path=str(repo),
        engine=engine,
        rule=rule,
        file=file,
        commit=commit,
        line=line,
        in_head=in_head,
        severity="low" if fixture else "high",
        message=message,
    )


def _head_paths(repo: Path, timeout_s: int) -> set[str]:
    res = subprocess.run(
        ["git", "ls-tree", "-r", "--name-only", "-z", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    # An empty repo has no HEAD; every path then counts as history-only.
    if res.returncode != 0:
        return set()
    return {p for p in res.stdout.split("\0") if p}


def _scan_gitleaks(repo: Path, timeout_s: int) -> list[tuple[str, str, str | None, int | None]]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        res = subprocess.run(
            [
                "gitleaks",
                "git",
                str(repo),
                "--no-banner",
                "--redact",
                "--log-level",
                "error",
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--max-target-megabytes",
                "5",
                "--exit-code",
                "0",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        if res.returncode != 0:
            raise RuntimeError(f"gitleaks exit={res.returncode}: {res.stderr.strip()[:300]}")
        data = json.loads(report.read_text() or "[]")
    if not isinstance(data, list):
        raise RuntimeError("gitleaks report is not a JSON list")
    return [
        (
            str(d.get("RuleID", "unknown")),
            str(d.get("File", "")),
            d.get("Commit"),
            d.get("StartLine"),
        )
        for d in data
        if isinstance(d, dict)
    ]


def _scan_trufflehog(repo: Path, timeout_s: int) -> list[tuple[str, str, str | None, int | None]]:
    res = subprocess.run(
        ["trufflehog", "git", f"file://{repo}", "--no-update", "--no-verification", "--json"],
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if res.returncode not in (0, 183):
        raise RuntimeError(f"trufflehog exit={res.returncode}: {res.stderr.strip()[-300:]}")
    hits = []
    for line in res.stdout.splitlines():
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        git = (obj.get("SourceMetadata") or {}).get("Data", {}).get("Git") or {}
        if not git:
            continue  # log lines and non-git sources
        hits.append(
            (
                str(obj.get("DetectorName", "unknown")),
                str(git.get("file", "")),
                git.get("commit"),
                git.get("line"),
            )
        )
    return hits


_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def _scan_regex(repo: Path, timeout_s: int) -> list[tuple[str, str, str | None, int | None]]:
    res = subprocess.run(
        [
            "git",
            "log",
            "-p",
            "--all",
            "--no-textconv",
            "--no-color",
            "--no-ext-diff",
            "-U0",
            "--format=commit %H",
        ],
        cwd=repo,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout_s,
    )
    if res.returncode != 0:
        raise RuntimeError(f"git log exit={res.returncode}: {res.stderr.strip()[:300]}")
    hits: list[tuple[str, str, str | None, int | None]] = []
    seen: set[tuple[str, str]] = set()
    commit = path = None
    line_no = 0
    for raw in res.stdout.splitlines():
        if raw.startswith("commit "):
            commit, path = raw[7:].strip(), None
        elif raw.startswith("+++ "):
            path = raw[6:] if raw.startswith("+++ b/") else None
        elif m := _HUNK_RE.match(raw):
            line_no = int(m.group(1))
        elif raw.startswith("+") and path:
            for rx, name in _REGEX_PATTERNS:
                # Report each rule once per file: the first commit that added it.
                if rx.search(raw) and (name, path) not in seen:
                    seen.add((name, path))
                    hits.append((name, path, commit, line_no))
            line_no += 1
    return hits


_RUNNERS = {"gitleaks": _scan_gitleaks, "trufflehog": _scan_trufflehog, "regex": _scan_regex}


def _available_engines(engine: str) -> list[str]:
    if engine != "auto":
        return [engine]
    return [e for e in ENGINES if e == "regex" or shutil.which(e)]


def scan_history_secrets(
    *,
    dev_root: Path,
    max_depth: int,
    exclude_repo_globs: list[str] | None = None,
    engine: str = "auto",
    timeout_s: int = 300,
    max_concurrency: int = 4,
) -> tuple[dict[str, Any], list[str]]:
    """Scan every repo under dev_root; return (report, errors)."""
    if engine != "auto" and engine not in ENGINES:
        raise ValueError(f"unknown engine {engine!r}; expected auto or one of {ENGINES}")
    errors: list[str] = []
    repos_meta: list[dict[str, Any]] = []
    findings: list[HistoryFinding] = []
    engines = _available_engines(engine)
    if engine == "regex" or engines == ["regex"]:
        errors.append(
            "gitleaks and trufflehog not found; using devguard's built-in regex, which "
            "covers fewer secret types"
        )

    def scan_one(repo: Path) -> tuple[dict[str, Any], list[HistoryFinding]]:
        status, used, repo_error = "not_scanned", None, None
        hits: list[tuple[str, str, str | None, int | None]] = []
        for name in engines:
            try:
                hits = _RUNNERS[name](repo, timeout_s)
            except subprocess.TimeoutExpired:
                # The next engine would read the same oversized history; stop here
                # and report missed coverage instead of tripling the cost.
                repo_error = f"{name}: timed out after {timeout_s}s"
                break
            except (OSError, subprocess.SubprocessError, RuntimeError, ValueError) as e:
                repo_error = f"{name}: {e}"
                continue
            status, used, repo_error = "scanned", name, None
            break
        repo_findings: list[HistoryFinding] = []
        if status == "scanned":
            head = _head_paths(repo, timeout_s=30)
            for rule, file, commit, line in hits:
                if file and not _skip_path(file):
                    repo_findings.append(_finding(repo, used or "", rule, file, commit, line, head))
        meta = {
            "repo_path": str(repo),
            "status": status,
            "engine": used,
            "findings_count": len(repo_findings),
            "error": repo_error,
        }
        return meta, repo_findings

    repos = sorted(iter_git_repos(dev_root, max_depth=max_depth, exclude_globs=exclude_repo_globs))
    workers = max(1, min(int(max_concurrency), 12))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        # map keeps discovery order, so the report is stable across runs.
        for meta, repo_findings in pool.map(scan_one, repos):
            if meta["error"]:
                errors.append(f"{meta['repo_path']}: {meta['error']}")
            repos_meta.append(meta)
            findings.extend(repo_findings)

    not_scanned = [r for r in repos_meta if r["status"] != "scanned"]
    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(dev_root),
            "max_depth": max_depth,
            "exclude_repo_globs": exclude_repo_globs or [],
            "engine": engine,
            "repos_discovered_count": len(repos_meta),
        },
        "repos": repos_meta,
        "findings": [asdict(f) for f in findings],
        "summary": {
            "findings_total": len(findings),
            "high_findings": sum(1 for f in findings if f.severity == "high"),
            "history_only_findings": sum(1 for f in findings if not f.in_head),
            "repos_scanned": len(repos_meta) - len(not_scanned),
            "repos_not_scanned": len(not_scanned),
            "total_errors": len(not_scanned),
        },
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2))
    os.replace(tmp, path)
