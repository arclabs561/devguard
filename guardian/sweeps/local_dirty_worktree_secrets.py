from __future__ import annotations

import fnmatch
import json
import os
import subprocess
from collections import Counter
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _default_dev_root() -> Path:
    return Path(os.getenv("DEV_DIR") or "~/Documents/dev").expanduser()


# Files where hash-like strings routinely trigger false positives (e.g. SentryToken on uv.lock).
LOCK_FILE_BASENAMES: frozenset[str] = frozenset({
    "uv.lock",
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "Pipfile.lock",
    "requirements.lock",
})


def _iter_git_repos(root: Path, max_depth: int) -> Iterable[Path]:
    """Discover git repos under root, bounded by max_depth."""
    root = root.resolve()
    try:
        max_depth = int(max_depth)
    except Exception:
        max_depth = 2
    max_depth = max(0, min(max_depth, 6))

    # BFS-ish walk with depth bound.
    stack: list[tuple[Path, int]] = [(root, 0)]
    seen: set[Path] = set()

    junk_top = {
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
    }

    while stack:
        cur, depth = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)

        # If this directory *is* a repo root, yield it and don't descend further.
        if (cur / ".git").exists():
            yield cur
            continue

        if depth >= max_depth:
            continue

        try:
            for child in cur.iterdir():
                if not child.is_dir():
                    continue
                name = child.name
                if depth == 0 and name in junk_top:
                    continue
                # Skip hidden dirs by default (except `_infra` pattern is handled in other sweeps;
                # here we only care about local worktrees).
                if name.startswith("."):
                    continue
                stack.append((child, depth + 1))
        except Exception:
            continue


def _dirty_paths(repo: Path, timeout_s: int = 8) -> tuple[list[str], str | None]:
    """Return a list of dirty file paths (relative to repo) from `git status --porcelain`.

    This includes modified, added, deleted (ignored), renamed (new path), and untracked files.
    Returns ([], None) when the repo is clean (not an error).
    """
    try:
        res = subprocess.run(
            ["git", "status", "--porcelain=v1", "-z"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=os.environ.copy(),
        )
    except Exception as e:
        return [], str(e)

    if res.returncode != 0:
        return [], (res.stderr or "").strip()[:300] or f"git status exit={res.returncode}"

    out = res.stdout or ""
    if not out:
        return [], None

    paths: list[str] = []
    for entry in out.split("\0"):
        if not entry:
            continue
        # Porcelain v1 format begins with XY status and a space, then path.
        # For renames, it can be "R  old -> new" (in -z form it's "R  old\0new\0" in some modes),
        # but we keep this parser simple and best-effort.
        if len(entry) >= 4 and entry[2] == " ":
            p = entry[3:]
        else:
            p = entry
        # Handle the "old -> new" display form (non -z) defensively.
        if " -> " in p:
            p = p.split(" -> ", 1)[1]
        p = p.strip()
        if not p:
            continue
        paths.append(p)

    # Dedup and drop obviously non-files.
    uniq = sorted(set(paths))
    return uniq, None


@dataclass(frozen=True)
class LocalDirtyFinding:
    repo_path: str
    engine: str
    type: str
    file: str | None
    line: int | None
    git_tracked: bool | None = None
    git_ignored: bool | None = None
    exposure: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "repo_path": self.repo_path,
            "engine": self.engine,
            "type": self.type,
            "file": self.file,
            "line": self.line,
            "git_tracked": self.git_tracked,
            "git_ignored": self.git_ignored,
            "exposure": self.exposure,
        }


def _parse_trufflehog_filesystem_json(stdout: str, repo_path: str) -> list[LocalDirtyFinding]:
    findings: list[LocalDirtyFinding] = []
    for line in (stdout or "").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except Exception:
            continue
        if not isinstance(obj, dict):
            continue
        detector = obj.get("DetectorName") or obj.get("Detector") or obj.get("DetectorType") or "unknown"

        file_path = None
        line_no = None
        sm = obj.get("SourceMetadata") or {}
        data = sm.get("Data") if isinstance(sm, dict) else {}
        fs = data.get("Filesystem") if isinstance(data, dict) else {}
        if isinstance(fs, dict):
            file_path = fs.get("file") or fs.get("path")
            lv = fs.get("line")
            if isinstance(lv, int):
                line_no = lv
            elif isinstance(lv, str):
                try:
                    line_no = int(lv)
                except Exception:
                    line_no = None

        findings.append(
            LocalDirtyFinding(
                repo_path=repo_path,
                engine="trufflehog",
                type=str(detector),
                file=str(file_path) if file_path is not None else None,
                line=line_no,
            )
        )
    return findings


def scan_dirty_worktrees(
    *,
    dev_root: Path | None,
    max_depth: int,
    only_dirty: bool,
    exclude_repo_globs: list[str] | None = None,
    check_upstream: bool = True,
    fetch_remotes: bool = False,
    max_paths_per_repo: int = 50,
    include_ignored_files: bool = False,
    max_concurrency: int,
    timeout_s: int,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()

    repos = sorted({str(p) for p in _iter_git_repos(root, max_depth=max_depth)})
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    if globs:
        repos = [r for r in repos if not any(fnmatch.fnmatch(r, g) for g in globs)]
    # When only_dirty, we filter inside _scan_one (single git status call per repo)
    # rather than calling _is_repo_dirty + _dirty_paths (two calls per repo).
    dirty_repos = repos

    try:
        max_concurrency = int(max_concurrency)
    except Exception:
        max_concurrency = 4
    max_concurrency = max(1, min(max_concurrency, 12))

    per_repo_timeout = max(30, min(int(timeout_s), 600))

    findings: list[LocalDirtyFinding] = []
    repo_meta: list[dict[str, Any]] = []
    ignored_paths_skipped_total = 0
    repos_with_ignored_skips = 0
    repos_with_truncated_paths = 0
    ignored_skipped_basenames: Counter[str] = Counter()
    ignored_skipped_lock = Lock()

    try:
        max_paths_per_repo = int(max_paths_per_repo)
    except Exception:
        max_paths_per_repo = 50
    max_paths_per_repo = max(1, min(max_paths_per_repo, 500))

    def _classify(
        repo: Path, repo_path: str, abs_path: str
    ) -> tuple[bool | None, bool | None, str | None, str]:
        rel = abs_path[len(repo_path.rstrip("/") + "/") :] if abs_path.startswith(repo_path.rstrip("/") + "/") else ""
        tracked = _git_check_tracked(repo, rel) if rel else None
        ignored = _git_check_ignored(repo, rel) if rel else None
        exposure = None
        if tracked is True:
            exposure = "tracked"
        elif ignored is True:
            exposure = "untracked_ignored"
        elif ignored is False:
            exposure = "untracked_not_ignored"
        return tracked, ignored, exposure, rel

    def _git_check_ignored(repo: Path, rel_path: str) -> bool | None:
        try:
            r = subprocess.run(
                ["git", "check-ignore", "-q", rel_path],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=5,
                env=os.environ.copy(),
            )
            if r.returncode == 0:
                return True
            if r.returncode == 1:
                return False
            return None
        except Exception:
            return None

    def _git_check_tracked(repo: Path, rel_path: str) -> bool | None:
        try:
            r = subprocess.run(
                ["git", "ls-files", "--error-unmatch", rel_path],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=5,
                env=os.environ.copy(),
            )
            if r.returncode == 0:
                return True
            if r.returncode == 1:
                return False
            return None
        except Exception:
            return None

    def _maybe_fetch(repo: Path) -> str | None:
        if not fetch_remotes:
            return None
        try:
            res = subprocess.run(
                ["git", "fetch", "--prune", "--quiet"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=min(30, per_repo_timeout),
                env=os.environ.copy(),
            )
            if res.returncode != 0:
                return (res.stderr or "").strip()[:300] or f"git fetch exit={res.returncode}"
            return None
        except Exception as e:
            return str(e)

    def _ahead_behind(repo: Path) -> tuple[int | None, int | None, str | None]:
        # Returns (ahead, behind, err). Values are None if no upstream.
        try:
            up = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=8,
                env=os.environ.copy(),
            )
            if up.returncode != 0:
                return None, None, None
            cnt = subprocess.run(
                ["git", "rev-list", "--left-right", "--count", "HEAD...@{u}"],
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=10,
                env=os.environ.copy(),
            )
            if cnt.returncode != 0:
                return None, None, (cnt.stderr or "").strip()[:200] or f"rev-list exit={cnt.returncode}"
            # output: "<left>\t<right>" where left=behind? Actually for HEAD...@{u}, left=commits unique to HEAD, right=unique to upstream.
            parts = (cnt.stdout or "").strip().split()
            if len(parts) >= 2:
                ahead = int(parts[0])
                behind = int(parts[1])
                return ahead, behind, None
            return None, None, "unexpected rev-list output"
        except Exception as e:
            return None, None, str(e)

    def _scan_one(repo_path: str) -> tuple[str, list[LocalDirtyFinding], list[str], dict | None]:
        """Returns (repo_path, findings, errors, repo_meta_entry_or_None)."""
        repo_errors: list[str] = []
        repo_findings: list[LocalDirtyFinding] = []

        repo = Path(repo_path)
        rel_paths, err = _dirty_paths(repo)
        if err:
            return repo_path, [], [f"git status failed for {repo_path}: {err}"], None
        if not rel_paths:
            return repo_path, [], [], None

        rel_paths_sorted = sorted(rel_paths)
        truncated = False
        if len(rel_paths_sorted) > max_paths_per_repo:
            rel_paths_sorted = rel_paths_sorted[:max_paths_per_repo]
            truncated = True

        abs_paths: list[str] = []
        skipped_ignored = 0
        skipped_ignored_sample: list[str] = []
        for rp in rel_paths_sorted:
            ap = repo / rp
            if not (ap.exists() and ap.is_file()):
                continue
            abs_p = str(ap)
            tracked, ignored, _exposure, _rel = _classify(repo, repo_path, abs_p)
            if ignored is True and tracked is False and not include_ignored_files:
                skipped_ignored += 1
                bn = Path(rp).name
                if bn and len(skipped_ignored_sample) < 5 and bn not in skipped_ignored_sample:
                    skipped_ignored_sample.append(bn)
                if bn:
                    with ignored_skipped_lock:
                        ignored_skipped_basenames[bn] += 1
                continue
            abs_paths.append(abs_p)
        if not abs_paths:
            return repo_path, [], [], None

        fetch_err = _maybe_fetch(repo) if check_upstream else None
        ahead, behind, ab_err = _ahead_behind(repo) if check_upstream else (None, None, None)
        meta_entry = {
            "repo_path": repo_path,
            "dirty_paths_count": len(rel_paths),
            "scanned_paths_count": len(abs_paths),
            "paths_truncated": truncated,
            "max_paths_per_repo": max_paths_per_repo,
            "ignored_paths_skipped": skipped_ignored,
            "ignored_paths_skipped_sample": skipped_ignored_sample,
            "ahead": ahead,
            "behind": behind,
            "upstream_checked": bool(check_upstream),
            "fetched": bool(fetch_remotes),
            "upstream_error": ab_err,
            "fetch_error": fetch_err,
        }

        cmd = [
            "trufflehog",
            "filesystem",
            "--json",
            "--no-update",
            "--no-verification",
            "--no-fail-on-scan-errors",
            f"--concurrency={max_concurrency}",
            *abs_paths,
        ]
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=per_repo_timeout,
                env=os.environ.copy(),
            )
        except Exception as e:
            return repo_path, [], [f"trufflehog filesystem failed for {repo_path}: {e}"], None

        # TruffleHog may exit non-zero on some errors; we tolerate and record stderr.
        if res.returncode not in (0, 183):
            stderr = (res.stderr or "").strip()
            if stderr:
                repo_errors.append(f"trufflehog filesystem error for {repo_path}: exit={res.returncode} stderr={stderr[:600]}")

        if res.stdout:
            parsed = _parse_trufflehog_filesystem_json(res.stdout, repo_path=repo_path)
            for f in parsed:
                # Skip findings in lock files -- they contain dependency hashes that
                # routinely trigger false positives (e.g. SentryToken on uv.lock).
                if f.file and Path(f.file).name in LOCK_FILE_BASENAMES:
                    continue
                if f.file:
                    tracked, ignored, exposure, _rel = _classify(repo, repo_path, f.file)
                    object.__setattr__(f, "git_tracked", tracked)
                    object.__setattr__(f, "git_ignored", ignored)
                    object.__setattr__(f, "exposure", exposure)
                repo_findings.append(f)

        return repo_path, repo_findings, repo_errors, meta_entry

    with ThreadPoolExecutor(max_workers=max_concurrency) as ex:
        futures = [ex.submit(_scan_one, r) for r in dirty_repos]
        for fut in as_completed(futures):
            try:
                _repo, fs, es, meta_entry = fut.result()
            except Exception as e:
                errors.append(f"dirty worktree scan worker crashed: {e}")
                continue
            if fs:
                findings.extend(fs)
            if es:
                errors.extend(es)
            if meta_entry:
                repo_meta.append(meta_entry)
                ignored_paths_skipped_total += meta_entry["ignored_paths_skipped"]
                if meta_entry["ignored_paths_skipped"] > 0:
                    repos_with_ignored_skips += 1
                if meta_entry["paths_truncated"]:
                    repos_with_truncated_paths += 1

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_discovered_count": len(repos),
            "repos_scanned_count": len(repo_meta),
            "only_dirty": bool(only_dirty),
            "max_depth": int(max_depth),
            "exclude_repo_globs": globs,
            "check_upstream": bool(check_upstream),
            "fetch_remotes": bool(fetch_remotes),
            "max_paths_per_repo": max_paths_per_repo,
            "include_ignored_files": bool(include_ignored_files),
        },
        "engine": {
            "name": "trufflehog",
            "mode": "filesystem",
            "max_concurrency": max_concurrency,
            "per_repo_timeout_s": per_repo_timeout,
        },
        "repos": repo_meta[:500],
        "findings": [f.to_dict() for f in findings[:500]],
        "summary": {
            "findings_total": len(findings),
            "ignored_paths_skipped_total": ignored_paths_skipped_total,
            "repos_with_ignored_paths_skipped": repos_with_ignored_skips,
            "repos_with_paths_truncated": repos_with_truncated_paths,
            "ignored_paths_skipped_top_basenames": ignored_skipped_basenames.most_common(15),
        },
        "errors": errors,
    }

    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2))
