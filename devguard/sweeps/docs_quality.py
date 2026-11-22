"""Docs quality sweep: Vale and readcost over Markdown docs in local repos.

Findings are advisory prose candidates. Coverage is the load-bearing part:
a missing tool, a timeout, an unconfigured Vale, or unparsable output marks
the repo incomplete instead of reporting it clean.
"""

from __future__ import annotations

import fnmatch
import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from devguard.sweeps._common import contained_file, iter_git_repos, utc_now

_MAX_FINDINGS_PER_REPO = 50
_MAX_FILE_BYTES = 256 * 1024
TOOLS = ("vale", "readcost")


def _tracked_docs(
    repo: Path, include_changelog: bool, limit: int
) -> tuple[list[str], list[str], list[str]]:
    proc = subprocess.run(
        ["git", "-C", str(repo), "ls-files", "-z", "--", "README.md", "docs", "CHANGELOG.md"],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git ls-files failed (exit {proc.returncode})")
    selected: list[str] = []
    oversized: list[str] = []
    for rel in sorted(p for p in proc.stdout.decode("utf-8", "replace").split("\0") if p):
        if rel == "CHANGELOG.md" and not include_changelog:
            continue
        if rel.startswith("docs/") and not rel.endswith(".md"):
            continue
        path = repo / rel
        if contained_file(path, repo):
            (oversized if path.stat().st_size > _MAX_FILE_BYTES else selected).append(rel)
    # README first so the bound never drops it.
    selected.sort(key=lambda r: (r != "README.md", r))
    limit = max(1, limit)
    return selected[:limit], selected[limit:], oversized


def _run(cmd: list[str], cwd: Path, timeout_s: int) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ, READCOST_NO_DOWNLOAD="1", NO_COLOR="1")
    return subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout_s, check=False
    )


def _vale_has_styles(repo: Path, timeout_s: int) -> bool:
    """Vale with no configured styles prints `{}`: an empty result, not a pass."""
    proc = _run(["vale", "ls-config"], repo, timeout_s)
    if proc.returncode != 0:
        return False
    try:
        cfg = json.loads(proc.stdout)
    except ValueError:
        return False
    return bool(cfg.get("GBaseStyles") or cfg.get("SBaseStyles") or cfg.get("Checks"))


def _direct(
    repo: Path, files: list[str], timeout_s: int, tools: tuple[str, ...]
) -> tuple[list[dict], list[str], set[str]]:
    findings: list[dict] = []
    incomplete: list[str] = []
    covered: dict[str, set[str]] = {tool: set() for tool in tools}
    for tool in tools:
        if not shutil.which(tool):
            incomplete.append(f"{tool}: not installed")
            continue
        try:
            if tool == "vale":
                if not _vale_has_styles(repo, timeout_s):
                    incomplete.append("vale: no styles configured for this repo")
                    continue
                proc = _run(["vale", "--output=JSON", "--no-exit", *files], repo, timeout_s)
            else:
                proc = _run(
                    ["readcost", "check", "--fail-on", "never", "--output", "json", *files],
                    repo,
                    timeout_s,
                )
        except subprocess.TimeoutExpired:
            incomplete.append(f"{tool}: timed out after {timeout_s}s")
            continue
        except OSError as exc:
            incomplete.append(f"{tool}: could not run ({exc.__class__.__name__})")
            continue
        if proc.returncode != 0:
            detail = " ".join(proc.stderr.split())[:200]
            incomplete.append(f"{tool}: exit {proc.returncode}" + (f": {detail}" if detail else ""))
            continue
        try:
            data = json.loads(proc.stdout)
            if tool == "vale":
                for path, alerts in data.items():
                    for a in alerts:
                        findings.append(
                            {
                                "tool": "vale",
                                "file": os.path.relpath(path, repo.resolve())
                                if os.path.isabs(path)
                                else path,
                                "line": a["Line"],
                                "rule": a["Check"],
                                "message": a["Message"],
                            }
                        )
                covered[tool].update(files)
            else:
                if not isinstance(data, list):
                    raise ValueError("expected per-file results")
                for entry in data:
                    rel = (
                        os.path.relpath(entry["path"], repo.resolve())
                        if os.path.isabs(entry["path"])
                        else entry["path"]
                    )
                    if rel in files:
                        covered[tool].add(rel)
                    for item in entry["findings"]:
                        findings.append(
                            {
                                "tool": "readcost",
                                "file": os.path.relpath(entry["path"], repo)
                                if os.path.isabs(entry["path"])
                                else entry["path"],
                                "line": item["line"],
                                "rule": item["feature"],
                                "message": item["message"],
                            }
                        )
                for rel in sorted(set(files) - covered[tool]):
                    incomplete.append(f"readcost: missing result for {rel}")
        except (ValueError, KeyError, TypeError, AttributeError):
            covered[tool].clear()
            incomplete.append(f"{tool}: unreadable JSON output")
    return findings, incomplete, set(files).intersection(*covered.values())


def _wrapper(
    repo: Path, files: list[str], wrapper: str, timeout_s: int
) -> tuple[list[dict], list[str], set[str]]:
    """Run a docs-check style wrapper: `<wrapper> --json files...` -> list of per-file results."""
    try:
        # The wrapper runs both tools per file, so scale the bound by file count.
        proc = _run([wrapper, "--json", *files], repo, timeout_s * max(1, len(files)))
    except subprocess.TimeoutExpired:
        return [], [f"{wrapper}: timed out"], set()
    except OSError as exc:
        return [], [f"{wrapper}: could not run ({exc.__class__.__name__})"], set()
    findings: list[dict] = []
    incomplete: list[str] = []
    seen: set[str] = set()
    failed: set[str] = set()
    try:
        data = json.loads(proc.stdout)
        if not isinstance(data, list):
            raise ValueError("expected per-file results")
        for result in data:
            path = result["path"]
            rel = os.path.relpath(path, repo.resolve()) if os.path.isabs(path) else path
            seen.add(rel)
            if result["unavailable"]:
                failed.add(rel)
            for item in result["findings"]:
                findings.append({**item, "file": rel})
            incomplete.extend(f"{rel}: {u}" for u in result["unavailable"])
    except (ValueError, KeyError, TypeError):
        return [], [f"{wrapper}: unreadable JSON output (exit {proc.returncode})"], set()
    for rel in sorted(set(files) - seen):
        incomplete.append(f"{wrapper}: missing result for {rel}")
    if proc.returncode and not incomplete and not (proc.returncode == 1 and findings):
        incomplete.append(f"{wrapper}: unexplained exit {proc.returncode}")
        failed.update(files)
    return findings, incomplete, (set(files) & seen) - failed


def _resolve_engine(engine: str, wrapper: str) -> str:
    if engine == "auto":
        return "wrapper" if shutil.which(wrapper) else "direct"
    if engine not in ("wrapper", "direct", *TOOLS):
        raise ValueError(f"unknown docs_quality engine: {engine}")
    return engine


def audit_docs_quality(
    *,
    dev_root: Path,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    repo_names: list[str] | None = None,
    include_changelog: bool = False,
    max_files_per_repo: int = 20,
    engine: str = "auto",
    wrapper: str = "docs-check",
    timeout_s: int = 120,
    max_concurrency: int = 2,
) -> tuple[dict[str, Any], list[str]]:
    """Check Markdown docs per repo; return (report, errors)."""
    resolved = _resolve_engine(engine, wrapper)
    globs = exclude_repo_globs or []
    repos = [
        r
        for r in sorted(iter_git_repos(dev_root, max_depth=max_depth))
        if not any(fnmatch.fnmatch(str(r), g) for g in globs)
        and (not repo_names or r.name in repo_names)
    ]

    def one(repo: Path) -> dict[str, Any]:
        entry: dict[str, Any] = {"repo_path": str(repo), "files": [], "findings": []}
        try:
            files, limited, oversized = _tracked_docs(repo, include_changelog, max_files_per_repo)
        except (RuntimeError, OSError, subprocess.TimeoutExpired) as exc:
            entry["incomplete"] = [f"file discovery failed: {exc}"]
            return entry
        entry.update(files=files, omitted_by_limit=limited, oversized=oversized, files_checked=[])
        if not files:
            entry["incomplete"] = []
            return entry
        if resolved == "wrapper":
            raw, incomplete, covered = _wrapper(repo, files, wrapper, timeout_s)
        else:
            raw, incomplete, covered = _direct(
                repo, files, timeout_s, (resolved,) if resolved in TOOLS else TOOLS
            )
        entry["files_checked"] = sorted(covered)
        entry["incomplete"] = incomplete
        entry["findings_total"] = len(raw)
        entry["findings_omitted"] = max(0, len(raw) - _MAX_FINDINGS_PER_REPO)
        entry["findings"] = [
            {
                "check": f"docs_quality:{f['tool']}/{f['rule']}",
                "severity": "low",
                "file": f["file"],
                "line": f["line"],
                "message": f"{f['file']}:{f['line']}: {' '.join(str(f['message']).split())[:240]}",
            }
            for f in raw[:_MAX_FINDINGS_PER_REPO]
        ]
        return entry

    with ThreadPoolExecutor(max_workers=max(1, min(max_concurrency, 8))) as pool:
        results = list(pool.map(one, repos))

    errors = [
        f"{Path(r['repo_path']).name}: {msg}" for r in results for msg in r.get("incomplete", [])
    ]
    checked = [r for r in results if r["files"]]
    selected = sum(len(r["files"]) for r in results)
    limited = sum(len(r.get("omitted_by_limit", [])) for r in results)
    oversized = sum(len(r.get("oversized", [])) for r in results)
    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "scope": {
            "dev_root": str(dev_root),
            "repos_scanned": len(repos),
            "repos_with_docs": len(checked),
            "engine": resolved,
            "include_changelog": include_changelog,
        },
        "summary": {
            "files_checked": sum(len(r.get("files_checked", [])) for r in results),
            "files_selected": selected,
            "files_eligible": selected + limited,
            "files_omitted_by_limit": limited,
            "files_oversized": oversized,
            "total_findings": sum(r.get("findings_total", 0) for r in checked),
            "repos_with_findings": sum(1 for r in checked if r.get("findings_total")),
            "incomplete_repos": sum(1 for r in results if r.get("incomplete")),
            "coverage_complete": not errors and not limited and not oversized,
        },
        "repos": sorted(
            results,
            key=lambda r: (-r.get("findings_total", 0), r["repo_path"]),
        ),
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
