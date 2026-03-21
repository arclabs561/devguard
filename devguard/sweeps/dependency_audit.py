"""Dependency audit sweep: scan local repos for known vulnerabilities in dependencies.

Discovers git repos under a dev root, detects language by manifest/lock files,
and runs the appropriate audit tool (cargo-audit, npm audit, pip-audit).
Produces a unified report with per-repo findings bucketed by severity.
"""

from __future__ import annotations

import fnmatch
import json
import shutil
import subprocess
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos, utc_now as _utc_now


# ---------------------------------------------------------------------------
# Language / engine detection
# ---------------------------------------------------------------------------

# Maps lock/manifest files to (language, engine_name).
_MANIFEST_MAP: list[tuple[str, str, str]] = [
    ("Cargo.lock", "rust", "cargo-audit"),
    ("package-lock.json", "js", "npm-audit"),
    ("yarn.lock", "js", "npm-audit"),
    ("pnpm-lock.yaml", "js", "npm-audit"),
    ("uv.lock", "python", "pip-audit"),
    ("requirements.txt", "python", "pip-audit"),
    ("poetry.lock", "python", "pip-audit"),
]


@dataclass(frozen=True)
class DetectedEngine:
    language: str
    engine: str


def detect_engines(repo: Path) -> list[DetectedEngine]:
    """Detect which audit engines apply to a repo based on manifest files."""
    seen_engines: set[str] = set()
    results: list[DetectedEngine] = []
    for filename, lang, engine in _MANIFEST_MAP:
        if engine in seen_engines:
            continue
        if (repo / filename).exists():
            seen_engines.add(engine)
            results.append(DetectedEngine(language=lang, engine=engine))
    return results


# ---------------------------------------------------------------------------
# JSON output parsers
# ---------------------------------------------------------------------------

SEVERITY_BUCKETS = ("critical", "high", "medium", "low")


@dataclass
class VulnSummary:
    id: str
    severity: str  # one of SEVERITY_BUCKETS or "unknown"
    package: str
    title: str


def _cargo_severity_from_categories(categories: list[str]) -> str:
    """Infer severity from cargo-audit advisory categories when no explicit severity."""
    high_cats = {"memory-corruption", "memory-exposure", "code-execution"}
    medium_cats = {"denial-of-service", "crypto-failure", "thread-safety"}
    for cat in categories:
        if cat in high_cats:
            return "high"
    for cat in categories:
        if cat in medium_cats:
            return "medium"
    return "unknown"


def parse_cargo_audit_json(raw: str) -> list[VulnSummary]:
    """Parse `cargo audit --json` output."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    vulns: list[VulnSummary] = []
    for v in data.get("vulnerabilities", {}).get("list", []):
        advisory = v.get("advisory", {})
        pkg = v.get("package", {})
        # Try explicit severity, then CVSS, then infer from categories
        sev_str = _normalize_severity(advisory.get("severity"))
        if sev_str == "unknown" and advisory.get("cvss"):
            sev_str = _normalize_severity(str(advisory["cvss"]).split("/")[0])
        if sev_str == "unknown":
            sev_str = _cargo_severity_from_categories(advisory.get("categories", []))
        # Informational advisories (unmaintained, etc.) are low severity
        if advisory.get("informational") is not None:
            sev_str = "low"
        vulns.append(VulnSummary(
            id=advisory.get("id", "UNKNOWN"),
            severity=sev_str,
            package=pkg.get("name", "unknown"),
            title=advisory.get("title", ""),
        ))
    return vulns


def parse_npm_audit_json(raw: str) -> list[VulnSummary]:
    """Parse `npm audit --json` output."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    vulns: list[VulnSummary] = []
    # npm v7+ audit JSON uses "vulnerabilities" dict keyed by package name
    vuln_dict = data.get("vulnerabilities", {})
    if isinstance(vuln_dict, dict):
        for pkg_name, info in vuln_dict.items():
            if not isinstance(info, dict):
                continue
            sev_str = _normalize_severity(info.get("severity", "unknown"))
            # Extract title from via list (first dict entry) or fall back to name
            title = ""
            via = info.get("via", [])
            for v_item in via:
                if isinstance(v_item, dict) and v_item.get("title"):
                    title = v_item["title"]
                    break
            vulns.append(VulnSummary(
                id=info.get("name", pkg_name),
                severity=sev_str,
                package=pkg_name,
                title=title or pkg_name,
            ))
    return vulns


def parse_pip_audit_json(raw: str) -> list[VulnSummary]:
    """Parse `pip-audit --format=json` output."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    vulns: list[VulnSummary] = []
    # pip-audit outputs a list of dicts, each with "name", "version", "vulns"
    if isinstance(data, list):
        for entry in data:
            pkg = entry.get("name", "unknown")
            for v in entry.get("vulns", []):
                sev_str = _normalize_severity(v.get("fix_versions", [""])[0] if v.get("fix_versions") else "")
                # pip-audit doesn't always include severity; use id-based lookup
                vuln_id = v.get("id", "UNKNOWN")
                desc = v.get("description", "")
                # Attempt to extract severity from aliases or description
                aliases = v.get("aliases", [])
                sev_str = _normalize_severity(v.get("severity", "unknown"))
                vulns.append(VulnSummary(
                    id=vuln_id,
                    severity=sev_str,
                    package=pkg,
                    title=desc[:120] if desc else vuln_id,
                ))
    return vulns


def _normalize_severity(raw: str | None) -> str:
    """Normalize severity string to one of the standard buckets."""
    if not raw:
        return "unknown"
    low = raw.strip().lower()
    if low in SEVERITY_BUCKETS:
        return low
    # Map common aliases
    if low in ("info", "informational", "negligible", "none"):
        return "low"
    if low in ("moderate", "mod"):
        return "medium"
    return "unknown"


# ---------------------------------------------------------------------------
# Per-repo audit runner
# ---------------------------------------------------------------------------

_ENGINE_COMMANDS: dict[str, tuple[list[str], str | None]] = {
    # (argv, which_binary_to_check)
    "cargo-audit": (["cargo", "audit", "--json"], "cargo-audit"),
    "npm-audit": (["npm", "audit", "--json"], "npm"),
    "pip-audit": (["pip-audit", "--format=json", "--output=-"], "pip-audit"),
}

_ENGINE_PARSERS: dict[str, Any] = {
    "cargo-audit": parse_cargo_audit_json,
    "npm-audit": parse_npm_audit_json,
    "pip-audit": parse_pip_audit_json,
}


@dataclass
class RepoAuditResult:
    repo_path: str
    engines_run: list[str] = field(default_factory=list)
    vulns: list[dict[str, str]] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    skipped_engines: list[str] = field(default_factory=list)
    error: str | None = None


def _audit_repo(
    repo: Path,
    engines: list[str],
    timeout_s: int,
) -> RepoAuditResult:
    """Run applicable audit tools on a single repo."""
    detected = detect_engines(repo)
    result = RepoAuditResult(repo_path=str(repo))
    counts: Counter[str] = Counter()

    for det in detected:
        if det.engine not in engines:
            result.skipped_engines.append(det.engine)
            continue

        cmd_spec = _ENGINE_COMMANDS.get(det.engine)
        if cmd_spec is None:
            continue
        argv, which_bin = cmd_spec

        # Check tool availability
        if which_bin and not shutil.which(which_bin):
            result.skipped_engines.append(f"{det.engine} (not installed)")
            continue

        try:
            proc = subprocess.run(
                argv,
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            # cargo-audit and npm audit return non-zero when vulns are found;
            # that is expected -- we still parse stdout.
            raw = proc.stdout or ""
        except subprocess.TimeoutExpired:
            result.skipped_engines.append(f"{det.engine} (timeout)")
            continue
        except Exception as exc:
            result.skipped_engines.append(f"{det.engine} ({exc})")
            continue

        parser = _ENGINE_PARSERS.get(det.engine)
        if parser is None:
            continue

        vulns = parser(raw)
        result.engines_run.append(det.engine)
        for v in vulns:
            result.vulns.append({
                "id": v.id,
                "severity": v.severity,
                "package": v.package,
                "title": v.title,
                "engine": det.engine,
            })
            counts[v.severity] += 1

    result.severity_counts = dict(counts)
    return result


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def audit_dependencies(
    *,
    dev_root: Path | None = None,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    engines: list[str] | None = None,
    max_concurrency: int = 4,
    timeout_s: int = 120,
) -> tuple[dict[str, Any], list[str]]:
    """Audit dependencies across local repos for known vulnerabilities.

    Returns (report_dict, errors_list).
    """
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    all_engines = engines or ["cargo-audit", "npm-audit", "pip-audit"]

    repos = sorted(iter_git_repos(root, max_depth=max_depth))
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    if globs:
        repos = [r for r in repos if not any(fnmatch.fnmatch(str(r), g) for g in globs)]

    results: list[RepoAuditResult] = []

    def _run(repo: Path) -> RepoAuditResult:
        try:
            return _audit_repo(repo, engines=all_engines, timeout_s=timeout_s)
        except Exception as exc:
            return RepoAuditResult(repo_path=str(repo), error=str(exc))

    with ThreadPoolExecutor(max_workers=max_concurrency) as pool:
        futures = {pool.submit(_run, r): r for r in repos}
        for fut in as_completed(futures):
            res = fut.result()
            results.append(res)
            if res.error:
                errors.append(f"{res.repo_path}: {res.error}")

    # Sort by severity (critical first), then by vuln count descending
    def _sort_key(r: RepoAuditResult) -> tuple[int, int, str]:
        crit = r.severity_counts.get("critical", 0)
        high = r.severity_counts.get("high", 0)
        total = len(r.vulns)
        return (-crit, -high, -total, r.repo_path)  # type: ignore[return-value]

    results.sort(key=_sort_key)

    # Aggregate severity counts
    total_counts: Counter[str] = Counter()
    for r in results:
        total_counts.update(r.severity_counts)

    repos_with_vulns = [r for r in results if r.vulns]

    report: dict[str, Any] = {
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": len(repos),
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
            "engines_requested": all_engines,
        },
        "summary": {
            "repos_with_vulns": len(repos_with_vulns),
            "total_vulns": sum(len(r.vulns) for r in results),
            "severity_counts": {s: total_counts.get(s, 0) for s in SEVERITY_BUCKETS},
            "unknown_severity": total_counts.get("unknown", 0),
        },
        "repos": [
            {
                "repo_path": r.repo_path,
                "engines_run": r.engines_run,
                "skipped_engines": r.skipped_engines,
                "vuln_count": len(r.vulns),
                "severity_counts": r.severity_counts,
                "vulns": r.vulns[:100],  # cap per repo
            }
            for r in results
            if r.vulns or r.skipped_engines
        ][:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
