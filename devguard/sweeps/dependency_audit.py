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
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now

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


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("invalid audit JSON schema")
    return value


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError("invalid audit JSON schema")
    return value


def _string(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("invalid audit JSON schema")
    return value


def _payload(raw: str) -> Any:
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("invalid audit JSON") from None
    if isinstance(data, dict) and "error" in data:
        raise ValueError("audit tool reported an error")
    return data


def parse_cargo_audit_json(raw: str) -> list[VulnSummary]:
    """Parse `cargo audit --json` output."""
    data = _payload(raw)
    vulns: list[VulnSummary] = []
    entries = _array(_object(_object(data).get("vulnerabilities")).get("list"))
    for entry in entries:
        v = _object(entry)
        advisory = _object(v.get("advisory"))
        pkg = _object(v.get("package"))
        _string(advisory.get("id"))
        _string(pkg.get("name"))
        _string(advisory.get("title", ""))
        categories = [_string(c) for c in _array(advisory.get("categories", []))]
        # Try explicit severity, then CVSS, then infer from categories
        sev_str = _normalize_severity(advisory.get("severity"))
        if sev_str == "unknown" and advisory.get("cvss"):
            sev_str = _normalize_severity(str(advisory["cvss"]).split("/")[0])
        if sev_str == "unknown":
            sev_str = _cargo_severity_from_categories(categories)
        # Informational advisories (unmaintained, etc.) are low severity
        if advisory.get("informational") is not None:
            sev_str = "low"
        vulns.append(
            VulnSummary(
                id=advisory.get("id", "UNKNOWN"),
                severity=sev_str,
                package=pkg.get("name", "unknown"),
                title=advisory.get("title", ""),
            )
        )
    return vulns


def parse_npm_audit_json(raw: str) -> list[VulnSummary]:
    """Parse `npm audit --json` output."""
    data = _payload(raw)
    vulns: list[VulnSummary] = []
    # npm v7+ audit JSON uses "vulnerabilities" dict keyed by package name
    vuln_dict = _object(_object(data).get("vulnerabilities"))
    if isinstance(vuln_dict, dict):
        for pkg_name, info in vuln_dict.items():
            info = _object(info)
            _string(info.get("name", pkg_name))
            sev_str = _normalize_severity(info.get("severity", "unknown"))
            # Extract title from via list (first dict entry) or fall back to name
            title = ""
            via = _array(info.get("via", []))
            for v_item in via:
                if isinstance(v_item, dict):
                    item_title = _string(v_item.get("title", ""))
                    if item_title and not title:
                        title = item_title
                else:
                    _string(v_item)
            vulns.append(
                VulnSummary(
                    id=str(info.get("name") or pkg_name),
                    severity=sev_str,
                    package=pkg_name,
                    title=title or pkg_name,
                )
            )
    return vulns


def parse_pip_audit_json(raw: str) -> list[VulnSummary]:
    """Parse `pip-audit --format=json` output."""
    data = _payload(raw)
    vulns: list[VulnSummary] = []
    # Current pip-audit wraps dependencies/fixes; older releases used a list.
    if isinstance(data, dict):
        for fix in _array(data.get("fixes")):
            _object(fix)
        data = data.get("dependencies")
    for item in _array(data):
        entry = _object(item)
        pkg = _string(entry.get("name"))
        if "skip_reason" in entry:
            raise ValueError("pip-audit skipped a dependency")
        _string(entry.get("version"))
        for item_vuln in _array(entry.get("vulns")):
            v = _object(item_vuln)
            vuln_id = _string(v.get("id"))
            desc = _string(v.get("description", ""))
            for key in ("aliases", "fix_versions"):
                for value in _array(v.get(key, [])):
                    _string(value)
            vulns.append(
                VulnSummary(
                    id=vuln_id,
                    severity=_normalize_severity(v.get("severity")),
                    package=pkg,
                    title=desc[:120] if desc else vuln_id,
                )
            )
    return vulns


def _normalize_severity(raw: str | None) -> str:
    """Normalize severity string to one of the standard buckets."""
    if raw is None:
        return "unknown"
    low = _string(raw).strip().lower()
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
    "pip-audit": (
        [
            "pip-audit",
            "--format=json",
            "--output=-",
            "--no-deps",
            "--disable-pip",
            "--strict",
            "-r",
            "requirements.txt",
        ],
        "pip-audit",
    ),
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
    engine_errors: list[str] = []

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

        if det.engine == "pip-audit" and not (repo / "requirements.txt").is_file():
            engine_errors.append(
                "pip-audit: unsupported input; export fully pinned requirements.txt"
            )
            continue

        try:
            proc = subprocess.run(
                argv,
                cwd=str(repo),
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            if proc.returncode not in (0, 1):
                engine_errors.append(f"{det.engine}: unexpected exit status {proc.returncode}")
                continue
            raw = proc.stdout or ""
        except subprocess.TimeoutExpired:
            engine_errors.append(f"{det.engine}: timeout")
            continue
        except Exception:
            engine_errors.append(f"{det.engine}: execution failed")
            continue

        parser = _ENGINE_PARSERS.get(det.engine)
        if parser is None:
            continue

        try:
            vulns = parser(raw)
        except (ValueError, TypeError, KeyError):
            # Tool output and exception messages may contain credentials or local data.
            engine_errors.append(f"{det.engine}: invalid or incomplete audit result")
            continue
        if proc.returncode == 1 and not vulns:
            engine_errors.append(f"{det.engine}: failure without vulnerability findings")
            continue
        result.engines_run.append(det.engine)
        for v in vulns:
            result.vulns.append(
                {
                    "id": v.id,
                    "severity": v.severity,
                    "package": v.package,
                    "title": v.title,
                    "engine": det.engine,
                }
            )
            counts[v.severity] += 1

    result.error = "; ".join(engine_errors) or None
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
        except Exception:
            return RepoAuditResult(repo_path=str(repo), error="dependency audit failed")

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
                "error": r.error,
                "vuln_count": len(r.vulns),
                "severity_counts": r.severity_counts,
                "vulns": r.vulns[:100],  # cap per repo
            }
            for r in results
            if r.engines_run or r.skipped_engines or r.error
        ][:200],
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
