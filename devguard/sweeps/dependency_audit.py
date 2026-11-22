"""Dependency audit sweep: scan local repos for known vulnerabilities in dependencies.

Discovers git repos under a dev root, detects language by manifest/lock files,
and runs the appropriate audit tool (cargo-audit, npm audit, pip-audit).
Produces a unified report with per-repo findings bucketed by severity.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import shutil
import subprocess
import tomllib
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cvss import CVSS3, CVSS4
from cvss.exceptions import CVSSError

from devguard.sweeps._common import default_dev_root as _default_dev_root
from devguard.sweeps._common import iter_git_repos
from devguard.sweeps._common import utc_now as _utc_now

# ---------------------------------------------------------------------------
# Language / engine detection
# ---------------------------------------------------------------------------

# Maps lock/manifest files to (language, engine_name).
_MANIFEST_MAP: list[tuple[str, str, str]] = [
    ("go.mod", "go", "osv-scanner"),
    ("Cargo.lock", "rust", "cargo-audit"),
    ("package-lock.json", "js", "npm-audit"),
    ("yarn.lock", "js", "osv-scanner"),
    ("pnpm-lock.yaml", "js", "osv-scanner"),
    ("uv.lock", "python", "osv-scanner"),
    ("requirements.txt", "python", "pip-audit"),
    ("poetry.lock", "python", "osv-scanner"),
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


_INPUT_FILES = tuple(
    dict.fromkeys(
        [name for name, _, _ in _MANIFEST_MAP]
        + ["Cargo.toml", "package.json", "pyproject.toml", "go.sum"]
    )
)


def resolve_package_roots(repo: Path, requested: list[str]) -> list[Path]:
    """Validate the entire explicit selection before any audit subprocess runs."""
    root = repo.resolve(strict=True)
    if not (root / ".git").exists():
        raise ValueError("--repo must be a local Git repository")
    resolved: list[Path] = []
    for value in requested:
        relative = Path(value)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("package roots must be relative paths without '..'")
        try:
            package = (root / relative).resolve(strict=True)
        except (OSError, RuntimeError):
            raise ValueError("package root does not exist or cannot be resolved") from None
        if not package.is_relative_to(root) or not package.is_dir():
            raise ValueError("package root must be a directory inside --repo")
        for name in _INPUT_FILES:
            candidate = package / name
            if candidate.is_symlink() and not candidate.resolve().is_relative_to(root):
                raise ValueError("package input symlink escapes --repo")
        detected = detect_engines(package)
        if not detected:
            raise ValueError("package root has no supported audit lockfile")
        if (
            any(d.engine == "npm-audit" for d in detected)
            and not (package / "package-lock.json").is_file()
        ):
            raise ValueError("explicit npm auditing requires package-lock.json")
        if (
            any(d.engine == "pip-audit" for d in detected)
            and not (package / "requirements.txt").is_file()
        ):
            raise ValueError("explicit Python auditing requires pinned requirements.txt")
        if package not in resolved:
            resolved.append(package)
    return resolved


def _locked_workspace_members(root: Path) -> set[Path]:
    """Members named in the workspace manifest and present as local packages in its lock."""
    try:
        workspace = tomllib.loads((root / "Cargo.toml").read_text()).get("workspace", {})
        if not workspace.get("members"):
            return set()
        packages = tomllib.loads((root / "Cargo.lock").read_text()).get("package", [])
        local_names = {p["name"] for p in packages if isinstance(p, dict) and "source" not in p}
        members: set[Path] = set()
        for field in ("members", "exclude"):
            for pattern in workspace.get(field, []):
                if (
                    not isinstance(pattern, str)
                    or Path(pattern).is_absolute()
                    or ".." in Path(pattern).parts
                ):
                    continue
                for member in root.glob(pattern):
                    manifest = member / "Cargo.toml"
                    if field == "exclude":
                        members.discard(member)
                    elif (
                        member != root
                        and manifest.is_file()
                        and manifest.resolve().is_relative_to(root.resolve())
                    ):
                        name = tomllib.loads(manifest.read_text()).get("package", {}).get("name")
                        if name in local_names:
                            members.add(member)
        return members
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
        KeyError,
        TypeError,
        AttributeError,
        ValueError,
    ):
        return set()


def _input_hashes(package: Path) -> dict[str, str | None]:
    return {
        name: hashlib.sha256((package / name).read_bytes()).hexdigest()
        if (package / name).is_file()
        else None
        for name in _INPUT_FILES
    }


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


def _cvss_severity(vector: str) -> str:
    try:
        model = CVSS4 if vector.startswith("CVSS:4.") else CVSS3
        return _normalize_severity(model(vector).severities()[0])
    except CVSSError:
        return "unknown"


def parse_osv_json(raw: str) -> list[VulnSummary]:
    entries = _array(_object(_payload(raw)).get("results"))
    findings = []
    for source in entries:
        for item in _array(_object(source).get("packages")):
            pkg = _string(_object(_object(item).get("package")).get("name"))
            for vuln in _array(item.get("vulnerabilities", [])):
                vid = _string(_object(vuln).get("id"))
                levels = [
                    _cvss_severity(_string(_object(score).get("score")))
                    for score in _array(vuln.get("severity", []))
                ]
                severity = next((s for s in SEVERITY_BUCKETS if s in levels), "unknown")
                if severity == "unknown":
                    severity = _normalize_severity(
                        _object(vuln.get("database_specific", {})).get("severity")
                    )
                findings.append(VulnSummary(vid, severity, pkg, _string(vuln.get("summary", vid))))
    return findings


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
            sev_str = _cvss_severity(_string(advisory["cvss"]))
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
    "osv-scanner": (["osv-scanner", "scan", "source", "--format", "json"], "osv-scanner"),
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
    "osv-scanner": parse_osv_json,
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
    inputs_before: dict[str, str | None] = field(default_factory=dict)
    inputs_after: dict[str, str | None] = field(default_factory=dict)
    engine_coverage: list[dict[str, str | None]] = field(default_factory=list)
    started_at: str | None = None
    finished_at: str | None = None


def _audit_repo(
    repo: Path,
    engines: list[str],
    timeout_s: int,
    explicit: bool = False,
    release_lock: bool = False,
) -> RepoAuditResult:
    """Run applicable audit tools on a single repo."""
    detected = [DetectedEngine("rust", "osv-scanner")] if release_lock else detect_engines(repo)
    result = RepoAuditResult(repo_path=str(repo))
    result.started_at = _utc_now()
    if explicit:
        result.inputs_before = _input_hashes(repo)
    counts: Counter[str] = Counter()
    engine_errors: list[str] = []

    present = {name for name in _INPUT_FILES if (repo / name).is_file()}
    for name, language in [
        ("Cargo.toml", "rust"),
        ("go.sum", "go"),
        ("package.json", "js"),
        ("pyproject.toml", "python"),
    ]:
        if name in present and not any(
            filename in present and lang == language for filename, lang, _ in _MANIFEST_MAP
        ):
            engine_errors.append(
                f"{name}: no auditable lockfile or pinned requirements in this directory"
            )

    for det in detected:
        if det.engine not in engines:
            result.skipped_engines.append(det.engine)
            continue

        cmd_spec = _ENGINE_COMMANDS.get(det.engine)
        if cmd_spec is None:
            continue
        argv, which_bin = cmd_spec
        if det.engine == "osv-scanner":
            argv = [*argv, "--lockfile", "Cargo.lock"] if release_lock else list(argv)
            for filename, _, engine in _MANIFEST_MAP:
                if engine == det.engine and (repo / filename).is_file():
                    argv.extend(["--lockfile", filename])
        if det.engine == "npm-audit":
            argv = ["npm", "--prefix", str(repo), "audit", "--json", "--ignore-scripts"]

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

    if explicit:
        result.inputs_after = _input_hashes(repo)
        if result.inputs_before != result.inputs_after:
            engine_errors.append("audit inputs changed during execution; result unknown")
    for det in detected:
        error = next((e for e in engine_errors if e.startswith(det.engine + ":")), None)
        result.engine_coverage.append(
            {
                "engine": det.engine,
                "status": "complete"
                if det.engine in result.engines_run
                else "error"
                if error
                else "skipped",
                "error": error,
            }
        )
    if result.skipped_engines:
        engine_errors.append("audit coverage incomplete; one or more engines skipped")
    result.finished_at = _utc_now()
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
    package_roots: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Audit dependencies across local repos for known vulnerabilities.

    Returns (report_dict, errors_list).
    """
    started_at = _utc_now()
    errors: list[str] = []
    root = dev_root if dev_root is not None else _default_dev_root()
    all_engines = engines or ["cargo-audit", "npm-audit", "pip-audit", "osv-scanner"]

    if package_roots is not None:
        if dev_root is None or not package_roots:
            raise ValueError(
                "explicit package roots require a local repository and nonempty selection"
            )
        repos = resolve_package_roots(root, package_roots)
    else:
        repos = sorted(iter_git_repos(root, max_depth=max_depth))
    globs = [g for g in (exclude_repo_globs or []) if isinstance(g, str) and g.strip()]
    if globs and package_roots is None:
        repos = [r for r in repos if not any(fnmatch.fnmatch(str(r), g) for g in globs)]

    repo_count = len(repos)
    without_inputs: list[str] = []
    if package_roots is None:
        packages: list[Path] = []
        ignored = {
            ".git",
            ".venv",
            "venv",
            "node_modules",
            "target",
            "vendor",
            "dist",
            "build",
            "__pycache__",
        }
        for repo in repos:
            initial_count = len(packages)
            workspace_members: set[Path] = set()

            def walk_error(exc: OSError) -> None:
                errors.append(f"{repo}: directory discovery failed ({type(exc).__name__})")

            for directory, dirs, files in os.walk(repo, onerror=walk_error):
                path = Path(directory)
                dirs[:] = sorted(
                    d for d in dirs if d not in ignored and not (path / d / ".git").exists()
                )
                inputs = set(files).intersection(_INPUT_FILES)
                if inputs == {"Cargo.toml"} and path in workspace_members:
                    continue
                if inputs:
                    if any((path / name).is_symlink() for name in _INPUT_FILES):
                        errors.append(f"{path}: symlinked package input requires explicit review")
                        continue
                    packages.append(path)
                    if {"Cargo.toml", "Cargo.lock"} <= inputs:
                        workspace_members.update(_locked_workspace_members(path))
            if len(packages) == initial_count:
                without_inputs.append(str(repo))
        repos = packages

    results: list[RepoAuditResult] = []

    def _run(repo: Path) -> RepoAuditResult:
        try:
            if package_roots is not None:
                return _audit_repo(repo, engines=all_engines, timeout_s=timeout_s, explicit=True)
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
        "schema_version": 1,
        "started_at": started_at,
        "generated_at": _utc_now(),
        "scope": {
            "dev_root": str(root),
            "repos_scanned": repo_count,
            "package_roots_discovered": len(repos),
            "repositories_without_auditable_inputs": without_inputs,
            "max_depth": max_depth,
            "exclude_repo_globs": globs,
            "engines_requested": all_engines,
            "package_roots_requested": package_roots,
            "package_roots_resolved": [str(p) for p in repos]
            if package_roots is not None
            else None,
        },
        "summary": {
            "repos_with_vulns": len(repos_with_vulns),
            "package_roots_complete": sum(bool(r.engines_run) and not r.error for r in results),
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
                "status": "unknown"
                if r.error or r.skipped_engines or not r.engines_run
                else "complete",
                "engine_coverage": r.engine_coverage,
                "started_at": r.started_at,
                "finished_at": r.finished_at,
                "inputs_before": r.inputs_before,
                "inputs_after": r.inputs_after,
                "input_changed": r.inputs_before != r.inputs_after,
                "vulns_omitted": 0,
                "vuln_count": len(r.vulns),
                "severity_counts": r.severity_counts,
                "vulns": r.vulns,
            }
            for r in results
            if r.engines_run or r.skipped_engines or r.error
        ],
        "truncation": {
            "repos_limit": None,
            "vulns_per_repo_limit": None,
            "repos_omitted": 0,
        },
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
