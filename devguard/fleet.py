"""Sweep many repositories in parallel, with cached clones and cached results.

`devguard sweep --repo` handles one repository per call. This module runs the
same sweeps over a list of repositories: an owner's GitHub inventory, explicit
URLs or `owner/name` slugs, or local checkouts under a directory.

Remote repositories are cloned once into a cache directory and refreshed with a
shallow fetch on later runs. A repository's result is cached under a key made of
its head commit, the devguard version, the sweep selection, the spec contents
and the set of external scanners installed, so an unchanged repository costs one
`git fetch` and no scan.

Each repository is scanned by a child `devguard sweep` process. That keeps the
single-repo code path the only implementation of every sweep, gives each scan
its own working directory (sweeps write report files relative to the cwd), and
confines a crash or an out-of-memory kill to the one repository that caused it.
"""

from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from devguard import __version__
from devguard.finding_evidence import finding_id, locations, references

# Sweeps whose subject is one repository. Workstation-wide sweeps (ssh_key_audit,
# credential_file_audit, git_identity_audit) would repeat the same work for every
# repository, and the rest need a network service or an API key.
REPO_SCOPED_SWEEPS: tuple[str, ...] = (
    "local_dev",
    "local_history_secrets",
    "exec_config_audit",
    "repo_lint",
    "gitignore_audit",
    "repo_hygiene",
    "dependency_audit",
    "cargo_publish_audit",
    "ai_editor_config_audit",
    "publish_audit",
    "pre_commit_audit",
    "mcp_security_audit",
    "publish_workflow_audit",
)

# External scanners whose presence changes what a sweep can find.
_RESULT_AFFECTING_TOOLS = (
    "gitleaks",
    "trufflehog",
    "cargo-audit",
    "osv-scanner",
    "pip-audit",
    "npm",
    "gh",
    # docs_quality reports a repository incomplete when either is missing, so
    # a result cached before one was installed must not be served afterwards.
    "vale",
    "readcost",
)

THRESHOLDS = ("critical", "high", "medium", "low", "info")
SEVERITIES = (*THRESHOLDS, "unknown")
_SEVERITY_ALIASES = {"error": "high", "warning": "medium", "warn": "medium", "note": "info"}
_SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES)}

_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+$")
_GH_FIELDS = "nameWithOwner,url,visibility,isArchived,isFork,isEmpty,pushedAt"


@dataclass(frozen=True)
class RepoRef:
    """One repository to scan: a remote to clone or a local checkout."""

    name: str
    url: str | None = None
    path: Path | None = None
    visibility: str = ""
    archived: bool = False
    fork: bool = False
    empty: bool = False
    pushed_at: str = ""

    @property
    def identity(self) -> str:
        return str(self.path.resolve()) if self.path is not None else self.name


@dataclass
class RepoResult:
    name: str
    url: str | None
    head: str | None
    visibility: str
    status: str  # scanned | cached | error
    exit_code: int
    seconds: float
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    reports: dict[str, Any] = field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        tally = Counter(f["severity"] for f in self.findings)
        return {s: tally.get(s, 0) for s in SEVERITIES}

    @property
    def worst(self) -> int:
        return min((_SEVERITY_RANK[f["severity"]] for f in self.findings), default=len(SEVERITIES))


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    text = _SEVERITY_ALIASES.get(text, text)
    return text if text in _SEVERITY_RANK else "info"


def severity_at_least(severity: str, threshold: str) -> bool:
    return threshold == "info" or _SEVERITY_RANK[severity] <= _SEVERITY_RANK[threshold]


# ---------------------------------------------------------------------------
# Cache locations
# ---------------------------------------------------------------------------


def cache_root() -> Path:
    """$DEVGUARD_CACHE_DIR, else $XDG_CACHE_HOME/devguard, else ~/.cache/devguard."""
    if explicit := os.environ.get("DEVGUARD_CACHE_DIR"):
        return Path(explicit).expanduser()
    base = os.environ.get("XDG_CACHE_HOME")
    return (Path(base).expanduser() if base else Path.home() / ".cache") / "devguard"


def _dir_size(path: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.lstat(os.path.join(root, name)).st_size
    return total


def cache_info(root: Path | None = None) -> dict[str, Any]:
    root = root or cache_root()
    repos_dir, results_dir = root / "repos", root / "results"
    repos = sorted(p.parent for p in repos_dir.glob("*/*/.git")) if repos_dir.is_dir() else []
    results = list(results_dir.glob("*.json")) if results_dir.is_dir() else []
    return {
        "path": str(root),
        "repos": len(repos),
        "repo_bytes": _dir_size(repos_dir) if repos_dir.is_dir() else 0,
        "results": len(results),
        "result_bytes": sum(p.stat().st_size for p in results),
    }


def clear_cache(root: Path | None = None, *, results_only: bool = False) -> None:
    root = root or cache_root()
    shutil.rmtree(root / "results", ignore_errors=True)
    if not results_only:
        shutil.rmtree(root / "repos", ignore_errors=True)


# ---------------------------------------------------------------------------
# Repository selection
# ---------------------------------------------------------------------------


def parse_target(target: str) -> RepoRef:
    """Turn a URL, an `owner/name` slug or a local path into a RepoRef."""
    text = target.strip()
    local = Path(text).expanduser()
    if local.exists():
        resolved = local.resolve()
        if not (resolved / ".git").exists():
            raise ValueError(f"{text}: not a git repository")
        return RepoRef(name=resolved.name, path=resolved)
    if text.startswith(("https://", "http://", "ssh://", "git@", "file://")):
        tail = text.rstrip("/").removesuffix(".git")
        parts = re.split(r"[/:]", tail)
        name = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
        return RepoRef(name=name, url=text)
    if _SLUG_RE.match(text):
        return RepoRef(name=text, url=f"https://github.com/{text}")
    raise ValueError(f"{text}: not a local repository, a URL or an owner/name slug")


def list_owner_repos(owner: str | None = None, *, limit: int = 5000) -> list[RepoRef]:
    """List an owner's repositories through the authenticated GitHub CLI.

    With no owner, lists the signed-in user's repositories, private ones included.
    """
    if shutil.which("gh") is None:
        raise ValueError("gh (GitHub CLI) not found; install it or pass repositories explicitly")
    args = ["gh", "repo", "list"]
    if owner:
        args.append(owner)
    args += ["--limit", str(limit), "--json", _GH_FIELDS]
    done = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if done.returncode != 0:
        raise ValueError(done.stderr.strip() or "gh repo list failed")
    try:
        rows = json.loads(done.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise ValueError(f"gh repo list returned invalid JSON: {exc}") from None
    return [
        RepoRef(
            name=row["nameWithOwner"],
            url=row.get("url") or f"https://github.com/{row['nameWithOwner']}",
            visibility=str(row.get("visibility") or "").lower(),
            archived=bool(row.get("isArchived")),
            fork=bool(row.get("isFork")),
            empty=bool(row.get("isEmpty")),
            pushed_at=str(row.get("pushedAt") or ""),
        )
        for row in rows
    ]


def filter_repos(
    repos: list[RepoRef],
    *,
    include_archived: bool = False,
    include_forks: bool = False,
    visibility: str | None = None,
    pushed_since: str | None = None,
    match: list[str] | None = None,
    exclude: list[str] | None = None,
    limit: int | None = None,
) -> list[RepoRef]:
    """Apply inventory filters. Globs match the full name and the bare repo name.

    Attributes a ref does not carry (a URL given by hand has no visibility or
    push date) never exclude it.
    """

    def globbed(ref: RepoRef, globs: list[str]) -> bool:
        short = ref.name.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(ref.name, g) or fnmatch.fnmatch(short, g) for g in globs)

    kept = []
    for ref in repos:
        if ref.empty:
            continue
        if ref.archived and not include_archived:
            continue
        if ref.fork and not include_forks:
            continue
        if visibility and ref.visibility and ref.visibility != visibility.lower():
            continue
        if pushed_since and ref.pushed_at and ref.pushed_at[:10] < pushed_since:
            continue
        if match and not globbed(ref, match):
            continue
        if exclude and globbed(ref, exclude):
            continue
        kept.append(ref)
    # Most recently pushed first, so --limit keeps the active repositories. The
    # sort is stable: refs with no push date keep their given order at the end.
    kept.sort(key=lambda r: r.pushed_at, reverse=True)
    unique: list[RepoRef] = []
    seen: set[str] = set()
    for ref in kept:
        identity = ref.identity
        if identity not in seen:
            seen.add(identity)
            unique.append(ref)
    names = Counter(ref.name for ref in unique)
    selected = unique[:limit] if limit else unique
    return [
        replace(ref, name=ref.identity) if ref.path is not None and names[ref.name] > 1 else ref
        for ref in selected
    ]


# ---------------------------------------------------------------------------
# Clone cache
# ---------------------------------------------------------------------------


def _git(args: list[str], cwd: Path | None, timeout: int) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout, env=env
    )


def _git_ok(args: list[str], cwd: Path | None, timeout: int) -> str:
    done = _git(args, cwd, timeout)
    if done.returncode != 0:
        detail = (done.stderr.strip().splitlines() or ["no output"])[-1]
        raise RuntimeError(f"git {args[0]} failed: {detail[:300]}")
    return done.stdout.strip()


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Serialize work on one cached clone across threads and devguard processes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as handle:
        try:
            import fcntl

            fcntl.flock(handle, fcntl.LOCK_EX)
        except ImportError:  # Windows: no advisory lock; concurrent runs may reclone.
            pass
        yield


def _path_component(part: str) -> str:
    """One directory name for the cache: no separators, and never `.`/`..` or hidden."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", part).lstrip(".")
    return safe or "_"


def cached_clone_path(ref: RepoRef, root: Path | None = None) -> Path:
    """Where *ref*'s clone lives. Always two levels below `<root>/repos`.

    The name comes from a URL or a file the user did not necessarily write, and
    a stale clone at this path is deleted before recloning, so a name such as
    `../..` must not be able to point outside the cache.
    """
    safe = [_path_component(part) for part in ref.name.split("/") if part]
    while len(safe) < 2:
        safe.insert(0, "_")
    return (root or cache_root()) / "repos" / safe[-2] / safe[-1]


def sync_repo(
    ref: RepoRef,
    *,
    root: Path | None = None,
    full_history: bool = False,
    refresh: bool = True,
    timeout: int = 600,
) -> tuple[Path, str]:
    """Make the cached clone match the remote's default branch; return (path, head).

    A missing or unreadable clone is created fresh. An existing one is updated
    with one fetch, shallow unless *full_history*. With *refresh* false an
    existing clone is used as it is, with no network access.
    """
    if ref.path is not None:
        return ref.path, _git_ok(["rev-parse", "HEAD"], ref.path, 30)
    if not ref.url:
        raise RuntimeError(f"{ref.name}: no URL or path")
    dest = cached_clone_path(ref, root)
    with _locked(dest.parent / f".{dest.name}.lock"):
        usable = (dest / ".git").exists() and _git(["rev-parse", "HEAD"], dest, 30).returncode == 0
        if usable and _git_ok(["remote", "get-url", "origin"], dest, 30) != ref.url:
            usable = False
        if not usable:
            shutil.rmtree(dest, ignore_errors=True)
            dest.parent.mkdir(parents=True, exist_ok=True)
            depth = [] if full_history else ["--depth", "1"]
            _git_ok(["clone", "--quiet", "--no-tags", *depth, ref.url, str(dest)], None, timeout)
        elif refresh:
            shallow = _git_ok(["rev-parse", "--is-shallow-repository"], dest, 30) == "true"
            if full_history and shallow:
                _git_ok(["fetch", "--quiet", "--no-tags", "--unshallow", "origin"], dest, timeout)
            depth = [] if full_history else ["--depth", "1"]
            _git_ok(["fetch", "--quiet", "--no-tags", *depth, "origin", "HEAD"], dest, timeout)
            _git_ok(["reset", "--quiet", "--hard", "FETCH_HEAD"], dest, 120)
            _git_ok(["clean", "-fdxq"], dest, 120)
        return dest, _git_ok(["rev-parse", "HEAD"], dest, 30)


def _worktree_dirty(path: Path) -> bool:
    # Filesystem sweeps can see ignored files and empty directories. Without
    # exclude rules, ls-files includes both and collapses untracked subtrees.
    extra = _git(["ls-files", "--others", "--directory"], path, 60)
    if extra.returncode or extra.stdout:
        return True
    tracked = _git(["status", "--porcelain", "--untracked-files=no"], path, 60)
    return tracked.returncode != 0 or bool(tracked.stdout)


# ---------------------------------------------------------------------------
# Result cache
# ---------------------------------------------------------------------------


def result_key(
    *, head: str, sweeps: list[str], spec_path: Path | None, full_history: bool, name: str
) -> str:
    spec_digest = ""
    if spec_path is not None and spec_path.is_file():
        spec_digest = hashlib.sha256(spec_path.read_bytes()).hexdigest()
    material = {
        "finding_evidence_format": 1,
        "cache_format": 5,  # Recheck reports produced before coverage and severity checks.
        "devguard": __version__,
        "repo": name,
        "head": head,
        "sweeps": sorted(sweeps),
        **({"pr_token_permissions": 1} if "publish_workflow_audit" in sweeps else {}),
        "spec": spec_digest,
        "full_history": full_history,
        "tools": [t for t in _RESULT_AFFECTING_TOOLS if shutil.which(t)],
    }
    return hashlib.sha256(json.dumps(material, sort_keys=True).encode()).hexdigest()


def _read_cached_result(root: Path, key: str) -> dict[str, Any] | None:
    try:
        data = json.loads((root / "results" / f"{key}.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("exit_code") not in (0, 2):
        return None
    reports = data.get("reports")
    return data if isinstance(reports, dict) and reports else None


def _write_cached_result(root: Path, key: str, payload: dict[str, Any]) -> None:
    results = root / "results"
    results.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=results, suffix=".tmp")
    with os.fdopen(fd, "w") as handle:
        json.dump(payload, handle)
    os.replace(tmp, results / f"{key}.json")


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


def _one_finding(sweep: str, raw: Any, repo_path: str = "") -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {"sweep": sweep, "check": sweep, "severity": "info", "file": "", "message": str(raw)}
    check = (
        raw.get("check")
        or raw.get("check_id")
        or raw.get("rule")
        or raw.get("reason")
        or raw.get("kind")
        or sweep
    )
    points = locations(raw, repo_path)
    file, line = points[0] if points else ("", None)
    files = [f"{path}:{n}" if n else path for path, n in points]
    message = raw.get("message") or raw.get("detail") or raw.get("reason") or str(check)
    # A deny-glob or oversized-blob hit carries no severity; treat it as medium.
    default = "medium" if sweep == "local_dev" else "info"
    return {
        "sweep": sweep,
        "check": str(check),
        "severity": normalize_severity(raw.get("severity") or raw.get("level") or default),
        "file": (f"{file}:{line}" if isinstance(line, int) else str(file))
        if file
        else next(iter(files), ""),
        **({"files": files} if raw.get("files") and files else {}),
        "finding_id": finding_id(sweep, str(check), file, raw),
        **({"line": line} if line else {}),
        **references(raw),
        "message": str(message),
    }


def extract_findings(reports: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten every sweep's report into one list of uniform findings.

    Sweeps keep findings at the top level (`findings`, `hits`) or per repository
    (`repos[].findings`, `repos[].missing_patterns`); each shape is read here so
    callers can count and rank without knowing the sweep.
    """
    found: list[dict[str, Any]] = []
    for sweep, report in reports.items():
        if not isinstance(report, dict):
            continue
        for key in ("findings", "hits"):
            items = report.get(key)
            if isinstance(items, list):
                found.extend(_one_finding(sweep, item) for item in items)
        for repo in report.get("repos") or []:
            if not isinstance(repo, dict):
                continue
            items = repo.get("findings")
            if isinstance(items, list):
                found.extend(
                    _one_finding(sweep, item, repo.get("repo_path") or "") for item in items
                )
            if sweep == "dependency_audit":
                for vuln in repo.get("vulns", []):
                    found.append(
                        _one_finding(
                            sweep,
                            {
                                "check": vuln["id"],
                                "severity": vuln["severity"],
                                "file": repo.get("repo_path"),
                                "message": f"{vuln['package']}: {vuln['title']}",
                            },
                        )
                    )
            for pattern in repo.get("missing_patterns") or []:
                found.append(
                    {
                        "sweep": sweep,
                        "check": "gitignore_gap",
                        "severity": "low" if repo.get("is_public") else "info",
                        "file": ".gitignore",
                        "message": f".gitignore does not cover {pattern}",
                    }
                )
    found.sort(key=lambda f: (_SEVERITY_RANK[f["severity"]], f["sweep"], f["check"], f["file"]))
    return found


def _report_errors(reports: dict[str, Any], sweeps: list[str]) -> list[str]:
    errors: list[str] = []
    for name in sweeps:
        if not isinstance(reports.get(name), dict) or not reports[name]:
            errors.append(f"{name}: requested sweep returned no report")
    for sweep, report in reports.items():
        if not isinstance(report, dict):
            continue
        for err in report.get("errors") or []:
            errors.append(f"{sweep}: {err}")
        if sweep == "dependency_audit":
            from devguard.sweeps.dependency_audit import coverage_gaps

            errors.extend(f"{sweep}: {gap}" for gap in coverage_gaps(report))
    return errors


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------


def run_sweeps(
    path: Path,
    sweeps: list[str],
    spec_path: Path | None,
    timeout: int,
    *,
    offline_dependencies: bool = False,
) -> tuple[int, dict[str, Any], str]:
    """Run `devguard sweep --repo path` in a child process. Returns (exit, reports, error)."""
    cmd = [sys.executable, "-m", "devguard", "sweep", "--repo", str(path), "--format", "json"]
    if offline_dependencies:
        cmd.append("--offline-dependencies")
    for name in sweeps:
        cmd += ["--only", name]
    if spec_path is not None and spec_path.is_file():
        cmd += ["--spec", str(spec_path.resolve())]
    with tempfile.TemporaryDirectory(prefix="devguard-fleet-") as workdir:
        try:
            done = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 3, {}, f"timed out after {timeout}s"
    if done.returncode not in (0, 2, 3) or not done.stdout.strip():
        tail = (done.stderr.strip().splitlines() or ["no output"])[-1][:300]
        return 3, {}, f"sweep exited {done.returncode} without a usable report: {tail}"
    try:
        reports = json.loads(done.stdout)
    except json.JSONDecodeError:
        return 3, {}, "sweep wrote output that is not JSON"
    if not isinstance(reports, dict) or not reports:
        return 3, {}, "sweep wrote an unexpected JSON shape"
    return done.returncode, reports, ""


def scan_one(
    ref: RepoRef,
    *,
    sweeps: list[str],
    spec_path: Path | None,
    root: Path,
    use_cache: bool = True,
    online_dependencies: bool = False,
    refresh: bool = True,
    full_history: bool = False,
    timeout: int = 900,
) -> RepoResult:
    started = time.monotonic()

    def result(status: str, code: int, head: str | None, **extra: Any) -> RepoResult:
        return RepoResult(
            name=ref.name,
            url=ref.url,
            head=head,
            visibility=ref.visibility,
            status=status,
            exit_code=code,
            seconds=round(time.monotonic() - started, 2),
            **extra,
        )

    try:
        path, head = sync_repo(ref, root=root, full_history=full_history, refresh=refresh)
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        return result("error", 3, None, errors=[str(exc)])

    # A local checkout with uncommitted changes has no stable identity to cache under.
    # Advisory databases can change independently of the repository and spec.
    cacheable = (
        use_cache
        and "dependency_audit" not in sweeps
        and not (ref.path is not None and _worktree_dirty(path))
    )
    key = result_key(
        head=head, sweeps=sweeps, spec_path=spec_path, full_history=full_history, name=ref.identity
    )
    if (
        cacheable
        and (hit := _read_cached_result(root, key))
        and not _report_errors(hit["reports"], sweeps)
    ):
        reports = hit["reports"]
        return result(
            "cached",
            int(hit.get("exit_code", 0)),
            head,
            findings=extract_findings(reports),
            errors=[],
            reports=reports,
        )

    offline_dependencies = "dependency_audit" in sweeps and (
        not refresh or (ref.visibility.upper() != "PUBLIC" and not online_dependencies)
    )
    code, reports, error = run_sweeps(
        path,
        sweeps,
        spec_path,
        timeout,
        **({"offline_dependencies": True} if offline_dependencies else {}),
    )
    if error:
        return result("error", 3, head, errors=[error])
    errors = _report_errors(reports, sweeps)
    if errors:
        code = 3
    findings = extract_findings(reports)
    if cacheable and code in (0, 2):
        _write_cached_result(root, key, {"exit_code": code, "reports": reports})
    status = "scanned"
    if set(sweeps) == {"dependency_audit"} and code == 0:
        scope = reports.get("dependency_audit", {}).get("scope", {})
        if scope.get("package_roots_discovered") == 0:
            status = "not_applicable"
    return result(
        status,
        code,
        head,
        findings=findings,
        errors=errors,
        reports=reports,
    )


def scan_fleet(
    refs: list[RepoRef],
    *,
    sweeps: list[str],
    spec_path: Path | None = None,
    root: Path | None = None,
    jobs: int = 4,
    use_cache: bool = True,
    online_dependencies: bool = False,
    refresh: bool = True,
    full_history: bool = False,
    timeout: int = 900,
    on_done: Callable[[RepoResult], None] | None = None,
) -> list[RepoResult]:
    """Scan *refs* with up to *jobs* repositories in flight; results keep input order."""
    root = root or cache_root()
    results: dict[int, RepoResult] = {}
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        pending = {
            pool.submit(
                scan_one,
                ref,
                sweeps=sweeps,
                spec_path=spec_path,
                root=root,
                use_cache=use_cache,
                online_dependencies=online_dependencies,
                refresh=refresh,
                full_history=full_history,
                timeout=timeout,
            ): index
            for index, ref in enumerate(refs)
        }
        for future in as_completed(pending):
            index = pending[future]
            try:
                results[index] = future.result()
            except Exception as exc:  # a bug here must not lose the other repositories
                ref = refs[index]
                results[index] = RepoResult(
                    name=ref.name,
                    url=ref.url,
                    head=None,
                    visibility=ref.visibility,
                    status="error",
                    exit_code=3,
                    seconds=0.0,
                    errors=[f"{type(exc).__name__}: {exc}"],
                )
            if on_done:
                on_done(results[index])
    return [results[i] for i in range(len(refs))]


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def fleet_exit_code(results: list[RepoResult], fail_on: str) -> int:
    """3 when any repository was not fully scanned, else 2 on findings at *fail_on* or worse."""
    if any(r.status == "error" or r.exit_code == 3 for r in results):
        return 3
    if fail_on != "never":
        severities = {f["severity"] for r in results for f in r.findings}
        if any(severity_at_least(severity, fail_on) for severity in severities):
            return 2
        if "unknown" in severities:
            return 3
    return 0


def fleet_report(
    results: list[RepoResult], *, sweeps: list[str], seconds: float, include_reports: bool = False
) -> dict[str, Any]:
    totals: Counter[str] = Counter()
    checks: Counter[tuple[str, str, str]] = Counter()
    for res in results:
        for finding in res.findings:
            totals[finding["severity"]] += 1
            checks[(finding["severity"], finding["sweep"], finding["check"])] += 1
    repos = []
    for res in results:
        row = asdict(res)
        row["counts"] = res.counts
        if audit := res.reports.get("dependency_audit"):
            row["dependency_coverage"] = {
                "package_roots_discovered": audit["scope"]["package_roots_discovered"],
                "package_roots_complete": audit["summary"]["package_roots_complete"],
            }
        if not include_reports:
            row.pop("reports")
        repos.append(row)
    return {
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "devguard_version": __version__,
        "sweeps": sorted(sweeps),
        "summary": {
            "repos": len(results),
            "scanned": sum(r.status == "scanned" for r in results),
            "cached": sum(r.status == "cached" for r in results),
            "errors": sum(r.status == "error" for r in results),
            "incomplete": sum(r.status != "error" and r.exit_code == 3 for r in results),
            "not_applicable": sum(r.status == "not_applicable" for r in results),
            "clean": sum(
                r.exit_code == 0 and not r.findings and r.status != "not_applicable"
                for r in results
            ),
            "findings": {s: totals.get(s, 0) for s in SEVERITIES},
            "seconds": round(seconds, 1),
        },
        "checks": [
            {"severity": sev, "sweep": sweep, "check": check, "count": count}
            for (sev, sweep, check), count in sorted(
                checks.items(), key=lambda kv: (_SEVERITY_RANK[kv[0][0]], -kv[1], kv[0][1:])
            )
        ],
        "repos": repos,
    }
