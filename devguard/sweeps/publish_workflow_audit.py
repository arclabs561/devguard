"""Publish workflow audit: static checks on publish and release GitHub workflows.

Checks:
- tag_push_without_credentials (error): a step runs `git push` after
  `actions/checkout` with `persist-credentials: false`, and no step in the job
  configures a token-bearing remote or auth header.
- msrv_pins_missing (warning): ci.yml pins dependencies with
  `cargo update --precise` for its MSRV job, but a publish job that installs
  an MSRV toolchain lacks some of those pins.
- semver_checks_all_features (warning): `cargo-semver-checks-action` runs with
  its default all-features group in a crate that has platform-only features or
  target-specific dependencies, which fail to build on the Linux runner.
- unpinned_action_ref (note): an action ref is not a full commit SHA while
  other workflows in the repo pin SHAs.
"""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from devguard.sweeps._common import iter_git_repos, utc_now

DEFAULT_WORKFLOW_GLOBS = ["publish*.yml", "publish*.yaml", "release*.yml", "release*.yaml"]

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
_GIT_PUSH_RE = re.compile(r"\bgit\s+(?:-C\s+\S+\s+)?push\b")
_TOKEN_REMOTE_RE = re.compile(
    r"x-access-token|https://[^\s/]*@github\.com|extraheader|git\s+remote\s+(?:set-url|add)\b.*\$\{\{"
    r"|gh\s+auth\s+setup-git",
    re.IGNORECASE,
)
_PRECISE_RE = re.compile(r"cargo\s+update\b[^\n]*?--precise\s+\S+")
_MSRV_TOOLCHAIN_RE = re.compile(
    r"rust-toolchain@1\.\d+|toolchain:\s*['\"]?1\.\d+|rustup\s+(?:toolchain\s+install|default|override\s+set)\s+1\.\d+"
    r"|cargo\s+\+1\.\d+|\bmsrv\b",
    re.IGNORECASE,
)
_PLATFORM_FEATURE_RE = re.compile(
    r"metal|cuda|objc|coreml|accelerate|\bmps\b|vulkan|rocm|directml|macos|windows|ios|android",
    re.IGNORECASE,
)
_OS_CFG_RE = re.compile(r"target_os|target_vendor|target_family|\bwindows\b|\bunix\b")
_PLATFORM_DEP_RE = re.compile(r"^(objc2.*|metal.*|cudarc|cuda.*|core-foundation.*|windows.*)$")


def _finding(check: str, severity: str, workflow: str, message: str) -> dict[str, Any]:
    return {
        "check": check,
        "severity": severity,
        "file": f".github/workflows/{workflow}",
        "message": f"{workflow}: {message}",
    }


def _normalize_precise(cmd: str) -> str:
    return " ".join(cmd.split())


def _jobs(doc: Any) -> dict[str, Any]:
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    return jobs if isinstance(jobs, dict) else {}


def _is_checkout(step: dict[str, Any]) -> bool:
    return str(step.get("uses", "")).startswith("actions/checkout@")


def _persist_false(step: dict[str, Any]) -> bool:
    val = (step.get("with") or {}).get("persist-credentials")
    return val is False or str(val).strip().lower() == "false"


def _check_tag_push(name: str, doc: Any) -> list[dict[str, Any]]:
    out = []
    for job_id, job in _jobs(doc).items():
        steps = [s for s in (job or {}).get("steps") or [] if isinstance(s, dict)]
        no_creds = False
        authed = False
        for step in steps:
            run = str(step.get("run") or "")
            if _is_checkout(step):
                no_creds = _persist_false(step)
                authed = False
                continue
            if _TOKEN_REMOTE_RE.search(run):
                authed = True
            if no_creds and not authed and _GIT_PUSH_RE.search(run):
                label = step.get("name") or run.strip().splitlines()[0][:60]
                out.append(
                    _finding(
                        "tag_push_without_credentials",
                        "error",
                        name,
                        f"job '{job_id}' step '{label}' runs git push after checkout with "
                        "persist-credentials: false and no token-bearing remote",
                    )
                )
    return out


def _check_msrv_pins(name: str, text: str, ci_pins: set[str]) -> list[dict[str, Any]]:
    if not ci_pins or not _MSRV_TOOLCHAIN_RE.search(text):
        return []
    have = {_normalize_precise(m) for m in _PRECISE_RE.findall(text)}
    missing = sorted(ci_pins - have)
    if not missing:
        return []
    return [
        _finding(
            "msrv_pins_missing",
            "warning",
            name,
            f"MSRV toolchain step without ci.yml pins: {'; '.join(missing)}",
        )
    ]


def _platform_only(manifest: Path) -> list[str]:
    try:
        data = tomllib.loads(manifest.read_text())
    except (OSError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []
    reasons = []
    target = data.get("target")
    if isinstance(target, dict):
        # Only OS/vendor-specific optional deps: a feature can enable them, and
        # all-features then compiles platform code on the Linux runner.
        for cfg, tables in target.items():
            deps = tables.get("dependencies") if isinstance(tables, dict) else None
            if not isinstance(deps, dict) or not _OS_CFG_RE.search(cfg):
                continue
            if any(isinstance(d, dict) and d.get("optional") for d in deps.values()):
                reasons.append(f"optional target-specific dependencies ({cfg})")
                break
    feats = [f for f in (data.get("features") or {}) if _PLATFORM_FEATURE_RE.search(f)]
    if feats:
        reasons.append(f"platform features: {', '.join(sorted(feats)[:5])}")
    deps = [d for d in (data.get("dependencies") or {}) if _PLATFORM_DEP_RE.match(d)]
    if deps:
        reasons.append(f"platform dependencies: {', '.join(sorted(deps)[:5])}")
    return reasons


def _crate_manifests(repo: Path) -> list[Path]:
    found = [repo / "Cargo.toml"] + sorted(repo.glob("crates/*/Cargo.toml"))
    return [p for p in found if p.is_file()]


def _check_semver_features(name: str, doc: Any, repo: Path) -> list[dict[str, Any]]:
    out = []
    for job_id, job in _jobs(doc).items():
        for step in (job or {}).get("steps") or []:
            if not isinstance(step, dict):
                continue
            if "cargo-semver-checks-action" not in str(step.get("uses", "")):
                continue
            with_ = step.get("with") or {}
            if any(k in with_ for k in ("feature-group", "features")):
                continue
            reasons = [r for m in _crate_manifests(repo) for r in _platform_only(m)]
            if reasons:
                out.append(
                    _finding(
                        "semver_checks_all_features",
                        "warning",
                        name,
                        f"job '{job_id}' runs cargo-semver-checks-action without feature-group "
                        f"or features; crate has {reasons[0]}",
                    )
                )
    return out


def _action_refs(text: str) -> list[str]:
    return [u for u in _USES_RE.findall(text) if "@" in u and not u.startswith(("./", "docker://"))]


def _check_unpinned(name: str, text: str, repo_pins_shas: bool) -> list[dict[str, Any]]:
    if not repo_pins_shas:
        return []
    loose = sorted({u for u in _action_refs(text) if not _SHA_RE.match(u.rsplit("@", 1)[1])})
    if not loose:
        return []
    return [
        _finding(
            "unpinned_action_ref",
            "note",
            name,
            f"action refs not pinned to a commit SHA (other workflows pin): {', '.join(loose[:8])}",
        )
    ]


def audit_workflows(repo: Path, workflow_globs: list[str] | None = None) -> list[dict[str, Any]]:
    """Audit one repo's publish/release workflows. Raises nothing for unreadable YAML."""
    wf_dir = repo / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    globs = workflow_globs or DEFAULT_WORKFLOW_GLOBS
    all_files = sorted(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file())
    texts = {p.name: p.read_text(errors="replace") for p in all_files}
    targets = [n for n in texts if any(fnmatch.fnmatch(n, g) for g in globs)]
    if not targets:
        return []

    ci_text = texts.get("ci.yml") or texts.get("ci.yaml") or ""
    ci_pins = {_normalize_precise(m) for m in _PRECISE_RE.findall(ci_text)}
    # Mixed pinning is the signal: the repo already pins SHAs somewhere.
    repo_pins_shas = any(
        _SHA_RE.match(u.rsplit("@", 1)[1]) for t in texts.values() for u in _action_refs(t)
    )

    findings: list[dict[str, Any]] = []
    for name in targets:
        text = texts[name]
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError:
            findings.append(_finding("workflow_parse_error", "warning", name, "YAML parse error"))
            continue
        findings += _check_tag_push(name, doc)
        findings += _check_msrv_pins(name, text, ci_pins)
        findings += _check_semver_features(name, doc, repo)
        findings += _check_unpinned(name, text, repo_pins_shas)
    return findings


def audit_publish_workflows(
    *,
    dev_root: Path,
    max_depth: int = 2,
    exclude_repo_globs: list[str] | None = None,
    workflow_globs: list[str] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    globs = exclude_repo_globs or []
    repos = [
        r
        for r in sorted(iter_git_repos(dev_root, max_depth=max_depth))
        if not any(fnmatch.fnmatch(str(r), g) for g in globs)
    ]
    results: list[dict[str, Any]] = []
    for repo in repos:
        try:
            findings = audit_workflows(repo, workflow_globs)
        except OSError as exc:
            errors.append(f"{repo.name}: {exc.__class__.__name__}")
            continue
        if findings:
            results.append({"repo_path": str(repo), "findings": findings})
    sev: dict[str, int] = {"error": 0, "warning": 0, "note": 0}
    for r in results:
        for f in r["findings"]:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    results.sort(key=lambda r: (-len(r["findings"]), r["repo_path"]))
    report: dict[str, Any] = {
        "generated_at": utc_now(),
        "scope": {"dev_root": str(dev_root), "repos_scanned": len(repos)},
        "summary": {
            "repos_with_findings": len(results),
            "total_findings": sum(sev.values()),
            "total_errors": sev["error"],
            "severity_counts": sev,
        },
        "repos": results,
        "errors": errors,
    }
    return report, errors


def write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
